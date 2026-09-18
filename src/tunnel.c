//
//  tunnel.c
//  rxpc
//
//  Created by ruter on 14.09.26.
//

#include "tunnel.h"

#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/un.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define CD_TUNNEL_MAGIC "CDTunnel"
#define CD_TUNNEL_HEADER_SIZE 10u
#define CD_TUNNEL_MTU_REQUEST 1280u
#define MAX_INGRESS_BUFFER (256u * 1024u)
#define MAX_FWD_CHUNK 16384u

#define USBMUXD_PATH "/var/run/usbmuxd"
#define USBMUX_TYPE 8u
#define USBMUX_VERSION 1u
#define UMX_HEADER_SIZE 16u

#define LOCKDOWN_PORT 62078
#define LABEL "rxpc"
#define CLIENT_VERSION_STRING "rxpc-1.0.0"
#define CORE_DEVICE_PROXY_SERVICE "com.apple.internal.devicecompute.CoreDeviceProxy"

#define TLSD_TIMEOUT_MS 10000u
#define PLIST_MAX_SIZE (16u * 1024u * 1024u)
#define UTUN_HEADER_SIZE 4u
#define IPV6_HEADER_SIZE 40u
#define IPV6_PAYLOAD_LEN_OFFSET 4u
#define FRAME_NEED_MORE 0u
#define FRAME_RESYNC 1u

struct rxpc_tunnel {
  char err[256];
  char *address;
  uint16_t rsd_port;
  char *client_address;
  uint32_t mtu;
  char *interface_name;
  int tun_fd;
  int sock_fd;
  SSL_CTX *ctx;
  SSL *ssl;
  atomic_int running;
  pthread_t tun_thread;
  pthread_t sock_thread;
  int threads_started;
};

static void tset_err(rxpc_tunnel *t, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(t->err, sizeof(t->err), fmt, ap);
  va_end(ap);
}

const char *rxpc_tunnel_error(const rxpc_tunnel *t) { return t ? t->err : "no tunnel"; }

const char *rxpc_tunnel_interface(const rxpc_tunnel *t) {
  return t && t->interface_name ? t->interface_name : "";
}

static char *xstrdup_n(const char *s, size_t n) {
  char *p = malloc(n + 1);
  if (!p) return NULL;
  memcpy(p, s, n);
  p[n] = 0;
  return p;
}

typedef struct {
  char *p;
  size_t len, cap;
} sbuf;

static int sbuf_reserve(sbuf *b, size_t extra) {
  if (b->len + extra + 1 <= b->cap) return 0;
  size_t cap = b->cap ? b->cap : 256;
  while (cap < b->len + extra + 1) cap *= 2;
  char *np = realloc(b->p, cap);
  if (!np) return -1;
  b->p = np;
  b->cap = cap;
  return 0;
}

static int sbuf_append(sbuf *b, const void *data, size_t n) {
  if (sbuf_reserve(b, n) != 0) return -1;
  memcpy(b->p + b->len, data, n);
  b->len += n;
  b->p[b->len] = 0;
  return 0;
}

static int sbuf_puts(sbuf *b, const char *s) { return sbuf_append(b, s, strlen(s)); }

static int sbuf_printf(sbuf *b, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char tmp[256];
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0) return -1;
  return sbuf_append(b, tmp, (size_t)n);
}

static void pl_esc(sbuf *b, const char *s) {
  for (; *s; s++) {
    switch (*s) {
      case '&':
        sbuf_puts(b, "&amp;");
        break;
      case '<':
        sbuf_puts(b, "&lt;");
        break;
      case '>':
        sbuf_puts(b, "&gt;");
        break;
      case '"':
        sbuf_puts(b, "&quot;");
        break;
      default:
        sbuf_append(b, s, 1);
    }
  }
}

static void pl_start(sbuf *b) {
  sbuf_puts(b, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
               "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
               "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
               "<plist version=\"1.0\">\n<dict>");
}

static void pl_end(sbuf *b) { sbuf_puts(b, "</dict>\n</plist>"); }

static void pl_key(sbuf *b, const char *k) {
  sbuf_puts(b, "<key>");
  pl_esc(b, k);
  sbuf_puts(b, "</key>");
}

static void pl_str(sbuf *b, const char *k, const char *v) {
  pl_key(b, k);
  sbuf_puts(b, "<string>");
  pl_esc(b, v);
  sbuf_puts(b, "</string>");
}

static void pl_empty_str(sbuf *b, const char *k) {
  pl_key(b, k);
  sbuf_puts(b, "<string></string>");
}

static void pl_int(sbuf *b, const char *k, long long v) {
  pl_key(b, k);
  sbuf_printf(b, "<integer>%lld</integer>", v);
}

static int b64_decode(const char *in, size_t inlen, uint8_t **out, size_t *outlen) {
  static const int8_t t[256] = {
      ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,
      ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13,
      ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20,
      ['V'] = 21, ['W'] = 22, ['X'] = 23, ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27,
      ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33, ['i'] = 34,
      ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
      ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48,
      ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
      ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61, ['+'] = 62,
      ['/'] = 63};

  size_t dstcap = 0;
  for (size_t i = 0; i < inlen; i++) {
    char c = in[i];
    if (c != '=' && c != '\n' && c != '\r' && c != ' ' && c != '\t') dstcap++;
  }
  dstcap = dstcap / 4 * 3 + 3;

  uint8_t *dst = malloc(dstcap + 1);
  if (!dst) return -1;
  size_t o = 0, acc = 0;
  int nbits = 0;
  for (size_t i = 0; i < inlen; i++) {
    char c = in[i];
    if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '=') continue;
    int v = t[(unsigned char)c];
    if (v < 0) {
      free(dst);
      return -1;
    }
    acc = (acc << 6) | (unsigned)v;
    nbits += 6;
    if (nbits >= 8) {
      nbits -= 8;
      dst[o++] = (uint8_t)((acc >> nbits) & 0xff);
    }
  }
  dst[o] = 0;
  *out = dst;
  *outlen = o;
  return 0;
}

typedef enum {
  PL_STR,
  PL_BOOL,
  PL_INT,
  PL_UINT,
  PL_REAL,
  PL_DATA,
  PL_ARRAY,
  PL_DICT,
} pl_type;

typedef struct pl_node pl_node;
struct pl_node {
  pl_type type;
  const char *str;
  size_t str_len;
  long long i;      
  unsigned long long u;
  double d; 
  int b;
  union {
    struct {
      pl_node **items;
      size_t n;
    } arr;
    struct {
      char **keys;
      pl_node **vals;
      size_t n;
    } dict;
  };
};

typedef struct {
  const char *s;
  size_t n;
  size_t i;
  int failed;
} plc;

static pl_node *pl_parse_val(plc *p);

static void pl_skip_ws(plc *p) {
  while (p->i < p->n && (p->s[p->i] == ' ' || p->s[p->i] == '\t' || p->s[p->i] == '\n' || p->s[p->i] == '\r'))
    p->i++;
}

static void pl_skip_decl(plc *p) {
  for (;;) {
    pl_skip_ws(p);
    if (p->i + 1 >= p->n) return;
    if (p->s[p->i] == '<' && (p->s[p->i + 1] == '?' || p->s[p->i + 1] == '!')) {
      while (p->i < p->n && p->s[p->i] != '>') p->i++;
      if (p->i < p->n) p->i++;
      continue;
    }
    return;
  }
}

static int pl_tag_name(plc *p, char *name, size_t cap) {
  if (p->i >= p->n || p->s[p->i] != '<') {
    p->failed = 1;
    return 0;
  }
  p->i++;
  int close = 0;
  if (p->i < p->n && p->s[p->i] == '/') {
    close = 1;
    p->i++;
  }
  size_t w = 0;
  while (p->i < p->n) {
    char c = p->s[p->i];
    if (c == '>' || c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
        (c == '/' && p->i + 1 < p->n && p->s[p->i + 1] == '>')) {
      if (c == '/' && p->i + 1 < p->n && p->s[p->i + 1] == '>') p->i++;
      break;
    }
    if (w + 1 < cap) name[w++] = c;
    p->i++;
  }
  name[w] = 0;
  while (p->i < p->n && p->s[p->i] != '>') p->i++;
  if (p->i < p->n) p->i++;
  return close;
}

static void pl_text_decode(const char *raw, size_t rl, char *out, size_t ocap) {
  size_t o = 0;
  for (size_t i = 0; i < rl && o + 1 < ocap; i++) {
    char c = raw[i];
    if (c == '&') {
      size_t semi = 0;
      while (i + semi < rl && raw[i + semi] != ';') semi++;
      if (i + semi < rl && semi > 1) {
        const char *at = raw + i + 1;
        size_t ent = semi - 1;
        if (ent == 3 && strncmp(at, "amp", 3) == 0)
          out[o++] = '&';
        else if (ent == 3 && strncmp(at, "lt", 3) == 0)
          out[o++] = '<';
        else if (ent == 3 && strncmp(at, "gt", 3) == 0)
          out[o++] = '>';
        else if (ent == 4 && strncmp(at, "quot", 4) == 0)
          out[o++] = '"';
        else if (ent == 5 && strncmp(at, "apos", 5) == 0)
          out[o++] = '\'';
        else if (ent >= 2 && at[0] == '#') {
          long cval = strtol(at + 1, NULL, 10);
          if (cval > 0 && cval < 128) out[o++] = (char)cval;
          else out[o++] = '&';
        } else out[o++] = '&';
        i += semi;
        continue;
      }
      out[o++] = '&';
      continue;
    }
    out[o++] = c;
  }
  out[o] = 0;
}

static char *pl_text(plc *p, const char *close_tag) {
  size_t start = p->i;
  while (p->i + 2 <= p->n && !(p->s[p->i] == '<' && p->s[p->i + 1] == '/')) p->i++;
  if (p->i + 2 > p->n || p->i < start) {
    p->failed = 1;
    return NULL;
  }
  size_t rl = p->i - start;
  char name[32];
  int closed = pl_tag_name(p, name, sizeof(name));
  if (p->failed || !closed || strcmp(name, close_tag) != 0) {
    p->failed = 1;
    return NULL;
  }
  char *out = malloc(rl + 1);
  if (!out) {
    p->failed = 1;
    return NULL;
  }
  pl_text_decode(p->s + start, rl, out, rl + 1);
  return out;
}

static pl_node *pl_node_new(pl_type t) {
  pl_node *n = calloc(1, sizeof(*n));
  if (n) n->type = t;
  return n;
}

static void pl_node_free(pl_node *n) {
  if (!n) return;
  switch (n->type) {
    case PL_DICT:
      for (size_t i = 0; i < n->dict.n; i++) {
        free(n->dict.keys[i]);
        pl_node_free(n->dict.vals[i]);
      }
      free(n->dict.keys);
      free(n->dict.vals);
      break;
    case PL_ARRAY:
      for (size_t i = 0; i < n->arr.n; i++) pl_node_free(n->arr.items[i]);
      free(n->arr.items);
      break;
    case PL_STR:
    case PL_DATA:
      free((void *)n->str);
      break;
    default:
      break;
  }
  free(n);
}

static pl_node *pl_parse_val(plc *p) {
  pl_skip_decl(p);
  char name[64];
  int closed = pl_tag_name(p, name, sizeof(name));
  if (p->failed) return NULL;
  if (closed) {
    p->failed = 1;
    return NULL;
  }

  if (strcmp(name, "plist") == 0) {
    pl_node *child = pl_parse_val(p);
    pl_skip_decl(p);
    if (!p->failed && p->i + 1 < p->n && p->s[p->i] == '<' && p->s[p->i + 1] == '/') {
      char c[32];
      pl_tag_name(p, c, sizeof(c));
    }
    return child;
  }

  if (strcmp(name, "dict") == 0) {
    pl_node *n = pl_node_new(PL_DICT);
    if (!n) return NULL;
    for (;;) {
      pl_skip_decl(p);
      if (p->i + 1 < p->n && p->s[p->i] == '<' && p->s[p->i + 1] == '/') {
        char c[32];
        int kc = pl_tag_name(p, c, sizeof(c));
        if (p->failed || kc != 1 || strcmp(c, "dict") != 0) {
          p->failed = 1;
          pl_node_free(n);
          return NULL;
        }
        break;
      }
      char kname[64];
      int kc = pl_tag_name(p, kname, sizeof(kname));
      if (p->failed || kc != 0 || strcmp(kname, "key") != 0) {
        p->failed = 1;
        pl_node_free(n);
        return NULL;
      }
      char *key = pl_text(p, "key");
      if (!key || p->failed) {
        free(key);
        p->failed = 1;
        pl_node_free(n);
        return NULL;
      }
      pl_node *v = pl_parse_val(p);
      if (!v || p->failed) {
        free(key);
        pl_node_free(n);
        return NULL;
      }
      size_t idx = n->dict.n;
      char **nk = realloc(n->dict.keys, (idx + 1) * sizeof(*nk));
      pl_node **nv = realloc(n->dict.vals, (idx + 1) * sizeof(*nv));
      if (!nk || !nv) {
        free(nk);
        free(nv);
        free(key);
        pl_node_free(v);
        pl_node_free(n);
        return NULL;
      }

      n->dict.keys = nk;
      n->dict.vals = nv;
      n->dict.keys[idx] = key;
      n->dict.vals[idx] = v;
      n->dict.n = idx + 1;
    }

    return n;
  }

  if (strcmp(name, "array") == 0) {
    pl_node *n = pl_node_new(PL_ARRAY);
    if (!n) return NULL;
    for (;;) {
      pl_skip_decl(p);
      if (p->i + 1 < p->n && p->s[p->i] == '<' && p->s[p->i + 1] == '/') {
        char c[32];
        int kc = pl_tag_name(p, c, sizeof(c));
        if (p->failed || kc != 1 || strcmp(c, "array") != 0) {
          p->failed = 1;
          pl_node_free(n);
          return NULL;
        }

        break;
      }

      pl_node *v = pl_parse_val(p);
      if (!v || p->failed) {
        p->failed = 1;
        pl_node_free(n);
        return NULL;
      }

      size_t idx = n->arr.n;
      pl_node **ni = realloc(n->arr.items, (idx + 1) * sizeof(*ni));
      if (!ni) {
        pl_node_free(v);
        pl_node_free(n);
        return NULL;
      }

      n->arr.items = ni;
      n->arr.items[idx] = v;
      n->arr.n = idx + 1;
    }

    return n;
  }

  if (strcmp(name, "true") == 0 || strcmp(name, "false") == 0) {
    pl_node *n = pl_node_new(PL_BOOL);
    if (n) n->b = (strcmp(name, "true") == 0);

    return n;
  }

  if (strcmp(name, "string") == 0 || strcmp(name, "date") == 0) {
    char *t = pl_text(p, name);
    if (!t) return NULL;
    pl_node *n = pl_node_new(PL_STR);
    if (!n) {
      free(t);
      return NULL;
    }

    n->str = t;
    n->str_len = strlen(t);

    return n;
  }

  if (strcmp(name, "integer") == 0) {
    char *t = pl_text(p, "integer");
    if (!t) return NULL;
    long long v = strtoll(t, NULL, 10);
    free(t);
    pl_node *n = pl_node_new(PL_INT);
    if (!n) return NULL;
    n->i = v;

    return n;
  }

  if (strcmp(name, "real") == 0) {
    char *t = pl_text(p, "real");
    if (!t) return NULL;
    double d = strtod(t, NULL);
    free(t);
    pl_node *n = pl_node_new(PL_REAL);
    if (!n) return NULL;
    n->d = d;

    return n;
  }

  if (strcmp(name, "uid") == 0 || strcmp(name, "int") == 0) {
    char *t = pl_text(p, name);
    if (!t) return NULL;
    unsigned long long u = strtoull(t, NULL, 10);
    free(t);
    pl_node *n = pl_node_new(PL_UINT);
    if (!n) return NULL;
    n->u = u;

    return n;
  }

  if (strcmp(name, "data") == 0) {
    char *t = pl_text(p, "data");
    if (!t) return NULL;
    uint8_t *dec = NULL;
    size_t dlen = 0;
    pl_node *n = NULL;
    if (b64_decode(t, strlen(t), &dec, &dlen) == 0) {
      n = pl_node_new(PL_DATA);
      if (n) {
        n->str = (const char *)dec;
        n->str_len = dlen;
      } else {
        free(dec);
      }
    }

    free(t);
    return n;
  }

  p->failed = 1;
  return NULL;
}

static pl_node *pl_parse(const char *xml, size_t len) {
  plc c = {.s = xml, .n = len, .i = 0, .failed = 0};
  pl_node *n = pl_parse_val(&c);
  return (n && !c.failed) ? n : NULL;
}

static const pl_node *pl_dict_get(const pl_node *d, const char *key) {
  if (!d || d->type != PL_DICT) return NULL;
  for (size_t i = 0; i < d->dict.n; i++) if (strcmp(d->dict.keys[i], key) == 0) return d->dict.vals[i];
  return NULL;
}

static int pl_str_copy(const pl_node *n, char *out, size_t outsz) {
  if (!n || outsz == 0) return -1;
  const char *s;
  size_t l;
  if (n->type == PL_STR || n->type == PL_DATA) {
    s = n->str;
    l = n->str_len;
  } else {
    return -1;
  }

  if (l >= outsz) l = outsz - 1;
  memcpy(out, s, l);
  out[l] = 0;

  return 0;
}

static int pl_long(const pl_node *n, long long *out) {
  if (!n || n->type != PL_INT) return -1;
  *out = n->i;
  return 0;
}

static int pl_bool_val(const pl_node *n, int *out) {
  if (!n || n->type != PL_BOOL) return -1;
  *out = n->b;
  return 0;
}

static int wait_fd(int fd, short events, const atomic_int *running, unsigned timeout_ms) {
  struct pollfd pfd = {.fd = fd, .events = events};
  for (;;) {
    if (running && !atomic_load(running)) return 0;
    int rc = poll(&pfd, 1, (int)timeout_ms);
    if (rc < 0) {
      if (errno == EINTR) continue;
      return 0;
    }
    if (rc == 0) return 0;
    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
    return (pfd.revents & events) != 0;
  }
}

static int io_write_all(int fd, SSL *ssl, const uint8_t *data, size_t len, unsigned timeout_ms) {
  size_t off = 0;
  while (off < len) {
    if (ssl) {
      ERR_clear_error();
      int n = SSL_write(ssl, data + off, (int)(len - off));
      if (n > 0) {
        off += (size_t)n;
        continue;
      }
      int e = SSL_get_error(ssl, n);
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return -1;
      int fd2 = SSL_get_fd(ssl);
      if (!wait_fd(fd2, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, NULL, timeout_ms)) return -1;
      continue;
    }
    ssize_t n = send(fd, data + off, len - off, 0);
    if (n > 0) {
      off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_fd(fd, POLLOUT, NULL, timeout_ms)) return -1;
      continue;
    }
    return -1;
  }
  return 0;
}

static int io_read_exact(int fd, SSL *ssl, uint8_t *data, size_t len, unsigned timeout_ms) {
  size_t off = 0;
  while (off < len) {
    if (ssl) {
      ERR_clear_error();
      int n = SSL_read(ssl, data + off, (int)(len - off));
      if (n > 0) {
        off += (size_t)n;
        continue;
      }
      int e = SSL_get_error(ssl, n);
      if (e == SSL_ERROR_ZERO_RETURN) return -1;
      if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return -1;
      int fd2 = SSL_get_fd(ssl);
      if (!wait_fd(fd2, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, NULL, timeout_ms)) return -1;
      continue;
    }
    ssize_t n = recv(fd, data + off, len - off, 0);
    if (n > 0) {
      off += (size_t)n;
      continue;
    }
    if (n == 0) return -1;
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (!wait_fd(fd, POLLIN, NULL, timeout_ms)) return -1;
      continue;
    }
    return -1;
  }
  return 0;
}

static atomic_uint g_umx_tag = 0;
static uint32_t umx_tag_next(void) { return atomic_fetch_add(&g_umx_tag, 1) + 1; }

static int umx_open(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  if (strlen(USBMUXD_PATH) >= sizeof(sun.sun_path)) {
    close(fd);
    return -1;
  }

  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", USBMUXD_PATH);
  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
    close(fd);
    return -1;
  }

  fcntl(fd, F_SETFL, O_NONBLOCK);
  return fd;
}

static int umx_send(int fd, const char *xml, uint32_t tag) {
  size_t plen = strlen(xml);
  uint32_t len = UMX_HEADER_SIZE + (uint32_t)plen;
  uint8_t hdr[UMX_HEADER_SIZE];
  hdr[0] = (uint8_t)(len & 0xff);
  hdr[1] = (uint8_t)((len >> 8) & 0xff);
  hdr[2] = (uint8_t)((len >> 16) & 0xff);
  hdr[3] = (uint8_t)((len >> 24) & 0xff);
  hdr[4] = USBMUX_VERSION;
  hdr[5] = 0;
  hdr[6] = 0;
  hdr[7] = 0;
  hdr[8] = USBMUX_TYPE;
  hdr[9] = 0;
  hdr[10] = 0;
  hdr[11] = 0;
  hdr[12] = (uint8_t)(tag & 0xff);
  hdr[13] = (uint8_t)((tag >> 8) & 0xff);
  hdr[14] = (uint8_t)((tag >> 16) & 0xff);
  hdr[15] = (uint8_t)((tag >> 24) & 0xff);
  if (io_write_all(fd, NULL, hdr, sizeof(hdr), TLSD_TIMEOUT_MS) != 0) return -1;
  return io_write_all(fd, NULL, (const uint8_t *)xml, plen, TLSD_TIMEOUT_MS);
}

static pl_node *umx_recv(int fd) {
  uint8_t hdr[UMX_HEADER_SIZE];
  if (io_read_exact(fd, NULL, hdr, sizeof(hdr), 5000) != 0) return NULL;
  uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
  if (len < UMX_HEADER_SIZE || len > PLIST_MAX_SIZE) return NULL;
  size_t plen = len - UMX_HEADER_SIZE;
  char *payload = malloc(plen + 1);
  if (!payload) return NULL;
  if (io_read_exact(fd, NULL, (uint8_t *)payload, plen, 5000) != 0) {
    free(payload);
    return NULL;
  }
  payload[plen] = 0;
  pl_node *node = pl_parse(payload, plen);
  free(payload);
  return node;
}

static int umx_list_pick(int fd, const char *want, char *out_udid, size_t out_udid_sz, long long *out_device_id) {
  sbuf req = {0};
  pl_start(&req);
  pl_str(&req, "MessageType", "ListDevices");
  pl_str(&req, "ProgName", LABEL);
  pl_str(&req, "ClientVersionString", CLIENT_VERSION_STRING);
  pl_end(&req);
  int rc = umx_send(fd, req.p, umx_tag_next());
  free(req.p);
  if (rc != 0) return -1;

  pl_node *resp = umx_recv(fd);
  if (!resp) return -1;
  const pl_node *list = pl_dict_get(resp, "DeviceList");
  if (!list || list->type != PL_ARRAY) {
    pl_node_free(resp);
    return -1;
  }
  int found = -1;
  for (size_t i = 0; i < list->arr.n && found < 0; i++) {
    const pl_node *props = pl_dict_get(list->arr.items[i], "Properties");
    if (!props) continue;
    const pl_node *sn = pl_dict_get(props, "SerialNumber");
    char buf[512];
    if (!sn || pl_str_copy(sn, buf, sizeof(buf)) != 0) continue;
    if (want && strcmp(buf, want) != 0) continue;
    const pl_node *did = pl_dict_get(list->arr.items[i], "DeviceID");
    if (!did || pl_long(did, out_device_id) != 0) continue;
    snprintf(out_udid, out_udid_sz, "%s", buf);
    found = 0;
  }
  pl_node_free(resp);
  return found;
}

typedef struct {
  char *host_id, *system_buid, *host_cert, *host_key;
} pair_fields;

static void pair_free(pair_fields *pf) {
  free(pf->host_id);
  free(pf->system_buid);
  free(pf->host_cert);
  free(pf->host_key);
  memset(pf, 0, sizeof(*pf));
}

static int umx_read_pair(int fd, const char *udid, pair_fields *out) {
  memset(out, 0, sizeof(*out));
  sbuf req = {0};
  pl_start(&req);
  pl_str(&req, "MessageType", "ReadPairRecord");
  pl_str(&req, "PairRecordID", udid);
  pl_str(&req, "ProgName", LABEL);
  pl_str(&req, "ClientVersionString", CLIENT_VERSION_STRING);
  pl_end(&req);
  int rc = umx_send(fd, req.p, umx_tag_next());
  free(req.p);
  if (rc != 0) return -1;

  pl_node *resp = umx_recv(fd);
  if (!resp) return -1;
  const pl_node *data = pl_dict_get(resp, "PairRecordData");
  if (!data || data->type != PL_DATA) {
    pl_node_free(resp);
    return -1;
  }

  pl_node *inner = pl_parse(data->str, data->str_len);
  pl_node_free(resp);
  if (!inner) return -1;

  int ok = 0;
  const char *keys[4] = {"HostID", "SystemBUID", "HostCertificate", "HostPrivateKey"};
  char **dsts[4] = {&out->host_id, &out->system_buid, &out->host_cert, &out->host_key};
  for (int i = 0; i < 4; i++) {
    const pl_node *v = pl_dict_get(inner, keys[i]);
    char buf[8192];
    if (!v || pl_str_copy(v, buf, sizeof(buf)) != 0) break;
    *dsts[i] = xstrdup_n(buf, strlen(buf));
    if (!*dsts[i]) break;
    ok = i + 1;
  }

  pl_node_free(inner);
  if (ok != 4) {
    pair_free(out);
    return -1;
  }

  return 0;
}

static int umx_connect_device(int fd, long long device_id, int port) {
  sbuf req = {0};
  pl_start(&req);
  pl_str(&req, "MessageType", "Connect");
  pl_str(&req, "ProgName", LABEL);
  pl_str(&req, "ClientVersionString", CLIENT_VERSION_STRING);
  pl_int(&req, "DeviceID", device_id);
  pl_int(&req, "PortNumber", (long long)(((port & 0xff) << 8) | ((port >> 8) & 0xff)));
  pl_end(&req);
  int rc = umx_send(fd, req.p, umx_tag_next());
  free(req.p);
  if (rc != 0) return -1;

  pl_node *resp = umx_recv(fd);
  if (!resp) return -1;
  int ok = 0;
  const pl_node *msg = pl_dict_get(resp, "MessageType");
  const pl_node *num = pl_dict_get(resp, "Number");
  char m[32] = {0};
  if (msg && pl_str_copy(msg, m, sizeof(m)) == 0 && strcmp(m, "Result") == 0) {
    long long n = -1;
    if (num && pl_long(num, &n) == 0 && n == 0) ok = 1;
  }
  pl_node_free(resp);
  return ok ? fd : -1;
}

static int ls_xact(int fd, SSL *ssl, const sbuf *req, pl_node **out) {
  *out = NULL;
  if (req->len > 0) {
    uint8_t lh[4];
    lh[0] = (uint8_t)((req->len >> 24) & 0xff);
    lh[1] = (uint8_t)((req->len >> 16) & 0xff);
    lh[2] = (uint8_t)((req->len >> 8) & 0xff);
    lh[3] = (uint8_t)(req->len & 0xff);
    if (io_write_all(fd, ssl, lh, 4, TLSD_TIMEOUT_MS) != 0) return -1;
    if (io_write_all(fd, ssl, (const uint8_t *)req->p, req->len, TLSD_TIMEOUT_MS) != 0) return -1;
  }
  uint8_t hdr[4];
  if (io_read_exact(fd, ssl, hdr, 4, 5000) != 0) return -1;
  uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
  if (len == 0 || len > PLIST_MAX_SIZE) return -1;
  char *payload = malloc(len + 1);
  if (!payload) return -1;
  if (io_read_exact(fd, ssl, (uint8_t *)payload, len, 5000) != 0) {
    free(payload);
    return -1;
  }
  payload[len] = 0;
  *out = pl_parse(payload, len);
  free(payload);
  return *out ? 0 : -1;
}

static int load_pem(SSL_CTX *ctx, const char *pem, int is_cert) {
  BIO *bio = BIO_new_mem_buf(pem, (int)strlen(pem));
  if (!bio) return -1;
  int rc = -1;
  if (is_cert) {
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (cert && SSL_CTX_use_certificate(ctx, cert) == 1) rc = 0;
    X509_free(cert);
  } else {
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (key && SSL_CTX_use_PrivateKey(ctx, key) == 1) rc = 0;
    EVP_PKEY_free(key);
  }
  return rc;
}

static int tls_upgrade(int fd, const char *cert_pem, const char *key_pem, SSL_CTX **out_ctx, SSL **out_ssl) {
  fcntl(fd, F_SETFL, O_NONBLOCK);

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) return -1;
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  if (load_pem(ctx, cert_pem, 1) != 0 || load_pem(ctx, key_pem, 0) != 0 || SSL_CTX_check_private_key(ctx) != 1) {
    SSL_CTX_free(ctx);
    return -1;
  }

  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    SSL_CTX_free(ctx);
    return -1;
  }
  SSL_set_fd(ssl, fd);

  for (;;) {
    ERR_clear_error();
    int rc = SSL_connect(ssl);
    if (rc == 1) break;
    int e = SSL_get_error(ssl, rc);
    short ev = (e == SSL_ERROR_WANT_READ) ? POLLIN : (e == SSL_ERROR_WANT_WRITE) ? POLLOUT : 0;
    if (ev == 0 || !wait_fd(fd, ev, NULL, TLSD_TIMEOUT_MS)) {
      SSL_free(ssl);
      SSL_CTX_free(ctx);
      return -1;
    }
  }
  *out_ctx = ctx;
  *out_ssl = ssl;
  return 0;
}

static int json_str_field(const char *src, const char *key, char *out, size_t outsz) {
  char needle[128];
  snprintf(needle, sizeof(needle), "\"%s\":\"", key);
  const char *pos = strstr(src, needle);
  if (!pos) return -1;
  const char *start = pos + strlen(needle);
  const char *end = strchr(start, '"');
  if (!end) return -1;
  size_t len = (size_t)(end - start);
  if (len >= outsz) len = outsz - 1;
  memcpy(out, start, len);
  out[len] = 0;
  return 0;
}

static int json_uint_field(const char *src, const char *key, uint32_t *out) {
  char needle[128];
  snprintf(needle, sizeof(needle), "\"%s\":", key);
  const char *pos = strstr(src, needle);
  if (!pos) return -1;
  *out = (uint32_t)strtoul(pos + strlen(needle), NULL, 10);
  return 0;
}

static int cdtunnel_handshake(rxpc_tunnel *t) {
  char req[128];
  snprintf(req, sizeof(req), "{\"type\":\"clientHandshakeRequest\",\"mtu\":%u}", CD_TUNNEL_MTU_REQUEST);
  size_t reqlen = strlen(req);
  uint8_t head[CD_TUNNEL_HEADER_SIZE];
  memcpy(head, CD_TUNNEL_MAGIC, 8);
  head[8] = (uint8_t)((reqlen >> 8) & 0xff);
  head[9] = (uint8_t)(reqlen & 0xff);
  if (io_write_all(t->sock_fd, t->ssl, head, sizeof(head), TLSD_TIMEOUT_MS) != 0) return -1;
  if (io_write_all(t->sock_fd, t->ssl, (const uint8_t *)req, reqlen, TLSD_TIMEOUT_MS) != 0) return -1;

  if (io_read_exact(t->sock_fd, t->ssl, head, sizeof(head), TLSD_TIMEOUT_MS) != 0) return -1;
  if (memcmp(head, CD_TUNNEL_MAGIC, 8) != 0) return -1;
  size_t bodylen = ((size_t)head[8] << 8) | head[9];
  if (bodylen > PLIST_MAX_SIZE) return -1;
  char *body = malloc(bodylen + 1);
  if (!body) return -1;
  if (bodylen > 0 && io_read_exact(t->sock_fd, t->ssl, (uint8_t *)body, bodylen, TLSD_TIMEOUT_MS) != 0) {
    free(body);
    return -1;
  }
  body[bodylen] = 0;

  int rc = -1;
  const char *cp = strstr(body, "\"clientParameters\"");
  const char *cp_start = cp ? strchr(cp, '{') : NULL; 
  const char *cp_end = cp_start ? strchr(cp_start + 1, '}') : NULL;
  if (cp_start && cp_end) {
    size_t cplen = (size_t)(cp_end - cp_start + 1);
    if (cplen < 1024) {
      char cps[1024];
      memcpy(cps, cp_start, cplen);
      cps[cplen] = 0;
      char addr[256];
      uint32_t mtu = 0;
      if (json_str_field(cps, "address", addr, sizeof(addr)) == 0 && json_uint_field(cps, "mtu", &mtu) == 0 &&
          mtu > 0) {
        t->client_address = xstrdup_n(addr, strlen(addr));
        t->mtu = mtu;
        rc = 0;
      }
    }
  }
  if (rc == 0) {
    char addr[256];
    uint32_t port = 0;
    if (json_str_field(body, "serverAddress", addr, sizeof(addr)) == 0 && json_uint_field(body, "serverRSDPort", &port) == 0 &&
        port > 0) {
      t->address = xstrdup_n(addr, strlen(addr));
      t->rsd_port = (uint16_t)port;
    } else {
      rc = -1;
    }
  }
  free(body);
  return rc;
}

static int utun_open(char *ifname, size_t ifname_cap) {
  struct ctl_info ci;
  struct sockaddr_ctl sa;
  int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd < 0) return -1;
  fcntl(fd, F_SETFD, FD_CLOEXEC);

  memset(&ci, 0, sizeof(ci));
  snprintf(ci.ctl_name, sizeof(ci.ctl_name), "%s", UTUN_CONTROL_NAME);
  if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
    close(fd);
    return -1;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sc_len = sizeof(sa);
  sa.sc_family = AF_SYSTEM;
  sa.ss_sysaddr = SYSPROTO_CONTROL;
  sa.sc_id = ci.ctl_id;

  int found = 0;
  for (u_int32_t unit = 1; unit < 255; unit++) {
    sa.sc_unit = unit;
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
      found = 1;
      break;
    }
    if (errno != EBUSY) {
      close(fd);
      return -1;
    }
  }
  if (!found) {
    close(fd);
    return -1;
  }

  char name[20];
  socklen_t nlen = sizeof(name);
  if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &nlen) < 0) {
    close(fd);
    return -1;
  }
  snprintf(ifname, ifname_cap, "%s", name);
  fcntl(fd, F_SETFL, O_NONBLOCK);
  return fd;
}

static size_t utun_write_pkt(int fd, const uint8_t *frame, size_t len, const atomic_int *running) {
  uint8_t *w = malloc(len + UTUN_HEADER_SIZE);
  if (!w) return SIZE_MAX;
  uint32_t family = htonl(AF_INET6);
  memcpy(w, &family, UTUN_HEADER_SIZE);
  memcpy(w + UTUN_HEADER_SIZE, frame, len);
  size_t off = 0;
  size_t total = len + UTUN_HEADER_SIZE;
  for (;;) {
    if (running && !atomic_load(running)) break;
    ssize_t n = send(fd, w + off, total - off, 0);
    if (n >= 0) {
      off += (size_t)n;
      if (off == total) {
        free(w);
        return len;
      }
      continue;
    }
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS && errno != EINTR) break;
    (void)wait_fd(fd, POLLOUT, running, 200);
  }
  free(w);
  return SIZE_MAX;
}

static ssize_t utun_read_pkt(int fd, uint8_t *out, size_t cap) {
  ssize_t n = recv(fd, out, cap, 0);
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
  if (n < 0) return -1;
  if (n <= (ssize_t)UTUN_HEADER_SIZE) return 0;
  memmove(out, out + UTUN_HEADER_SIZE, (size_t)n - UTUN_HEADER_SIZE);
  return n - (ssize_t)UTUN_HEADER_SIZE;
}

static int utun_configure(const char *ifname, const char *addr, uint32_t mtu, const char *server) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s inet6 %s prefixlen 64 up", ifname, addr);
  if (system(cmd) != 0) return -1;
  snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s mtu %u", ifname, mtu);
  if (system(cmd) != 0) return -1;
  snprintf(cmd, sizeof(cmd), "/sbin/route -n add -inet6 %s/128 -interface %s >/dev/null 2>&1", server, ifname);
  if (system(cmd) != 0) return -1;
  return 0;
}

static void utun_remove_route(const char *server) {
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "/sbin/route -n delete -inet6 %s/128 >/dev/null 2>&1", server);
  (void)system(cmd);
}

static size_t ipv6_frame_len(const uint8_t *data, size_t len, size_t max_frame) {
  if (len < IPV6_HEADER_SIZE) return FRAME_NEED_MORE;
  if ((data[0] >> 4) != 6) return FRAME_RESYNC;
  size_t payload = ((size_t)data[IPV6_PAYLOAD_LEN_OFFSET] << 8) | data[IPV6_PAYLOAD_LEN_OFFSET + 1];
  size_t total = IPV6_HEADER_SIZE + payload;
  if (total > max_frame) return FRAME_RESYNC;
  if (len < total) return FRAME_NEED_MORE;
  return total;
}

static void *sock_to_tun_thread(void *arg) {
  rxpc_tunnel *t = arg;
  size_t ingress_len = 0;
  uint8_t *ingress = malloc(MAX_INGRESS_BUFFER);
  uint8_t *chunk = malloc(MAX_FWD_CHUNK);
  if (!ingress || !chunk) {
    free(ingress);
    free(chunk);
    atomic_store(&t->running, 0);
    return NULL;
  }
  while (atomic_load(&t->running)) {
    ERR_clear_error();
    int n = SSL_read(t->ssl, chunk, MAX_FWD_CHUNK);
    if (n > 0) {
      if (ingress_len + (size_t)n > MAX_INGRESS_BUFFER) break;
      memcpy(ingress + ingress_len, chunk, (size_t)n);
      ingress_len += (size_t)n;
      size_t offset = 0;
      while (offset < ingress_len) {
        size_t fra = ipv6_frame_len(ingress + offset, ingress_len - offset, t->mtu);
        if (fra == FRAME_NEED_MORE) {
          break;
        }
        if (fra == FRAME_RESYNC) {
          offset++;
          continue;
        }
        size_t wrc = utun_write_pkt(t->tun_fd, ingress + offset, fra, &t->running);
        if (wrc == SIZE_MAX) goto out;
        offset += fra;
      }
      if (offset > 0) {
        memmove(ingress, ingress + offset, ingress_len - offset);
        ingress_len -= offset;
      }
      continue;
    }
    int e = SSL_get_error(t->ssl, n);
    if (e == SSL_ERROR_ZERO_RETURN) break;
    if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) break;
    int fd2 = SSL_get_fd(t->ssl);
    if (!wait_fd(fd2, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, &t->running, 200)) {
      if (atomic_load(&t->running)) break;
    }
  }
out:
  free(ingress);
  free(chunk);
  return NULL;
}

static void *tun_to_sock_thread(void *arg) {
  rxpc_tunnel *t = arg;
  size_t cap = (size_t)t->mtu + 512;
  uint8_t *pkt = malloc(cap);
  if (!pkt) {
    atomic_store(&t->running, 0);
    return NULL;
  }
  while (atomic_load(&t->running)) {
    ssize_t n = utun_read_pkt(t->tun_fd, pkt, cap);
    if (n < 0) break;
    if (n == 0) {
      if (!wait_fd(t->tun_fd, POLLIN, &t->running, 200)) {
        if (atomic_load(&t->running)) break;
      }
      continue;
    }
    ERR_clear_error();
    int rc = SSL_write(t->ssl, pkt, (int)n);
    if (rc > 0) continue;
    int e = SSL_get_error(t->ssl, rc);
    if (e == SSL_ERROR_ZERO_RETURN) break;
    if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) break;
    int fd2 = SSL_get_fd(t->ssl);
    if (!wait_fd(fd2, e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, &t->running, 200)) {
      if (atomic_load(&t->running)) break;
    }
  }
  free(pkt);
  return NULL;
}

static void tunnel_teardown(rxpc_tunnel *t) {
  if (t->threads_started) {
    atomic_store(&t->running, 0);
    if (t->threads_started >= 1) pthread_join(t->sock_thread, NULL);
    if (t->threads_started >= 2) pthread_join(t->tun_thread, NULL);
    t->threads_started = 0;
  }
  if (t->ssl) {
    SSL_shutdown(t->ssl);
    SSL_free(t->ssl);
  }
  if (t->ctx) SSL_CTX_free(t->ctx);
  if (t->sock_fd >= 0) close(t->sock_fd);
  if (t->tun_fd >= 0) close(t->tun_fd);
  if (t->address && t->interface_name) utun_remove_route(t->address);
  free(t->address);
  free(t->client_address);
  free(t->interface_name);
  t->address = NULL;
  t->client_address = NULL;
  t->interface_name = NULL;
}

void rxpc_tunnel_close(rxpc_tunnel *t) {
  if (!t) return;
  tunnel_teardown(t);
  free(t);
}

#define FAIL_IMPL(...)        \
  do {                        \
    tset_err(t, __VA_ARGS__); \
    goto out;                 \
  } while (0)

static rxpc_tunnel *tunnel_open_apple(const char *udid, const char **out_address, uint16_t *out_rsd_port, char *err,
                                      size_t errsz) {
  rxpc_tunnel *t = calloc(1, sizeof(*t));
  if (!t) {
    snprintf(err, errsz, "out of memory");
    return NULL;
  }
  t->tun_fd = -1;
  t->sock_fd = -1;

  int umx = -1;
  int ldk = -1;
  SSL_CTX *ldk_ctx = NULL;
  SSL *ldk_ssl = NULL;
  pair_fields pf;
  memset(&pf, 0, sizeof(pf));
  sbuf req = {0};
  pl_node *resp = NULL;
  long long device_id = 0;
  char eff_udid[512];

  if (geteuid() != 0) FAIL_IMPL("needs root");

  if (!udid || !*udid) {
    umx = umx_open();
    if (umx < 0) FAIL_IMPL("usbmuxd connect failed: %s", strerror(errno));
    if (umx_list_pick(umx, NULL, eff_udid, sizeof(eff_udid), &device_id) != 0) {
      close(umx);
      umx = -1;
      FAIL_IMPL("no device found via usbmuxd");
    }
    close(umx);
    umx = -1;
    udid = eff_udid;
  }

  umx = umx_open();
  if (umx < 0) FAIL_IMPL("usbmuxd connect failed: %s", strerror(errno));
  if (umx_list_pick(umx, udid, eff_udid, sizeof(eff_udid), &device_id) != 0) FAIL_IMPL("device %s not found via usbmuxd", udid);
  if (umx_read_pair(umx, udid, &pf) != 0) FAIL_IMPL("usbmuxd ReadPairRecord failed for %s", udid);
  close(umx);
  umx = -1;

  umx = umx_open();
  if (umx < 0) FAIL_IMPL("usbmuxd connect failed: %s", strerror(errno));
  ldk = umx_connect_device(umx, device_id, LOCKDOWN_PORT);
  if (ldk < 0) FAIL_IMPL("usbmuxd connect to lockdown (port %d) failed", LOCKDOWN_PORT);
  umx = -1; 

  pl_start(&req);
  pl_str(&req, "Label", LABEL);
  pl_str(&req, "Request", "StartSession");
  pl_str(&req, "HostID", pf.host_id);
  pl_str(&req, "SystemBUID", pf.system_buid);
  pl_end(&req);
  if (ls_xact(ldk, NULL, &req, &resp) != 0) FAIL_IMPL("lockdown StartSession failed");
  free(req.p);
  req.p = NULL;

  int enable_ssl = 0;
  {
    const pl_node *r = pl_dict_get(resp, "Request");
    const pl_node *sid = pl_dict_get(resp, "SessionID");
    const pl_node *e = pl_dict_get(resp, "EnableSessionSSL");
    char rs[64] = {0};
    int have_r = r && pl_str_copy(r, rs, sizeof(rs)) == 0 && strcmp(rs, "StartSession") == 0;
    if (!have_r || !sid || !e || pl_bool_val(e, &enable_ssl) != 0) {
      pl_node_free(resp);
      tset_err(t, "unexpected StartSession response");
      goto out;
    }
  }
  pl_node_free(resp);

  if (enable_ssl) {
    if (tls_upgrade(ldk, pf.host_cert, pf.host_key, &ldk_ctx, &ldk_ssl) != 0) {
      tset_err(t, "lockdown TLS upgrade failed");
      goto out;
    }
  }

  req = (sbuf){0};
  pl_start(&req);
  pl_str(&req, "Label", LABEL);
  pl_str(&req, "Request", "StartService");
  pl_str(&req, "Service", CORE_DEVICE_PROXY_SERVICE);
  pl_empty_str(&req, "EscrowBag");
  pl_end(&req);
  resp = NULL;
  if (ls_xact(ldk, ldk_ssl, &req, &resp) != 0) {
    free(req.p);
    tset_err(t, "lockdown StartService failed");
    goto out;
  }

  free(req.p);
  req.p = NULL;

  long long service_port = -1;
  {
    const pl_node *r = pl_dict_get(resp, "Request");
    const pl_node *p = pl_dict_get(resp, "Port");
    char rs[64] = {0};
    int have_r = r && pl_str_copy(r, rs, sizeof(rs)) == 0 && strcmp(rs, "StartService") == 0;
    if (!have_r || !p || pl_long(p, &service_port) != 0 || service_port <= 0) {
      pl_node_free(resp);
      tset_err(t, "unexpected StartService response for %s", CORE_DEVICE_PROXY_SERVICE);
      goto out;
    }
  }
  pl_node_free(resp);

  if (ldk_ssl) SSL_free(ldk_ssl);
  if (ldk_ctx) SSL_CTX_free(ldk_ctx);
  ldk_ssl = NULL;
  ldk_ctx = NULL;
  close(ldk);
  ldk = -1;

  umx = umx_open();
  if (umx < 0) {
    tset_err(t, "usbmuxd connect failed: %s", strerror(errno));
    goto out;
  }

  int cpd = umx_connect_device(umx, device_id, (int)service_port);
  if (cpd < 0) {
    tset_err(t, "usbmuxd connect to CoreDeviceProxy (port %lld) failed", service_port);
    goto out;
  }

  umx = -1;
  t->sock_fd = cpd;
  if (tls_upgrade(t->sock_fd, pf.host_cert, pf.host_key, &t->ctx, &t->ssl) != 0) {
    tset_err(t, "CoreDeviceProxy TLS failed");
    goto out;
  }

  if (cdtunnel_handshake(t) != 0) {
    tset_err(t, "CDTunnel handshake failed");
    goto out;
  }

  char ifname[32] = {0};
  t->tun_fd = utun_open(ifname, sizeof(ifname));
  if (t->tun_fd < 0) {
    tset_err(t, "failed to open utun: %s", strerror(errno));
    goto out;
  }

  t->interface_name = xstrdup_n(ifname, strlen(ifname));
  if (!t->interface_name) {
    tset_err(t, "out of memory");
    goto out;
  }

  if (utun_configure(ifname, t->client_address, t->mtu, t->address) != 0) {
    tset_err(t, "failed to configure %s (ifconfig/route)", ifname);
    goto out;
  }

  pair_free(&pf);

  atomic_store(&t->running, 1);
  if (pthread_create(&t->sock_thread, NULL, sock_to_tun_thread, t) != 0) t->threads_started = 0;
  else if (pthread_create(&t->tun_thread, NULL, tun_to_sock_thread, t) != 0)
    t->threads_started = 1;
  else
    t->threads_started = 2;
  if (t->threads_started != 2) {
    atomic_store(&t->running, 0);
    if (t->threads_started == 1) pthread_join(t->sock_thread, NULL);
    t->threads_started = 0;
    tset_err(t, "failed to start forwarding threads");
    goto out;
  }

  if (out_address) *out_address = t->address;
  if (out_rsd_port) *out_rsd_port = t->rsd_port;
  snprintf(err, errsz, "");

  return t;

out:
  {
    char msg[256];
    snprintf(msg, sizeof(msg), "%s", t->err);
    if (umx >= 0) close(umx);
    if (ldk >= 0) close(ldk);
    if (ldk_ssl) SSL_free(ldk_ssl);
    if (ldk_ctx) SSL_CTX_free(ldk_ctx);

    pair_free(&pf);
    free(req.p);
    if (resp) pl_node_free(resp);
    
    tunnel_teardown(t);
    snprintf(err, errsz, "%s", msg);
    free(t);

    return NULL;
  }
}

#undef FAIL_IMPL

#else /* !__APPLE__ */
#endif /* __APPLE__ */

rxpc_tunnel *rxpc_tunnel_open(const char *udid, const char **out_address, uint16_t *out_rsd_port, char *err, size_t errsz) {
#if defined(__APPLE__)
  return tunnel_open_apple(udid, out_address, out_rsd_port, err, errsz);
#else
  (void)udid;
  (void)out_address;
  (void)out_rsd_port;
  if (errsz) snprintf(err, errsz, "macos only");
  return NULL;
#endif
}

#ifndef __APPLE__
void rxpc_tunnel_close(rxpc_tunnel *t) { (void)t; }

const char *rxpc_tunnel_error(const rxpc_tunnel *t) {
  (void)t;
  return "macos only";
}

const char *rxpc_tunnel_interface(const rxpc_tunnel *t) {
  (void)t;
  return "";
}
#endif
