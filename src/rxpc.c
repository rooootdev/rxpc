//
//  rxpc.c
//  rxpc
//
//  Created by ruter on 13.09.26.
//

#define _POSIX_C_SOURCE 200809L

#include "rxpc.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define WRAPPER_MAGIC 0x29b00b92u
#define OBJECT_MAGIC 0x42133742u
#define BODY_VERSION 5u

#define MAX_XPC_BODY_SIZE (16u * 1024u * 1024u) 

#define H2_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_FRAME_HEADER_SIZE 9u
#define H2_FRAME_DATA 0x00u
#define H2_FRAME_HEADERS 0x01u
#define H2_FRAME_RST_STREAM 0x03u
#define H2_FRAME_SETTINGS 0x04u
#define H2_FRAME_PING 0x06u
#define H2_FRAME_GOAWAY 0x07u
#define H2_FRAME_WINDOW_UPDATE 0x08u
#define H2_FLAG_END_HEADERS 0x04u
#define H2_FLAG_END_STREAM 0x01u
#define H2_FLAG_ACK 0x01u
#define H2_FLAG_PADDED 0x08u
#define RXPC_FLAG_FILE_TX_STREAM_REQUEST 0x00100000u

#define H2_SETTINGS_MAX_CONCURRENT_STREAMS 0x03u
#define H2_SETTINGS_INITIAL_WINDOW_SIZE 0x04u
#define H2_SETTINGS_MAX_FRAME_SIZE 0x05u

#define H2_OUR_INITIAL_WINDOW (16u * 1024u * 1024u)
#define H2_DEFAULT_PEER_MAX_FRAME 16384u
#define H2_DEFAULT_PEER_WINDOW 65535u

#define ROOT_STREAM 1u
#define REPLY_STREAM 3u

typedef struct {
  uint8_t *d;
  size_t len;
  size_t cap;
} buf;

static void buf_init(buf *b, size_t cap) {
  b->d = NULL;
  b->len = 0;
  b->cap = 0;
  if (cap < 64) cap = 64;

  b->d = malloc(cap);
  b->cap = b->d ? cap : 0;
}

static void buf_free(buf *b) {
  free(b->d);
  b->d = NULL;
  b->len = 0;
  b->cap = 0;
}

static int buf_reserve(buf *b, size_t need) {
  if (b->len + need <= b->cap) return 0;
  size_t ncap = b->cap ? b->cap : 64;
  while (ncap < b->len + need) ncap *= 2;

  void *nd = realloc(b->d, ncap);
  if (!nd) return -1;

  b->d = nd;
  b->cap = ncap;

  return 0;
}

static int buf_append(buf *b, const void *p, size_t n) {
  if (buf_reserve(b, n) != 0) return -1;
  memcpy(b->d + b->len, p, n);
  b->len += n;

  return 0;
}

static int b_u8(buf *b, uint8_t v) { 
  return buf_append(b, &v, 1); 
}

static int b_be16(buf *b, uint16_t v) {
  uint8_t t[2] = {(uint8_t)(v >> 8), (uint8_t)v};
  return buf_append(b, t, 2);
}

static int b_be24(buf *b, uint32_t v) {
  uint8_t t[3] = {(uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  return buf_append(b, t, 3);
}

static int b_be32(buf *b, uint32_t v) {
  uint8_t t[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  return buf_append(b, t, 4);
}

static void b_le32(buf *b, uint32_t v) {
  uint8_t t[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
  (void)buf_append(b, t, 4);
}

static void b_le64(buf *b, uint64_t v) {
  uint8_t t[8] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24), (uint8_t)(v >> 32), (uint8_t)(v >> 40), (uint8_t)(v >> 48), (uint8_t)(v >> 56)};
  (void)buf_append(b, t, 8);
}

static int need(const uint8_t *d, size_t len, size_t *off, size_t n) {
  if (*off > len || n > len - *off) return -1;
  return 0;
}

static uint32_t rd_le32(const uint8_t *d, size_t len, size_t *off) {
  if (need(d, len, off, 4) != 0) {
    *off = len + 1;
    return 0xffffffffu;
  }

  uint32_t v = (uint32_t)d[*off] | ((uint32_t)d[*off + 1] << 8) | ((uint32_t)d[*off + 2] << 16) | ((uint32_t)d[*off + 3] << 24);
  *off += 4;

  return v;
}

static uint64_t rd_le64(const uint8_t *d, size_t len, size_t *off) {
  if (need(d, len, off, 8) != 0) {
    *off = len + 1;
    return 0xffffffffffffffffull;
  }

  uint64_t v = 0;
  for (int i = 7; i >= 0; i--) v = (v << 8) | d[*off + i];
  *off += 8;

  return v;
}

static uint32_t rd_be24(const uint8_t *d, size_t len, size_t *off) {
  if (need(d, len, off, 3) != 0) {
    *off = len + 1;
    return 0xffffffu;
  }

  uint32_t v = ((uint32_t)d[*off] << 16) | ((uint32_t)d[*off + 1] << 8) | d[*off + 2];
  *off += 3;

  return v;
}

static rxpc_value *val_new(rxpc_type t) {
  rxpc_value *v = calloc(1, sizeof(*v));
  if (v) v->type = t;

  return v;
}

rxpc_value *rxpc_null(void) { return val_new(RXPC_NULL); }

rxpc_value *rxpc_bool(int b) {
  rxpc_value *v = val_new(RXPC_BOOL);
  if (v) v->b = b ? 1 : 0;

  return v;
}

rxpc_value *rxpc_int(int64_t i) {
  rxpc_value *v = val_new(RXPC_INT);
  if (v) v->i = i;

  return v;
}

rxpc_value *rxpc_uint(uint64_t u) {
  rxpc_value *v = val_new(RXPC_UINT);
  if (v) v->u = u;

  return v;
}

rxpc_value *rxpc_double(double d) {
  rxpc_value *v = val_new(RXPC_DOUBLE);
  if (v) v->d = d;

  return v;
}

rxpc_value *rxpc_string(const char *s) {
  rxpc_value *v = val_new(RXPC_STRING);
  if (v) v->str = strdup(s ? s : "");

  return v;
}

rxpc_value *rxpc_data(const void *bytes, size_t len) {
  rxpc_value *v = val_new(RXPC_DATA);
  if (v) {
    v->data.bytes = malloc(len ? len : 1);
    if (bytes && len) memcpy(v->data.bytes, bytes, len);
    v->data.len = len;
  }

  return v;
}

rxpc_value *rxpc_uuid(const void *bytes16) {
  rxpc_value *v = val_new(RXPC_UUID);
  if (v) {
    v->data.bytes = malloc(16);
    if (bytes16) memcpy(v->data.bytes, bytes16, 16);
    else memset(v->data.bytes, 0, 16);
    v->data.len = 16;
  }

  return v;
}

rxpc_value *rxpc_file_transfer(size_t size, uint64_t transfer_id) {
  rxpc_value *v = val_new(RXPC_FILE_TRANSFER);
  if (v) {
    v->transfer.transfer_id = transfer_id;
    v->transfer.transfer_size = size;
  }
  return v;
}

rxpc_value *rxpc_array(void) { return val_new(RXPC_ARRAY); }
rxpc_value *rxpc_dict(void) { return val_new(RXPC_DICT); }

void rxpc_array_append(rxpc_value *arr, rxpc_value *item) {
  if (!arr || arr->type != RXPC_ARRAY || !item) return;
  rxpc_value **ni = realloc(arr->array.items, (arr->array.count + 1) * sizeof(*ni));
  if (!ni) return;

  arr->array.items = ni;
  arr->array.items[arr->array.count++] = item;
}

int rxpc_dict_set(rxpc_value *dict, const char *key, rxpc_value *val) {
  if (!dict || dict->type != RXPC_DICT || !key || !val) return -1;
  size_t n = dict->dict.count;
  char **nk = realloc(dict->dict.keys, (n + 1) * sizeof(*nk));
  rxpc_value **nv = realloc(dict->dict.vals, (n + 1) * sizeof(*nv));
  if (!nk || !nv) {
    free(nk);
    free(nv);
    return -1;
  }

  dict->dict.keys = nk;
  dict->dict.vals = nv;
  dict->dict.keys[n] = strdup(key);
  dict->dict.vals[n] = val;
  dict->dict.count++;

  return 0;
}

const rxpc_value *rxpc_dict_get(const rxpc_value *dict, const char *key) {
  if (!dict || dict->type != RXPC_DICT || !key) return NULL;
  for (size_t i = 0; i < dict->dict.count; i++) if (strcmp(dict->dict.keys[i], key) == 0) return dict->dict.vals[i];

  return NULL;
}

void rxpc_value_free(rxpc_value *v) {
  if (!v) return;
  switch (v->type) {
    case RXPC_STRING:
      free(v->str);
      break;
    case RXPC_DATA:
    case RXPC_UUID:
      free(v->data.bytes);
      break;
    case RXPC_FILE_TRANSFER:
      break;
    case RXPC_ARRAY:
      for (size_t i = 0; i < v->array.count; i++) rxpc_value_free(v->array.items[i]);
      free(v->array.items);
      break;
    case RXPC_DICT:
      for (size_t i = 0; i < v->dict.count; i++) {
        free(v->dict.keys[i]);
        rxpc_value_free(v->dict.vals[i]);
      }

      free(v->dict.keys);
      free(v->dict.vals);
      break;
    default:
      break;
  }

  free(v);
}

static rxpc_value *clone_impl(const rxpc_value *v) {
  if (!v) return NULL;
  switch (v->type) {
    case RXPC_NULL: return rxpc_null();
    case RXPC_BOOL: return rxpc_bool(v->b);
    case RXPC_INT: return rxpc_int(v->i);
    case RXPC_UINT: return rxpc_uint(v->u);
    case RXPC_DOUBLE: return rxpc_double(v->d);
    case RXPC_STRING: return rxpc_string(v->str);
    case RXPC_DATA: return rxpc_data(v->data.bytes, v->data.len);
    case RXPC_UUID: return rxpc_uuid(v->data.bytes);
    case RXPC_FILE_TRANSFER: {
      return rxpc_file_transfer(v->transfer.transfer_size, v->transfer.transfer_id);
    }
    case RXPC_ARRAY: {
      rxpc_value *n = rxpc_array();
      for (size_t i = 0; i < v->array.count; i++) rxpc_array_append(n, clone_impl(v->array.items[i]));
      return n;
    }
    case RXPC_DICT: {
      rxpc_value *n = rxpc_dict();
      for (size_t i = 0; i < v->dict.count; i++) rxpc_dict_set(n, v->dict.keys[i], clone_impl(v->dict.vals[i]));
      return n;
    }
  }

  return NULL;
}

rxpc_value *rxpc_value_clone(const rxpc_value *v) { return clone_impl(v); }

static size_t pad4(size_t len) { return (4 - (len % 4)) % 4; }

static int xenc_value(buf *b, const rxpc_value *v);
static int xenc_key(buf *b, const char *key) {
  size_t kl = strlen(key);
  if (buf_append(b, key, kl) != 0) return -1;
  if (b_u8(b, 0) != 0) return -1;
  for (size_t i = 0; i < pad4(kl + 1); i++) if (b_u8(b, 0) != 0) return -1;

  return 0;
}

static int xenc_dict_payload(buf *b, const rxpc_value *d) {
  b_le32(b, (uint32_t)d->dict.count);
  for (size_t i = 0; i < d->dict.count; i++) {
    if (xenc_key(b, d->dict.keys[i]) != 0) return -1;
    if (xenc_value(b, d->dict.vals[i]) != 0) return -1;
  }

  return 0;
}

static int xenc_value(buf *b, const rxpc_value *v) {
  if (!v) {
    b_le32(b, RXPC_NULL);
    return 0;
  }

  switch (v->type) {
    case RXPC_NULL:
      b_le32(b, RXPC_NULL);

      return 0;
    case RXPC_BOOL:
      b_le32(b, RXPC_BOOL);
      b_u8(b, v->b ? 1 : 0);
      b_u8(b, 0);
      b_u8(b, 0);
      b_u8(b, 0);

      return 0;
    case RXPC_INT:
      b_le32(b, RXPC_INT);
      b_le64(b, (uint64_t)v->i);

      return 0;
    case RXPC_UINT:
      b_le32(b, RXPC_UINT);
      b_le64(b, v->u);

      return 0;
    case RXPC_DOUBLE: {
      b_le32(b, RXPC_DOUBLE);
      uint64_t bits;
      memcpy(&bits, &v->d, 8);
      b_le64(b, bits);

      return 0;
    }
    case RXPC_STRING: {
      size_t sl = strlen(v->str);
      b_le32(b, RXPC_STRING);
      b_le32(b, (uint32_t)(sl + 1));
      if (buf_append(b, v->str, sl) != 0) return -1;
      b_u8(b, 0);
      for (size_t i = 0; i < pad4(sl + 1); i++) b_u8(b, 0);

      return 0;
    }
    case RXPC_DATA: {
      b_le32(b, RXPC_DATA);
      b_le32(b, (uint32_t)v->data.len);
      if (buf_append(b, v->data.bytes, v->data.len) != 0) return -1;
      for (size_t i = 0; i < pad4(v->data.len); i++) b_u8(b, 0);

      return 0;
    }
    case RXPC_UUID: {
      b_le32(b, RXPC_UUID);
      if (buf_append(b, v->data.bytes, 16) != 0) return -1;

      return 0;
    }
    case RXPC_ARRAY: {
      buf inner;
      buf_init(&inner, 64);
      b_le32(&inner, (uint32_t)v->array.count);
      for (size_t i = 0; i < v->array.count; i++) {
        if (xenc_value(&inner, v->array.items[i]) != 0) {
          free(inner.d);
          return -1;
        }
      }

      b_le32(b, RXPC_ARRAY);
      b_le32(b, (uint32_t)inner.len);
      int rc = buf_append(b, inner.d, inner.len);
      free(inner.d);

      return rc;
    }
    case RXPC_DICT: {
      buf inner;
      buf_init(&inner, 64);
      if (xenc_dict_payload(&inner, v) != 0) {
        free(inner.d);
        return -1;
      }

      b_le32(b, RXPC_DICT);
      b_le32(b, (uint32_t)inner.len);
      int rc = buf_append(b, inner.d, inner.len);
      free(inner.d);

      return rc;
    }
    case RXPC_FILE_TRANSFER: {
      buf inner;
      buf_init(&inner, 32);

      rxpc_value *size = rxpc_uint(v->transfer.transfer_size);
      rxpc_value *dict = rxpc_dict();
      if (!size || !dict || rxpc_dict_set(dict, "s", size) != 0 || xenc_value(&inner, dict) != 0) {
        rxpc_value_free(size);
        rxpc_value_free(dict);
        buf_free(&inner);
        return -1;
      }

      b_le32(b, RXPC_FILE_TRANSFER);
      b_le64(b, v->transfer.transfer_id);
      int rc = buf_append(b, inner.d, inner.len);
      rxpc_value_free(dict);
      buf_free(&inner);

      return rc;
    }
    default:
      return -1;
  }
}

static void xenc_message(buf *b, uint32_t flags, uint64_t id, const rxpc_value *body) {
  b_le32(b, WRAPPER_MAGIC);
  if (!body) {
    b_le32(b, flags);
    b_le64(b, 0);
    b_le64(b, id);
    return;
  }
  buf inner;
  buf_init(&inner, 64);
  (void)xenc_value(&inner, body);
  b_le32(b, flags);
  b_le64(b, (uint64_t)(inner.len + 8));
  b_le64(b, id);
  b_le32(b, OBJECT_MAGIC);
  b_le32(b, BODY_VERSION);
  (void)buf_append(b, inner.d, inner.len);
  free(inner.d);
}

static rxpc_value *xdec_val(const uint8_t *d, size_t len, size_t *off);
static char *xdec_key(const uint8_t *d, size_t len, size_t *off) {
  size_t start = *off;
  size_t kl = 0;
  while (*off < len && d[*off] != 0) {
    (*off)++;
    kl++;
  }

  if (*off >= len) return NULL;
  (*off)++;

  size_t pad = pad4(kl + 1);
  if (*off + pad > len) return NULL;
  *off += pad;

  char *key = malloc(kl + 1);
  if (!key) return NULL;
  memcpy(key, d + start, kl);
  key[kl] = 0;

  return key;
}

static rxpc_value *xdec_dict(const uint8_t *d, size_t len, size_t *off) {
  uint32_t count = rd_le32(d, len, off);
  if (count == 0xffffffffu) return NULL;
  rxpc_value *dict = rxpc_dict();
  if (!dict) return NULL;
  for (uint32_t i = 0; i < count; i++) {
    char *key = xdec_key(d, len, off);
    if (!key) {
      rxpc_value_free(dict);
      return NULL;
    }

    rxpc_value *val = xdec_val(d, len, off);
    if (!val) {
      free(key);
      rxpc_value_free(dict);
      return NULL;
    }

    rxpc_dict_set(dict, key, val);
    free(key);
  }

  return dict;
}

static rxpc_value *xdec_val(const uint8_t *d, size_t len, size_t *off) {
  uint32_t type = rd_le32(d, len, off);
  if (type == 0xffffffffu) return NULL;
  switch (type) {
    case RXPC_NULL:
      return rxpc_null();
    case RXPC_BOOL:
      if (need(d, len, off, 4) != 0) return NULL;
      {
        int b = d[*off] != 0;
        *off += 4;

        return rxpc_bool(b);
      }
    case RXPC_INT: {
      if (need(d, len, off, 8) != 0) return NULL;
      uint64_t raw = rd_le64(d, len, off);

      return rxpc_int((int64_t)raw);
    }
    case RXPC_UINT: {
      if (need(d, len, off, 8) != 0) return NULL;
      uint64_t raw = rd_le64(d, len, off);

      return rxpc_uint(raw);
    }
    case RXPC_DOUBLE: {
      if (need(d, len, off, 8) != 0) return NULL;
      uint64_t raw = rd_le64(d, len, off);
      double dv;
      memcpy(&dv, &raw, 8);

      return rxpc_double(dv);
    }
    case RXPC_DATA: {
      uint32_t dl = rd_le32(d, len, off);
      if (dl == 0xffffffffu || need(d, len, off, dl) != 0) return NULL;
      rxpc_value *v = rxpc_data(d + *off, dl);
      *off += dl;

      size_t pad = pad4(dl);
      if (need(d, len, off, pad) != 0) {
        rxpc_value_free(v);
        return NULL;
      }

      *off += pad;

      return v;
    }
    case RXPC_STRING: {
      uint32_t sl = rd_le32(d, len, off);
      if (sl == 0xffffffffu || need(d, len, off, sl) != 0) return NULL;
      size_t start = *off;
      *off += sl;
      size_t cl = 0;
      while (cl < sl && d[start + cl] != 0) cl++;
      char *s = malloc(cl + 1);
      if (!s) return NULL;
      memcpy(s, d + start, cl);
      s[cl] = 0;
      rxpc_value *v = rxpc_string(s);
      free(s);

      size_t pad = pad4(sl);
      if (need(d, len, off, pad) != 0) {
        rxpc_value_free(v);
        return NULL;
      }

      *off += pad;

      return v;
    }
    case RXPC_UUID:
      if (need(d, len, off, 16) != 0) return NULL;
      {
        rxpc_value *v = rxpc_uuid(d + *off);
        *off += 16;

        return v;
      }
    case RXPC_ARRAY: {
      uint32_t pl = rd_le32(d, len, off);
      if (pl == 0xffffffffu || need(d, len, off, pl) != 0) return NULL;

      size_t end = *off + pl;
      uint32_t count = rd_le32(d, len, off);
      if (count == 0xffffffffu || *off > end) return NULL;

      rxpc_value *arr = rxpc_array();
      if (!arr) return NULL;
      for (uint32_t i = 0; i < count; i++) {
        if (*off >= end && i + 1 < count) {
          rxpc_value_free(arr);
          return NULL;
        }

        rxpc_value *item = xdec_val(d, len, off);
        if (!item || *off > end) {
          rxpc_value_free(arr);
          return NULL;
        }

        rxpc_array_append(arr, item);
      }
      *off = end;

      return arr;
    }
    case RXPC_DICT: {
      uint32_t pl = rd_le32(d, len, off);
      if (pl == 0xffffffffu || need(d, len, off, pl) != 0) return NULL;

      size_t end = *off + pl;
      rxpc_value *dict = xdec_dict(d, len, off);

      if (!dict) return NULL;
      *off = end;

      return dict;
    }
    case RXPC_FILE_TRANSFER: {
      uint64_t id = rd_le64(d, len, off);
      rxpc_value *meta = xdec_val(d, len, off);
      if (!meta || meta->type != RXPC_DICT) {
        rxpc_value_free(meta);
        return NULL;
      }

      const rxpc_value *size = rxpc_dict_get(meta, "s");
      rxpc_value *v = size && size->type == RXPC_UINT ? rxpc_file_transfer((size_t)size->u, id) : NULL;
      rxpc_value_free(meta);
      
      return v;
    }
    default:
      return NULL;
  }
}

struct msg {
  uint32_t flags;
  uint64_t id;
  rxpc_value *body;
  struct msg *next;
};

struct rxpc_conn {
  int fd;
  int connected;
  char err[256];

  uint32_t peer_max_frame;
  uint32_t conn_send_window;
  uint32_t root_send_window;
  uint32_t reply_send_window;

  buf inbuf;
  buf pending1;
  buf pending3;
  struct msg *qhead;
  struct msg *qtail;
  uint64_t next_msg_id;
  uint32_t next_file_stream;
  uint32_t file_send_window;
  uint32_t file_stream;
  int peer_settings_seen;
};

static _Thread_local char rxpc_last_err[1024];

static void set_err(rxpc_conn *c, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(c->err, sizeof(c->err), fmt, ap);
  va_end(ap);
  snprintf(rxpc_last_err, sizeof(rxpc_last_err), "%s", c->err);
}

static int write_all(int fd, const void *p, size_t n) {
  const uint8_t *d = p;
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, d + off, n - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    off += (size_t)w;
  }

  return 0;
}

static int connect_with_timeout(int fd, const struct sockaddr *sa, socklen_t slen, int timeout_ms) {
  int rc = connect(fd, sa, slen);
  if (rc == 0) return 0;
  if (errno != EINPROGRESS) return -1;
  struct pollfd pfd = {fd, POLLOUT, 0};
  rc = poll(&pfd, 1, timeout_ms);
  if (rc <= 0) {
    errno = rc == 0 ? ETIMEDOUT : errno;
    return -1;
  }

  int soerr = 0;
  socklen_t elen = sizeof(soerr);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &elen) != 0 || soerr != 0) {
    errno = soerr ? soerr : EIO;
    return -1;
  }

  return 0;
}

static int send_frame(rxpc_conn *c, uint32_t type, uint32_t flags, uint32_t stream, const void *body, size_t blen) {
  uint8_t hdr[H2_FRAME_HEADER_SIZE];
  hdr[0] = (uint8_t)(blen >> 16);
  hdr[1] = (uint8_t)(blen >> 8);
  hdr[2] = (uint8_t)blen;
  hdr[3] = (uint8_t)type;
  hdr[4] = (uint8_t)flags;
  hdr[5] = (uint8_t)((stream >> 24) & 0x7f);
  hdr[6] = (uint8_t)(stream >> 16);
  hdr[7] = (uint8_t)(stream >> 8);
  hdr[8] = (uint8_t)stream;

  if (write_all(c->fd, hdr, sizeof(hdr)) != 0) return -1;
  if (blen && write_all(c->fd, body, blen) != 0) return -1;

  return 0;
}

static int send_window_update(rxpc_conn *c, uint32_t stream, uint32_t incr) {
  uint8_t body[4] = {(uint8_t)((incr >> 24) & 0x7f), (uint8_t)(incr >> 16), (uint8_t)(incr >> 8), (uint8_t)incr};
  return send_frame(c, H2_FRAME_WINDOW_UPDATE, 0, stream, body, 4);
}

static void enqueue_msg(rxpc_conn *c, uint32_t flags, uint64_t id, rxpc_value *body) {
  struct msg *m = malloc(sizeof(*m));
  if (!m) {
    rxpc_value_free(body);
    return;
  }

  m->flags = flags;
  m->id = id;
  m->body = body;
  m->next = NULL;

  if (c->qtail) {
    c->qtail->next = m;
  } else {
    c->qhead = m;
  }

  c->qtail = m;
}

static int ingest_stream(rxpc_conn *c, buf *pb) {
  while (pb->len >= 24) {
    uint32_t magic = (uint32_t)pb->d[0] | ((uint32_t)pb->d[1] << 8) | ((uint32_t)pb->d[2] << 16) | ((uint32_t)pb->d[3] << 24);
    if (magic != WRAPPER_MAGIC) {
      set_err(c, "desynced: bad xpc wrapper magic 0x%08x", magic);
      return -1;
    }

    uint64_t blen = (uint64_t)pb->d[8] | ((uint64_t)pb->d[9] << 8) | ((uint64_t)pb->d[10] << 16) | ((uint64_t)pb->d[11] << 24) | ((uint64_t)pb->d[12] << 32) | ((uint64_t)pb->d[13] << 40) | ((uint64_t)pb->d[14] << 48) | ((uint64_t)pb->d[15] << 56);
    if (blen > MAX_XPC_BODY_SIZE) {
      set_err(c, "desynced: xpc body length %llu exceeds bound", (unsigned long long)blen);
      return -1;
    }

    size_t total = 24 + (size_t)blen;
    if (pb->len < total) break;

    size_t off = 0;
    (void)rd_le32(pb->d, total, &off); /* magic */
    uint32_t flags = rd_le32(pb->d, total, &off);
    (void)rd_le64(pb->d, total, &off); /* bodyLen */
    uint64_t id = rd_le64(pb->d, total, &off);

    rxpc_value *body = NULL;
    if (blen > 0) {
      size_t boff = off;
      uint32_t om = rd_le32(pb->d, total, &boff);
      uint32_t ov = rd_le32(pb->d, total, &boff);
      if (om != OBJECT_MAGIC || ov != BODY_VERSION) {
        set_err(c, "bad xpc body header (magic 0x%08x version 0x%08x)", om, ov);
        return -1;
      }

      body = xdec_val(pb->d, total, &boff);
      if (!body || body->type != RXPC_DICT) {
        rxpc_value_free(body);
        set_err(c, "could not decode xpc body value", "");
        return -1;
      }
    }
    enqueue_msg(c, flags, id, body);
    memmove(pb->d, pb->d + total, pb->len - total);
    pb->len -= total;
  }

  return 0;
}

static int handle_data(rxpc_conn *c, uint32_t stream, const uint8_t *data, size_t n, size_t raw_len) {
  if ((stream & 1) == 0 && raw_len > 0) {
    if (send_window_update(c, 0, (uint32_t)raw_len) != 0) {
      set_err(c, "failed to send WINDOW_UPDATE: %s", strerror(errno));
      return -1;
    }

    if (send_window_update(c, stream, (uint32_t)raw_len) != 0) {
      set_err(c, "failed to send WINDOW_UPDATE: %s", strerror(errno));
      return -1;
    }
  }

  buf *pb = stream == ROOT_STREAM ? &c->pending1 : stream == REPLY_STREAM ? &c->pending3 : NULL;
  if (pb && n > 0) {
    if (buf_append(pb, data, n) != 0) {
      set_err(c, "out of memory buffering xpc stream", "");
      return -1;
    }

    return ingest_stream(c, pb);
  }

  return 0;
}

static int apply_settings(rxpc_conn *c, const uint8_t *body, size_t n) {
  size_t off = 0;
  while (off + 6 <= n) {
    uint16_t id = (uint16_t)(((uint16_t)body[off] << 8) | body[off + 1]);
    uint32_t val = ((uint32_t)body[off + 2] << 24) | ((uint32_t)body[off + 3] << 16) | ((uint32_t)body[off + 4] << 8) |
                   body[off + 5];
    switch (id) {
      case H2_SETTINGS_MAX_FRAME_SIZE:
        c->peer_max_frame = val;
        break;
      case H2_SETTINGS_INITIAL_WINDOW_SIZE:
        c->root_send_window = val;
        c->reply_send_window = val;
        c->file_send_window = val;
        break;
      default:
        break;
    }

    off += 6;
  }

  return 0;
}

static int rxpc_pump(rxpc_conn *c, int timeout_ms) {
  struct pollfd pfd = {c->fd, POLLIN, 0};
  int rc = poll(&pfd, 1, timeout_ms);
  if (rc < 0) {
    if (errno == EINTR) return 0;
    set_err(c, "poll failed: %s", strerror(errno));
    return -1;
  }

  if (rc == 0) return 0;

  uint8_t tmp[16384];
  ssize_t r = read(c->fd, tmp, sizeof(tmp));
  if (r < 0) {
    if (errno == EINTR) return 0;
    set_err(c, "read failed: %s", strerror(errno));
    return -1;
  }

  if (r == 0) {
    set_err(c, "connection closed by peer", "");
    return -1;
  }

  if (buf_append(&c->inbuf, tmp, (size_t)r) != 0) {
    set_err(c, "out of memory buffering frames", "");
    return -1;
  }

  int processed = 0;
  while (c->inbuf.len >= H2_FRAME_HEADER_SIZE) {
    size_t off = 0;
    uint32_t flen = rd_be24(c->inbuf.d, c->inbuf.len, &off);
    uint8_t type = off < c->inbuf.len ? c->inbuf.d[off] : 0;
    uint8_t flags = off < c->inbuf.len ? c->inbuf.d[off + 1] : 0;
    uint32_t stream = 0;
    if (off + 4 <= c->inbuf.len) {
      stream = ((uint32_t)c->inbuf.d[off + 2] << 24) | ((uint32_t)c->inbuf.d[off + 3] << 16) | ((uint32_t)c->inbuf.d[off + 4] << 8) | c->inbuf.d[off + 5];
      stream &= 0x7fffffff;
    }

    size_t total = H2_FRAME_HEADER_SIZE + flen;
    if (c->inbuf.len < total) break;
    const uint8_t *fb = c->inbuf.d + H2_FRAME_HEADER_SIZE;

    switch (type) {
      case H2_FRAME_DATA: {
        const uint8_t *dat = fb;
        size_t dlen = flen;
        if (flags & H2_FLAG_PADDED) {
          if (dlen == 0) {
            set_err(c, "protocol error: padded DATA with empty payload", "");
            return -1;
          }

          uint8_t p = fb[0];
          if (p > dlen) {
            set_err(c, "protocol error: padding exceeds DATA length", "");
            return -1;
          }

          dat = fb + 1;
          dlen = dlen - 1 - p;
        }

        if (handle_data(c, stream, dat, dlen, flen) != 0) return -1;
        processed = 1;
        break;
      }
      case H2_FRAME_SETTINGS:
        if (!(flags & H2_FLAG_ACK)) {
          (void)apply_settings(c, fb, flen);
          c->peer_settings_seen = 1;
          processed = 1;
        }

        break;
      case H2_FRAME_WINDOW_UPDATE: {
        if (flen >= 4) {
          uint32_t incr = ((uint32_t)fb[0] << 24) | ((uint32_t)fb[1] << 16) | ((uint32_t)fb[2] << 8) | fb[3];
          incr &= 0x7fffffff;
          if (stream == 0) c->conn_send_window += incr;
          else if (stream == ROOT_STREAM) c->root_send_window += incr;
          else if (stream == REPLY_STREAM) c->reply_send_window += incr;
          else if (stream == c->file_stream) c->file_send_window += incr;

          processed = 1;
        }

        break;
      }
      case H2_FRAME_RST_STREAM:
        {
          uint32_t code = flen >= 4 ? ((uint32_t)fb[0] << 24) | ((uint32_t)fb[1] << 16) | ((uint32_t)fb[2] << 8) | fb[3] : 0;
          if ((stream & 1u) && stream >= 5 && stream < c->next_file_stream) {
            processed = 1;
            break;
          }

          set_err(c, "peer sent RST_STREAM (error %u)", code);

          return -1;
        }
      case H2_FRAME_GOAWAY:
        {
          uint32_t code = flen >= 8 ? ((uint32_t)fb[4] << 24) | ((uint32_t)fb[5] << 16) | ((uint32_t)fb[6] << 8) | fb[7] : 0;
          set_err(c, "peer sent GOAWAY (error %u)", code);

          return -1;
        }
      case H2_FRAME_PING:
      case H2_FRAME_HEADERS:
      default:
        processed = 1;
        break;
    }
    memmove(c->inbuf.d, c->inbuf.d + total, c->inbuf.len - total);
    c->inbuf.len -= total;
  }
  return processed ? 1 : 0;
}

static void frame_hdr(buf *b, uint32_t type, uint32_t flags, uint32_t stream, size_t blen) {
  (void)b_be24(b, (uint32_t)blen);
  (void)b_u8(b, (uint8_t)type);
  (void)b_u8(b, (uint8_t)flags);
  (void)b_be32(b, stream & 0x7fffffff);
}

static void frame_headers(buf *b, uint32_t stream) {
  frame_hdr(b, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, stream, 0);
}

static void frame_data(buf *b, uint32_t stream, const uint8_t *payload, size_t blen) {
  frame_hdr(b, H2_FRAME_DATA, 0, stream, blen);
  (void)buf_append(b, payload, blen);
}

static void frame_settings(buf *b, uint32_t flags, const uint8_t *setval, size_t blen) {
  frame_hdr(b, H2_FRAME_SETTINGS, flags, 0, blen);
  if (blen) (void)buf_append(b, setval, blen);
}

static void frame_window_update(buf *b, uint32_t stream, uint32_t incr) {
  uint8_t wb[4] = {(uint8_t)((incr >> 24) & 0x7f), (uint8_t)(incr >> 16), (uint8_t)(incr >> 8), (uint8_t)incr};
  frame_hdr(b, H2_FRAME_WINDOW_UPDATE, 0, stream, 4);
  (void)buf_append(b, wb, 4);
}

static int rxpc_pump(rxpc_conn *c, int timeout_ms);

static int perform_handshake(rxpc_conn *c) {
  buf b;
  buf_init(&b, 512);

  (void)buf_append(&b, H2_MAGIC, strlen(H2_MAGIC));

  {
    buf set;
    buf_init(&set, 16);
    (void)b_be16(&set, H2_SETTINGS_MAX_CONCURRENT_STREAMS);
    (void)b_be32(&set, 100);
    (void)b_be16(&set, H2_SETTINGS_INITIAL_WINDOW_SIZE);
    (void)b_be32(&set, H2_OUR_INITIAL_WINDOW);
    frame_settings(&b, 0, set.d, set.len);
    free(set.d);
  }

  frame_window_update(&b, 0, H2_OUR_INITIAL_WINDOW - H2_DEFAULT_PEER_WINDOW);
  frame_headers(&b, ROOT_STREAM);

  {
    buf m;
    buf_init(&m, 64);
    rxpc_value *empty = rxpc_dict();
    xenc_message(&m, RXPC_FLAG_ALWAYS_SET, 0, empty);
    rxpc_value_free(empty);
    frame_data(&b, ROOT_STREAM, m.d, m.len);
    free(m.d);
  }

  frame_headers(&b, REPLY_STREAM);

  {
    buf m;
    buf_init(&m, 32);
    xenc_message(&m, 0x0201u, 0, NULL);
    frame_data(&b, ROOT_STREAM, m.d, m.len);
    free(m.d);
  }

  {
    buf m;
    buf_init(&m, 32);
    xenc_message(&m, RXPC_FLAG_ALWAYS_SET | RXPC_FLAG_INIT_HANDSHAKE, 0, NULL);
    frame_data(&b, REPLY_STREAM, m.d, m.len);
    free(m.d);
  }

  int rc = write_all(c->fd, b.d, b.len);
  free(b.d);
  if (rc != 0) return rc;

  for (int i = 0; i < 100 && !c->peer_settings_seen; i++) {
    if (rxpc_pump(c, 100) < 0) return -1;
  }
  if (!c->peer_settings_seen) return -1;

  b.d = NULL;
  b.len = 0;
  b.cap = 0;
  frame_settings(&b, H2_FLAG_ACK, NULL, 0);
  rc = write_all(c->fd, b.d, b.len);
  free(b.d);
  return rc;
}

rxpc_conn *rxpc_connect(const char *host, const char *port, int timeout_ms) {
  rxpc_conn *c = calloc(1, sizeof(*c));
  if (!c) return NULL;
  c->fd = -1;
  c->err[0] = 0;
  c->peer_max_frame = H2_DEFAULT_PEER_MAX_FRAME;
  c->conn_send_window = H2_DEFAULT_PEER_WINDOW;
  c->root_send_window = H2_DEFAULT_PEER_WINDOW;
  c->reply_send_window = H2_DEFAULT_PEER_WINDOW;
  c->next_file_stream = 5;
  c->file_send_window = H2_DEFAULT_PEER_WINDOW;
  buf_init(&c->inbuf, 4096);
  buf_init(&c->pending1, 256);
  buf_init(&c->pending3, 256);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo *res = NULL;
  if (getaddrinfo(host, port, &hints, &res) != 0) {
    set_err(c, "getaddrinfo %s failed", host);
    rxpc_close(c);
    return NULL;
  }

  for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
    int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (fd < 0) continue;
    if (connect_with_timeout(fd, ai->ai_addr, ai->ai_addrlen, timeout_ms) != 0) {
      close(fd);
      continue;
    }

    int one = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    c->fd = fd;

    break;
  }

  freeaddrinfo(res);

  if (c->fd < 0) {
    snprintf(c->err, sizeof(c->err), "connect to %s:%s failed: %s", host, port, strerror(errno));
    rxpc_close(c);
    return NULL;
  }

  if (perform_handshake(c) != 0) {
    set_err(c, "handshake write failed: %s", strerror(errno));
    rxpc_close(c);
    return NULL;
  }

  c->connected = 1;
  return c;
}

void rxpc_close(rxpc_conn *c) {
  if (!c) return;
  if (c->fd >= 0) close(c->fd);
  c->fd = -1;
  c->connected = 0;
  buf_free(&c->inbuf);
  buf_free(&c->pending1);
  buf_free(&c->pending3);
  struct msg *m = c->qhead;
  while (m) {
    struct msg *n = m->next;
    rxpc_value_free(m->body);
    free(m);
    m = n;
  }

  free(c);
}

int rxpc_connected(const rxpc_conn *c) { return c && c->connected; }

const char *rxpc_error(const rxpc_conn *c) {
  if (c && c->err[0]) return c->err;
  if (rxpc_last_err[0]) return rxpc_last_err;
  return "no error";
}

static uint64_t rxpc_now_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000u + (uint64_t)tv.tv_usec / 1000u;
}

static int rxpc_remaining_deadline(uint64_t deadline_ms, int *out_rem) {
  uint64_t now = rxpc_now_ms();
  if (now >= deadline_ms) return 0;
  uint64_t left = deadline_ms - now;
  *out_rem = left > 60000u ? 60000 : (int)left;
  return 1;
}

rxpc_value *rxpc_recv(rxpc_conn *c, int timeout_ms, uint32_t *out_flags, uint64_t *out_id) {
  if (!c || !c->connected) {
    set_err(c, "not connected", "");
    return NULL;
  }

  uint64_t deadline = rxpc_now_ms() + (timeout_ms > 0 ? (uint64_t)timeout_ms : 0u);
  for (;;) {
    if (c->qhead) {
      struct msg *m = c->qhead;
      c->qhead = m->next;
      if (!c->qhead) c->qtail = NULL;
      if (!m->body) {
        free(m);
        continue;
      }
      rxpc_value *body = m->body;
      if (out_flags) *out_flags = m->flags;
      if (out_id) *out_id = m->id;
      free(m);
      return body;
    }

    int rem = 0;
    if (!rxpc_remaining_deadline(deadline, &rem)) {
      set_err(c, "timed out waiting for an XPC message", "");
      return NULL;
    }
    int rc = rxpc_pump(c, rem);
    if (rc < 0) return NULL;
  }
}

int rxpc_send(rxpc_conn *c, uint32_t flags, uint64_t id, const rxpc_value *body) {
  if (!c || !c->connected) {
    set_err(c, "not connected", "");
    return -1;
  }

  buf m;
  buf_init(&m, 256);
  xenc_message(&m, flags, id, body);

  size_t off = 0;
  while (off < m.len) {
    uint32_t win = c->conn_send_window;
    if (c->root_send_window < win) win = c->root_send_window;
    size_t chunk = m.len - off;
    if (c->peer_max_frame && (uint32_t)chunk > c->peer_max_frame) chunk = c->peer_max_frame;
    if ((uint32_t)chunk > win) chunk = win;

    if (chunk == 0) {
      int rc = rxpc_pump(c, 100);
      if (rc < 0) {
        free(m.d);
        return -1;
      }

      if (rc == 0) continue;
      continue;
    }

    if (send_frame(c, H2_FRAME_DATA, 0, ROOT_STREAM, m.d + off, chunk) != 0) {
      set_err(c, "DATA write failed: %s", strerror(errno));
      free(m.d);
      return -1;
    }

    c->conn_send_window -= (uint32_t)chunk;
    c->root_send_window -= (uint32_t)chunk;
    off += chunk;
  }

  free(m.d);
  return 0;
}

int rxpc_send_file_transfer(rxpc_conn *c, uint64_t transfer_id, const void *data, size_t len, int timeout_ms) {
  if (!c || !c->connected || (!data && len)) {
    set_err(c, "invalid file transfer", "");
    return -1;
  }

  const uint32_t stream = c->next_file_stream;
  c->next_file_stream += 2;
  c->file_stream = stream;
  if (send_frame(c, H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, stream, NULL, 0) != 0) {
    set_err(c, "file transfer HEADERS write failed: %s", strerror(errno));
    return -1;
  }

  buf preamble;
  buf_init(&preamble, 32);
  xenc_message(&preamble, RXPC_FLAG_ALWAYS_SET | RXPC_FLAG_FILE_TX_STREAM_REQUEST, transfer_id, NULL);
  size_t off = 0;

  while (off < preamble.len) {
    uint32_t win = c->conn_send_window;
    if (c->file_send_window < win) win = c->file_send_window;
    if (c->peer_max_frame && win > c->peer_max_frame) win = c->peer_max_frame;
    if (win == 0) {
      if (rxpc_pump(c, timeout_ms) < 0) { buf_free(&preamble); return -1; }
      continue;
    }

    size_t n = preamble.len - off;
    if (n > win) n = win;
    if (send_frame(c, H2_FRAME_DATA, 0, stream, preamble.d + off, n) != 0) {
      set_err(c, "file transfer preamble write failed: %s", strerror(errno));
      buf_free(&preamble);
      return -1;
    }

    c->conn_send_window -= (uint32_t)n;
    c->file_send_window -= (uint32_t)n;
    off += n;
  }

  buf_free(&preamble);

  off = 0;
  while (off < len) {
    uint32_t win = c->conn_send_window;
    if (c->file_send_window < win) win = c->file_send_window;
    if (c->peer_max_frame && win > c->peer_max_frame) win = c->peer_max_frame;
    if (win == 0) {
      if (rxpc_pump(c, timeout_ms) < 0) return -1;
      continue;
    }

    size_t n = len - off;
    if (n > win) n = win;
    if (send_frame(c, H2_FRAME_DATA, 0, stream, (const uint8_t *)data + off, n) != 0) {
      set_err(c, "file transfer data write failed: %s", strerror(errno));
      return -1;
    }

    c->conn_send_window -= (uint32_t)n;
    c->file_send_window -= (uint32_t)n;
    off += n;
  }

  if (send_frame(c, H2_FRAME_DATA, H2_FLAG_END_STREAM, stream, NULL, 0) != 0) {
    set_err(c, "file transfer close write failed: %s", strerror(errno));
    return -1;
  }

  c->file_stream = 0;
  return 0;
}

rxpc_service *rxpc_parse_services(const rxpc_value *peer_info, size_t *out_count) {
  *out_count = 0;
  if (!peer_info || peer_info->type != RXPC_DICT) return NULL;
  const rxpc_value *svcs = rxpc_dict_get(peer_info, "Services");
  if (!svcs || svcs->type != RXPC_DICT) return NULL;

  rxpc_service *arr = calloc(svcs->dict.count ? svcs->dict.count : 1, sizeof(*arr));
  if (!arr) return NULL;

  size_t n = 0;
  for (size_t i = 0; i < svcs->dict.count; i++) {
    const rxpc_value *info = svcs->dict.vals[i];
    if (!info || info->type != RXPC_DICT) continue;
    const rxpc_value *port = rxpc_dict_get(info, "Port");
    char portbuf[32] = {0};
    if (port && port->type == RXPC_STRING) {
      snprintf(portbuf, sizeof(portbuf), "%s", port->str);
    } else if (port && port->type == RXPC_INT) {
      snprintf(portbuf, sizeof(portbuf), "%lld", (long long)port->i);
    } else if (port && port->type == RXPC_UINT) {
      snprintf(portbuf, sizeof(portbuf), "%llu", (unsigned long long)port->u);
    }

    if (!portbuf[0]) continue;
    arr[n].name = strdup(svcs->dict.keys[i]);
    arr[n].port = strdup(portbuf);
    if (arr[n].name && arr[n].port) {
      n++;
    } else {
      free(arr[n].name);
      free(arr[n].port);
    }
  }

  if (n == 0) {
    free(arr);
    return NULL;
  }

  *out_count = n;

  return arr;
}

void rxpc_services_free(rxpc_service *services, size_t count) {
  if (!services) return;
  for (size_t i = 0; i < count; i++) {
    free(services[i].name);
    free(services[i].port);
  }

  free(services);
}

const char *rxpc_service_port(const rxpc_service *services, size_t count, const char *name) {
  for (size_t i = 0; i < count; i++) if (strcmp(services[i].name, name) == 0) return services[i].port;
  return NULL;
}

int rxpc_discover_services(rxpc_conn *c, int timeout_ms, rxpc_value **out_peer_info, rxpc_service **out_services, size_t *out_count) {
  if (out_peer_info) *out_peer_info = NULL;
  if (out_services) *out_services = NULL;
  if (out_count) *out_count = 0;

  rxpc_value *peer_info = NULL;
  rxpc_service *services = NULL;
  size_t count = 0;

  for (;;) {
    rxpc_value *body = rxpc_recv(c, timeout_ms, NULL, NULL);
    if (!body) return -1;
    if (body->type != RXPC_DICT || rxpc_dict_get(body, "Services") == NULL) {
      rxpc_value_free(body);
      continue;
    }

    peer_info = body;
    break;
  }

  services = rxpc_parse_services(peer_info, &count);
  if (out_peer_info) *out_peer_info = peer_info;
  else rxpc_value_free(peer_info);
  if (out_services) *out_services = services;
  else rxpc_services_free(services, count);
  if (out_count) *out_count = count;
  return 0;
}

static void random_bytes(uint8_t *out, size_t n) {
  size_t got = 0;
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    while (got < n) {
      ssize_t r = read(fd, out + got, n - got);
      if (r <= 0) break;
      got += (size_t)r;
    }

    close(fd);
  }

  static uint64_t seed = 0x9e3779b97f4a7c15ull;
  for (size_t i = got; i < n; i++) {
    seed = seed * 6364136223846793005ull + 1442695040888963407ull;
    out[i] = (uint8_t)(seed >> 56);
  }
}

static void uuid_v4_bytes(uint8_t out[16]) {
  random_bytes(out, 16);
  out[6] = (uint8_t)((out[6] & 0x0f) | 0x40);
  out[8] = (uint8_t)((out[8] & 0x3f) | 0x80);
}

rxpc_value *rxpc_coredevice_envelope(const char *feature, const rxpc_value *input) {
  rxpc_value *env = rxpc_dict();
  rxpc_dict_set(env, "CoreDevice.CoreDeviceDDIProtocolVersion", rxpc_int(2));

  rxpc_value *ver = rxpc_dict();
  rxpc_value *comp = rxpc_array();
  rxpc_array_append(comp, rxpc_uint(629));
  rxpc_array_append(comp, rxpc_uint(3));
  rxpc_dict_set(ver, "components", comp);
  rxpc_dict_set(ver, "originalComponentsCount", rxpc_int(2));
  rxpc_dict_set(ver, "stringValue", rxpc_string("629.3"));
  rxpc_dict_set(env, "CoreDevice.coreDeviceVersion", ver);

  uint8_t devid[16], invid[16];
  uuid_v4_bytes(devid);
  uuid_v4_bytes(invid);
  rxpc_dict_set(env, "CoreDevice.deviceIdentifier", rxpc_data(devid, 16));
  rxpc_dict_set(env, "CoreDevice.input", rxpc_value_clone(input));
  rxpc_dict_set(env, "CoreDevice.invocationIdentifier", rxpc_data(invid, 16));

  if (feature) {
    rxpc_dict_set(env, "CoreDevice.featureIdentifier", rxpc_string(feature));
    rxpc_dict_set(env, "CoreDevice.action", rxpc_dict());
  }

  return env;
}

int rxpc_coredevice_invoke(rxpc_conn *c, uint64_t id, const char *feature, const rxpc_value *input, int timeout_ms, rxpc_value **out_reply) {
  if (out_reply) *out_reply = NULL;
  if (!c || !c->connected) {
    set_err(c, "not connected", "");
    return -1;
  }

  rxpc_value *env = rxpc_coredevice_envelope(feature, input);
  if (!env) return -1;
  int rc = rxpc_send(c, RXPC_FLAG_ALWAYS_SET | RXPC_FLAG_DATA_PRESENT | RXPC_FLAG_WANTING_REPLY, id, env);
  rxpc_value_free(env);
  if (rc != 0) return -1;

  for (;;) {
    rxpc_value *body = rxpc_recv(c, timeout_ms, NULL, NULL);
    if (!body) return -1;
    if (body->type != RXPC_DICT || body->dict.count == 0) {
      rxpc_value_free(body);
      continue;
    }

    if (out_reply) *out_reply = body;
    else rxpc_value_free(body);

    return 0;
  }
}

int rxpc_coredevice_rotate(rxpc_conn *c, const char *orientation, int timeout_ms, rxpc_value **out_reply) {
  if (out_reply) *out_reply = NULL;
  if (!c || !c->connected) {
    set_err(c, "not connected", "");
    return -1;
  }

  rxpc_value *rot = rxpc_dict();
  rxpc_dict_set(rot, "_0", rxpc_string(orientation));

  rxpc_value *payload = rxpc_dict();
  rxpc_dict_set(payload, "rotate", rot);

  rxpc_value *m = rxpc_dict();
  rxpc_dict_set(m, "featureIdentifier",
                rxpc_string("com.apple.coredevice.feature.remote.devicecontrol.orientation"));
  rxpc_dict_set(m, "messageType", rxpc_string("OrientationRequest"));
  rxpc_dict_set(m, "payload", payload);

  int rc = rxpc_send(c, RXPC_FLAG_ALWAYS_SET | RXPC_FLAG_DATA_PRESENT | RXPC_FLAG_WANTING_REPLY, 1, m);
  rxpc_value_free(m);
  if (rc != 0) return -1;

  for (;;) {
    rxpc_value *body = rxpc_recv(c, timeout_ms, NULL, NULL);
    if (!body) return -1;
    if (body->type != RXPC_DICT || body->dict.count == 0) {
      rxpc_value_free(body);
      continue;
    }
    if (out_reply) *out_reply = body;
    else rxpc_value_free(body);

    return 0;
  }
}

static void dump_indent(FILE *out, int depth) {
  for (int i = 0; i < depth; i++) fputs("  ", out);
}

static void dump_value(FILE *out, const rxpc_value *v, int depth) {
  if (!v) {
    fputs("<null>\n", out);
    return;
  }

  switch (v->type) {
    case RXPC_NULL:
      fputs("null\n", out);
      break;
    case RXPC_BOOL:
      fprintf(out, "%s\n", v->b ? "true" : "false");
      break;
    case RXPC_INT:
      fprintf(out, "%lld\n", (long long)v->i);
      break;
    case RXPC_UINT:
      fprintf(out, "%llu\n", (unsigned long long)v->u);
      break;
    case RXPC_DOUBLE:
      fprintf(out, "%g\n", v->d);
      break;
    case RXPC_STRING:
      fprintf(out, "\"%s\"\n", v->str);
      break;
    case RXPC_DATA: {
      fputs("<data ", out);
      for (size_t i = 0; i < v->data.len; i++) fprintf(out, "%02x", v->data.bytes[i]);
      fprintf(out, ">\n");

      break;
    }
    case RXPC_UUID: {
      fputs("<uuid ", out);
      for (size_t i = 0; i < 16; i += 2) fprintf(out, "%02x%02x", v->data.bytes[i], v->data.bytes[i + 1]);
      fputs(">\n", out);

      break;
    }
    case RXPC_FILE_TRANSFER:
      fprintf(out, "<fileTransfer %zu bytes>\n", v->raw.len);
      break;
    case RXPC_ARRAY:
      fputs("[\n", out);
      for (size_t i = 0; i < v->array.count; i++) {
        dump_indent(out, depth + 1);
        dump_value(out, v->array.items[i], depth + 1);
      }

      dump_indent(out, depth);
      fputs("]\n", out);

      break;
    case RXPC_DICT:
      fputs("{\n", out);
      for (size_t i = 0; i < v->dict.count; i++) {
        dump_indent(out, depth + 1);
        fprintf(out, "%s = ", v->dict.keys[i]);
        dump_value(out, v->dict.vals[i], depth + 1);
      }

      dump_indent(out, depth);
      fputs("}\n", out);
      
      break;
  }
}

void rxpc_value_dump(FILE *out, const rxpc_value *v) { dump_value(out, v, 0); }
