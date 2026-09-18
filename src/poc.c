//
//  poc.c
//  rxpc
//
//  Created by ruter on 15.09.26.
//

#include "rxpc.h"
#include "tunnel.h"

#include <stdio.h>
#include <string.h>

#define DEVICECONTROL "com.apple.coredevice.devicecontrol"

static int usage(const char *argv0, const char *why) {
  if (why) fprintf(stderr, "%s\n", why);
  fprintf(stderr, "usage: %s [--udid <udid>] [--rotate left|right] [<host> <port>]\n", argv0);
  return 2;
}

static void list_services(rxpc_value *peer_info, rxpc_service *services, size_t count) {
  // printf("peer info:\n");
  // rxpc_value_dump(stdout, peer_info);
  printf("%zu service(s):\n", count);
  for (size_t i = 0; i < count; i++) printf(" %-60s -> %s\n", services[i].name, services[i].port ? services[i].port : "?");
}

static int discover_and_rotate(const char *host, const char *port, const char *rotate) {
  rxpc_conn *c = rxpc_connect(host, port, 8000);
  if (!c) {
    fprintf(stderr, "connect %s:%s failed: %s\n", host, port, rxpc_error(NULL));
    return 1;
  }

  rxpc_value *peer_info = NULL;
  rxpc_service *services = NULL;

  size_t count = 0;
  if (rxpc_discover_services(c, 90000, &peer_info, &services, &count) != 0) {
    fprintf(stderr, "discovery failed: %s\n", rxpc_error(c));
    rxpc_close(c);
    return 1;
  }

  list_services(peer_info, services, count);

  int rc = 0;
  if (rotate) {
    const char *dc_port = rxpc_service_port(services, count, DEVICECONTROL);
    if (!dc_port) {
      fprintf(stderr, "device does not expose %s\n", DEVICECONTROL);
      rc = 1;
    } else {
      rxpc_conn *dc = rxpc_connect(host, dc_port, 5000);
      if (!dc) {
        fprintf(stderr, "connect to devicecontrol (%s) failed: %s\n", dc_port, rxpc_error(NULL));
        rc = 1;
      } else {
        rxpc_value *reply = NULL;
        printf("rotating %s...\n", rotate);

        if (rxpc_coredevice_rotate(dc, rotate, 20000, &reply) != 0) {
          fprintf(stderr, "rotate failed: %s\n", rxpc_error(dc));
          rc = 1;
        } else {
          printf("reply:\n");
          rxpc_value_dump(stdout, reply);
          rxpc_value_free(reply);
        }

        rxpc_close(dc);
      }
    }
  }

  rxpc_close(c);
  rxpc_services_free(services, count);
  rxpc_value_free(peer_info);

  return rc;
}

int main(int argc, char **argv) {
  const char *udid = NULL, *rotate = NULL, *host = NULL, *port = NULL;

  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    if (strcmp(a, "--udid") == 0 && i + 1 < argc) udid = argv[++i];
    else if (strcmp(a, "--rotate") == 0 && i + 1 < argc) rotate = argv[++i];
    else if (a[0] == '-') return usage(argv[0], NULL);
    else if (!host) host = a;
    else if (!port) port = a;
    else return usage(argv[0], NULL);
  }

  if (rotate && strcmp(rotate, "left") && strcmp(rotate, "right")) return usage(argv[0], "--rotate must be 'left' or 'right'");
  if (host && !port) return usage(argv[0], "both <host> and <port> are required");

  char rsd_host[256], rsd_port[16];
  rxpc_tunnel *tun = NULL;

  if (host) {
    snprintf(rsd_host, sizeof(rsd_host), "%s", host);
    snprintf(rsd_port, sizeof(rsd_port), "%s", port);
  } else {
    char terr[256];
    const char *addr = NULL;
    uint16_t rport = 0;
    tun = rxpc_tunnel_open(udid, &addr, &rport, terr, sizeof(terr));
    if (!tun) {
      fprintf(stderr, "tunnel open failed: %s\n", terr);
      return 1;
    }

    snprintf(rsd_host, sizeof(rsd_host), "%s", addr);
    snprintf(rsd_port, sizeof(rsd_port), "%u", (unsigned)rport);
    printf("tunnel -> %s:%s via %s\n", rsd_host, rsd_port, rxpc_tunnel_interface(tun));
  }

  int rc = discover_and_rotate(rsd_host, rsd_port, rotate);
  if (tun) rxpc_tunnel_close(tun);

  return rc;
}