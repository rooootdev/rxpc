//
//  rxpc.h
//  rxpc
//
//  Created by ruter on 13.09.26.
//

#ifndef RXPC_H
#define RXPC_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  RXPC_NULL = 0x00001000,
  RXPC_BOOL = 0x00002000,
  RXPC_INT = 0x00003000,
  RXPC_UINT = 0x00004000,
  RXPC_DOUBLE = 0x00005000,
  RXPC_DATA = 0x00008000,
  RXPC_STRING = 0x00009000,
  RXPC_UUID = 0x0000a000,
  RXPC_ARRAY = 0x0000e000,
  RXPC_DICT = 0x0000f000,
  RXPC_FILE_TRANSFER = 0x0001a000,
} rxpc_type;

typedef struct rxpc_value {
  rxpc_type type;
  union {
    int b;
    int64_t i;
    uint64_t u;

    double d;
    struct {
      uint8_t *bytes;
      size_t len;
    } data;

    char *str;
    struct {
      struct rxpc_value **items;
      size_t count;
    } array;

    struct {
      char **keys;
      struct rxpc_value **vals;
      size_t count;
    } dict;

    struct {
      uint8_t *bytes;
      size_t len;
    } raw;
  };
} rxpc_value;

rxpc_value *rxpc_null(void);
rxpc_value *rxpc_bool(int b);
rxpc_value *rxpc_int(int64_t v);
rxpc_value *rxpc_uint(uint64_t v);
rxpc_value *rxpc_double(double v);
rxpc_value *rxpc_string(const char *s);
rxpc_value *rxpc_data(const void *bytes, size_t len);
rxpc_value *rxpc_uuid(const void *bytes16);
rxpc_value *rxpc_array(void);
rxpc_value *rxpc_dict(void);

void rxpc_array_append(rxpc_value *arr, rxpc_value *item);
int rxpc_dict_set(rxpc_value *dict, const char *key, rxpc_value *val);

const rxpc_value *rxpc_dict_get(const rxpc_value *dict, const char *key);
rxpc_value *rxpc_value_clone(const rxpc_value *v);

void rxpc_value_free(rxpc_value *v);
void rxpc_value_dump(FILE *out, const rxpc_value *v);

typedef struct rxpc_conn rxpc_conn;

#define RXPC_FLAG_ALWAYS_SET 0x00000001u
#define RXPC_FLAG_DATA_PRESENT 0x00000100u
#define RXPC_FLAG_WANTING_REPLY 0x00010000u
#define RXPC_FLAG_INIT_HANDSHAKE 0x00400000u

rxpc_conn *rxpc_connect(const char *host, const char *port, int timeout_ms);

void rxpc_close(rxpc_conn *c);
int rxpc_connected(const rxpc_conn *c);
const char *rxpc_error(const rxpc_conn *c);
rxpc_value *rxpc_recv(rxpc_conn *c, int timeout_ms, uint32_t *out_flags, uint64_t *out_id);
int rxpc_send(rxpc_conn *c, uint32_t flags, uint64_t id, const rxpc_value *body);

typedef struct rxpc_service {
  char *name;
  char *port;
} rxpc_service;

int rxpc_discover_services(rxpc_conn *c, int timeout_ms, rxpc_value **out_peer_info, rxpc_service **out_services, size_t *out_count);
rxpc_service *rxpc_parse_services(const rxpc_value *peer_info, size_t *out_count);

void rxpc_services_free(rxpc_service *services, size_t count);
const char *rxpc_service_port(const rxpc_service *services, size_t count, const char *name);

rxpc_value *rxpc_coredevice_envelope(const char *feature, const rxpc_value *input);
int rxpc_coredevice_invoke(rxpc_conn *c, uint64_t id, const char *feature, const rxpc_value *input, int timeout_ms, rxpc_value **out_reply);

/* High-level helper: ask the devicecontrol service to rotate the display.
 * Sends the OrientationRequest and returns the first meaningful reply. */
int rxpc_coredevice_rotate(rxpc_conn *c, const char *orientation, int timeout_ms, rxpc_value **out_reply);

#ifdef __cplusplus
}
#endif

#endif /* RXPC_H */
