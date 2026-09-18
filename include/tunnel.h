//
//  tunnel.h
//  rxpc
//
//  Created by ruter on 14.09.26.
//

#ifndef RXPC_TUNNEL_H
#define RXPC_TUNNEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rxpc_tunnel rxpc_tunnel;

rxpc_tunnel *rxpc_tunnel_open(const char *udid, const char **out_address, uint16_t *out_rsd_port, char *err, size_t errsz);
void rxpc_tunnel_close(rxpc_tunnel *t);

const char *rxpc_tunnel_error(const rxpc_tunnel *t);
const char *rxpc_tunnel_interface(const rxpc_tunnel *t);

#ifdef __cplusplus
}
#endif

#endif /* RXPC_TUNNEL_H */
