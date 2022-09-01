// TODO: Consider renaming this, since "dispatcher" is overloaded
// (this is not a process dispatcher, but event dispatcher)

#ifndef _AOS_RPC_SERVERS_H
#define _AOS_RPC_SERVERS_H

#include <errors/errno.h>
#include <aos/aos_rpc.h>

errval_t init_eventhandler(void *server_state, RpcMethod method,
                           RpcRequestWrap *request_wrap, struct capref request_cap,
                           RpcResponseWrap *response_wrap, struct capref *response_cap);
errval_t mem_eventhandler(void *server_state, RpcMethod method,
                          RpcRequestWrap *request_wrap, struct capref request_cap,
                          RpcResponseWrap *response_wrap, struct capref *response_cap);

struct waitset *mem_server_get_ws(void);

#endif  // _AOS_RPC_SERVERS_H