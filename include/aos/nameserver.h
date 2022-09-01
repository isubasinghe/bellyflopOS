/**
 * \file nameservice.h
 * \brief
 */

#ifndef INCLUDE_NAMESERVICE_H_
#define INCLUDE_NAMESERVICE_H_

#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/rpc/rpcs.pb-c.h>

// Forward-declare an opaque struct. This is so that we don't burn ourselves again
// by passing bad pointers as nameservice channels...
struct nameservice_chan;

typedef struct nameservice_chan *nameservice_chan_t;

///< handler which is called when a message is received over the registered channel
typedef void(nameservice_receive_handler_t)(void *st, void *message, size_t bytes,
                                            void **response, size_t *response_bytes,
                                            struct capref tx_cap, struct capref *rx_cap);

errval_t nameservice_rpc_proto(nameservice_chan_t chan, RpcMethod method,
                               RpcRequestWrap *request, struct capref request_cap,
                               RpcResponseWrap **response, struct capref *response_cap);

/**
 * @brief sends a message back to the client who sent us a message
 *
 * @param chan opaque handle of the channel
 * @oaram message pointer to the message
 * @param bytes size of the message in bytes
 * @param response the response message
 * @param response_byts the size of the response
 *
 * @return error value
 */
errval_t nameservice_rpc(nameservice_chan_t chan, void *message, size_t bytes,
                         void **response, size_t *response_bytes, struct capref tx_cap,
                         struct capref rx_cap);

/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler_proto the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register_proto(const char *name,
                                    aos_rpc_eventhandler_t recv_handler_proto, void *st);

/**
 * @brief registers our selves as 'name'
 *
 * @param name  our name
 * @param recv_handler the message handler for messages received over this service
 * @param st  state passed to the receive handler
 *
 * @return SYS_ERR_OK
 */
errval_t nameservice_register(const char *name,
                              nameservice_receive_handler_t recv_handler, void *st);


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name);


/**
 * @brief Lookup an endpoint and obtain an RPC channel to that. The call blocks until
 * 		  a service with `name` is successfully found.
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_lookup(const char *name, nameservice_chan_t *chan);

/**
 * @brief Try lookup an endpoint and obtain an RPC channel to that. If there's no service
 * 		  with name `name` return LIB_ERR_NAMESERVICE_UNKNOWN_NAME.
 *
 * @param name  name to lookup
 * @param chan  pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_try_lookup(const char *name, nameservice_chan_t *chan);

/**
 * @brief Obtain a channel based on the service id.
 *
 * @param serviceid	sid of the given server
 * @param chan  	pointer to the chan representation to send messages to the service
 *
 * @return  SYS_ERR_OK on success, errval on failure
 */
errval_t nameservice_connect(serviceid_t serviceid, nameservice_chan_t *chan);

/**
 * @brief enumerates all entries that match an query (prefix match)
 *        (the original interface is a bit weird, why not char ***result?)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate(char *query, size_t *num, char ***result);


/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate_services(char *query, size_t *num, ServiceInfo ***result);

void free_service_info_arr(ServiceInfo **services, size_t len);

#endif /* INCLUDE_AOS_AOS_NAMESERVICE_H_ */
