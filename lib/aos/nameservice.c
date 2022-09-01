/**
 * \file nameservice.h
 * \brief
 */
#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/waitset.h>
#include <aos/nameserver.h>
#include <aos/aos_rpc.h>
#include <aos/macros.h>
#include <collections/list.h>
#include <spawn/spawn.h>
#include <aos/spawnstore.h>

// Max number of services that can be registered in a domain.
#define MAX_SERVICES 10

struct service_entry {
    const char *name;
    serviceid_t sid;
    aos_rpc_eventhandler_t *recv_handler_proto;
    nameservice_receive_handler_t *recv_handler;
    // list of (struct aos_rpc *)
    collections_listnode *connections;
    bool is_deregistered;

    void *st;
};

struct nameservice_chan {
    struct aos_rpc rpc;
    serviceid_t server_sid;
};

size_t service_entries_next_idx = 0;
struct service_entry service_entries[MAX_SERVICES] = { 0 };
struct aos_rpc domain_server;

// Function declarations.
static errval_t service_eventhandler(void *server_state, RpcMethod method,
                                     RpcRequestWrap *req, struct capref request_cap,
                                     RpcResponseWrap *response_wrap,
                                     struct capref *response_cap);

static errval_t handle_service_connect(struct service_entry *service,
                                       ServiceConnectRequest *req,
                                       struct capref *response_cap)
{
    errval_t err;
    struct aos_rpc *rpc = malloc(sizeof(struct aos_rpc));
    if (collections_list_insert(service->connections, rpc)) {
        return LIB_ERR_COLLECTIONS_LIST_INSERT;
    }

    struct waitset *ws = get_default_waitset();

    switch (req->type) {
    case SERVICE_CONNECT_REQUEST__TYPE__LMP: {
        err = aos_rpc_init_lmp_server(rpc, ws, service_eventhandler, service);
        RETURN_IF_ERR(err);
        *response_cap = rpc->chan.lmp.local_cap;
    } break;
    case SERVICE_CONNECT_REQUEST__TYPE__UMP: {
        uint8_t *urpc;
        struct capref urpc_frame;
        struct frame_identity urpc_frame_id;
        err = ump_create_frame((void **)&urpc, BASE_PAGE_SIZE, &urpc_frame_id,
                               &urpc_frame);
        RETURN_IF_ERR(err);
        *response_cap = urpc_frame;
        err = aos_rpc_init_ump_server(rpc, urpc, urpc_frame_id.bytes, ws,
                                      service_eventhandler, service);
        RETURN_IF_ERR(err);
    } break;
    default:
        DEBUG_PRINTF("Unknown connection type: %d\n", req->type);
        return AOS_ERR_RPC_UNKOWN_CHANNEL_TYPE;
    }

    return SYS_ERR_OK;
}

// Handling of all services passes through this eventhandler.
static errval_t service_eventhandler(void *server_state, RpcMethod method,
                                     RpcRequestWrap *req, struct capref request_cap,
                                     RpcResponseWrap *response_wrap,
                                     struct capref *response_cap)
{
    errval_t err = SYS_ERR_OK;

    struct service_entry *service = (struct service_entry *)server_state;

    switch (method) {
    case RPC_METHOD__SERVICE_CONNECT:
        err = handle_service_connect(service, req->service_connect, response_cap);
        break;

    case RPC_METHOD__SERVICE_BYTES: {
        assert(service->recv_handler != NULL);
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_SERVICE_BYTES);
        ServiceBytesResponse *sb_res = malloc(sizeof(ServiceBytesResponse));
        service_bytes_response__init(sb_res);

        service->recv_handler(service->st, req->service_bytes->raw_bytes.data,
                              req->service_bytes->raw_bytes.len,
                              (void **)&sb_res->raw_bytes.data, &sb_res->raw_bytes.len,
                              request_cap, response_cap);

        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_SERVICE_BYTES;
        response_wrap->service_bytes = sb_res;
    } break;

    default:
        assert(service->recv_handler_proto != NULL);
        err = service->recv_handler_proto(service->st, method, req, request_cap,
                                          response_wrap, response_cap);
    }

    return err;
}

static errval_t handle_route(RouteRequest *req, struct capref request_cap,
                             RouteResponse **route_response, struct capref *response_cap)
{
    local_serviceid_t local_sid = sid_get_local_sid(req->destination_sid);
    assert(local_sid < service_entries_next_idx);

    // RouteResponse->inner_response
    RpcResponseWrap *inner_res = malloc(sizeof(RpcResponseWrap));
    rpc_response_wrap__init(inner_res);
    errval_t err = service_eventhandler(&service_entries[local_sid], req->method,
                                        req->inner_request, request_cap, inner_res,
                                        response_cap);
    inner_res->err = err;

    // RouteResponse
    *route_response = malloc(sizeof(RouteResponse));
    route_response__init(*route_response);
    (*route_response)->inner_response = inner_res;
    (*route_response)->method = req->method;

    return SYS_ERR_OK;
}

static errval_t domain_eventhandler(void *server_state, RpcMethod method,
                                    RpcRequestWrap *req, struct capref request_cap,
                                    RpcResponseWrap *response_wrap,
                                    struct capref *response_cap)
{
    errval_t err = SYS_ERR_OK;
    switch (method) {
    case RPC_METHOD__ROUTE:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_ROUTE);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_ROUTE;
        err = handle_route(req->route, request_cap, &response_wrap->route, response_cap);
        break;

    default:
        DEBUG_PRINTF("Unknown RPC_METHOD: %d\n", method);
    }

    return err;
}

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
                         struct capref rx_cap)
{
    ServiceBytesRequest req = SERVICE_BYTES_REQUEST__INIT;
    req.raw_bytes.data = (uint8_t *)message;
    req.raw_bytes.len = bytes;
    REQUEST_WRAP(req_wrap, service_bytes, SERVICE_BYTES, &req);
    RpcResponseWrap *res = NULL;
    struct capref response_cap = NULL_CAP;
    errval_t err = nameservice_rpc_proto(chan, RPC_METHOD__SERVICE_BYTES, &req_wrap,
                                         tx_cap, &res, &response_cap);
    RETURN_IF_ERR(err);

    if (!capref_is_null(response_cap) && !capref_is_null(rx_cap)) {
        cap_copy(rx_cap, response_cap);
    }

    // Take the bytes out.
    assert(res->data_case == RPC_RESPONSE_WRAP__DATA_SERVICE_BYTES);
    *response = res->service_bytes->raw_bytes.data;
    *response_bytes = res->service_bytes->raw_bytes.len;

    // Destroy the wrapping.
    res->service_bytes->raw_bytes.data = NULL;
    res->service_bytes->raw_bytes.len = 0;
    RESPONSE_WRAP_DESTROY(res);

    return SYS_ERR_OK;
}

errval_t nameservice_rpc_proto(nameservice_chan_t chan_ptr, RpcMethod method,
                               RpcRequestWrap *request, struct capref request_cap,
                               RpcResponseWrap **response, struct capref *response_cap)
{
    struct nameservice_chan *chan = (struct nameservice_chan *)chan_ptr;
    bool is_same_core = (sid_get_coreid(chan->server_sid) == disp_get_core_id());
    // Cross-core RPC which is either sending or expecting capability, route over init.
    if (!is_same_core && (!capref_is_null(request_cap) || response_cap != NULL)) {
        RouteRequest route_req = ROUTE_REQUEST__INIT;
        route_req.destination_sid = chan->server_sid;
        route_req.inner_request = request;
        route_req.method = method;
        REQUEST_WRAP(route_req_wrap, route, ROUTE, &route_req);

        RpcResponseWrap *route_res = NULL;
        errval_t err = aos_rpc_call(aos_rpc_get_init_channel(), RPC_METHOD__ROUTE,
                                    &route_req_wrap, request_cap, &route_res,
                                    response_cap);
        RETURN_IF_ERR(err);
        assert(route_res->data_case == RPC_RESPONSE_WRAP__DATA_ROUTE);
        assert(route_res->route->method == method);
        // Take out response.
        *response = route_res->route->inner_response;
        route_res->route->inner_response = NULL;
        RESPONSE_WRAP_DESTROY(route_res);

        return (*response)->err;
    } else {
        return aos_rpc_call(&chan->rpc, method, request, request_cap, response,
                            response_cap);
    }
}

static errval_t nameservice_register_super(const char *name,
                                           aos_rpc_eventhandler_t recv_handler_proto,
                                           nameservice_receive_handler_t recv_handler,
                                           void *st)
{
    assert(service_entries_next_idx < MAX_SERVICES);

    errval_t err;
    local_serviceid_t cur_local_sid = service_entries_next_idx++;

    if (cur_local_sid == 0) {
        // Establish init -> child channel so that clients can connect.
        aos_rpc_init_lmp_server(&domain_server, get_default_waitset(),
                                &domain_eventhandler, NULL);

        // A thread to handle domain_server is spawned. This is VERY HIDDEN and maybe
        // should be refactored to always be spawned and not just lazily?
        run_dispatcher_threads(1, get_default_waitset());
        err = aos_rpc_call(aos_rpc_get_init_channel(),
                           RPC_METHOD__INIT_ESTABLISH_DOMAIN_SERVER, NULL,
                           domain_server.chan.lmp.local_cap, NULL, NULL);
        PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);
    }

    struct service_entry *entry = &service_entries[cur_local_sid];
    entry->name = strdup(name);
    entry->recv_handler_proto = recv_handler_proto;
    entry->recv_handler = recv_handler;
    entry->is_deregistered = false;
    entry->st = st;
    collections_list_create(&entry->connections, free);
    entry->sid = sid_from(disp_get_domain_id(), cur_local_sid);

    if (strcmp(name, "nameserver") == 0) {
        assert(entry->sid == NAMESERVER_SERVICEID);
        // no-op.
    } else {
        NsRegisterRequest req = NS_REGISTER_REQUEST__INIT;
        ServiceInfo service = SERVICE_INFO__INIT;
        service.name = (char *)name;
        service.sid = entry->sid;
        req.service = &service;
        REQUEST_WRAP(req_wrap, ns_register, NS_REGISTER, &req);
        err = nameservice_rpc_proto(get_nameserver_chan(), RPC_METHOD__NS_REGISTER,
                                    &req_wrap, NULL_CAP, NULL, NULL);
        RETURN_IF_ERR(err);
    }

    return SYS_ERR_OK;
}

errval_t nameservice_register_proto(const char *name,
                                    aos_rpc_eventhandler_t recv_handler_proto, void *st)
{
    return nameservice_register_super(name, recv_handler_proto, NULL, st);
}
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
                              nameservice_receive_handler_t recv_handler, void *st)
{
    return nameservice_register_super(name, NULL, recv_handler, st);
}


/**
 * @brief deregisters the service 'name'
 *
 * @param the name to deregister
 *
 * @return error value
 */
errval_t nameservice_deregister(const char *name)
{
    struct service_entry *entry = NULL;
    for (size_t i = 0; i < service_entries_next_idx; ++i) {
        if (strcmp(name, service_entries[i].name) == 0) {
            entry = &service_entries[i];
        }
    }

    if (entry == NULL) {
        return LIB_ERR_NAMESERVICE_INVALID_NAME;
    }

    NsDeregisterRequest req = NS_DEREGISTER_REQUEST__INIT;
    req.name = (char *)name;
    REQUEST_WRAP(req_wrap, ns_deregister, NS_DEREGISTER, &req);
    errval_t err = nameservice_rpc_proto(get_nameserver_chan(), RPC_METHOD__NS_DEREGISTER,
                                         &req_wrap, NULL_CAP, NULL, NULL);
    RETURN_IF_ERR(err);

    entry->is_deregistered = true;

    return SYS_ERR_OK;
}

static errval_t nameservice_connect_explicit_route(struct aos_rpc *route_rpc,
                                                   serviceid_t serviceid,
                                                   nameservice_chan_t *chan_ret)
{
    errval_t err;

    // Get server endpoint.
    ServiceConnectRequest req = SERVICE_CONNECT_REQUEST__INIT;

    if (sid_get_coreid(serviceid) == disp_get_core_id()) {
        req.type = SERVICE_CONNECT_REQUEST__TYPE__LMP;
    } else {
        req.type = SERVICE_CONNECT_REQUEST__TYPE__UMP;
    }

    REQUEST_WRAP(req_wrap_inner, service_connect, SERVICE_CONNECT, &req);
    RouteRequest req_outer = ROUTE_REQUEST__INIT;
    req_outer.destination_sid = serviceid;
    req_outer.method = RPC_METHOD__SERVICE_CONNECT;
    req_outer.inner_request = &req_wrap_inner;
    REQUEST_WRAP(req_wrap_outer, route, ROUTE, &req_outer);

    struct capref server_ep;
    err = aos_rpc_call(route_rpc, RPC_METHOD__ROUTE, &req_wrap_outer, NULL_CAP, NULL,
                       &server_ep);
    PUSH_RETURN_IF_ERR(err, AOS_ERR_RPC_CALL);

    // Malloc channel and establish connection.
    struct nameservice_chan *chan = malloc(sizeof(struct nameservice_chan));
    chan->server_sid = serviceid;

    if (req.type == SERVICE_CONNECT_REQUEST__TYPE__LMP) {
        err = aos_rpc_establish_lmp_client(&chan->rpc, server_ep);
        GOTO_IF_ERR(err, cleanup);
    } else {
        struct frame_identity id;
        err = frame_identify(server_ep, &id);
        PUSH_GOTO_IF_ERR(err, LIB_ERR_FRAME_IDENTIFY, cleanup);

        uint8_t *urpc;
        err = paging_map_frame_attr(get_current_paging_state(), (void **)&urpc, id.bytes,
                                    server_ep, VREGION_FLAGS_READ_WRITE);
        PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_MAP, cleanup);
        aos_rpc_init_ump_client(&chan->rpc, urpc, id.bytes);
    }
    *chan_ret = chan;

    return SYS_ERR_OK;

cleanup:
    free(chan);
    return err;
}

errval_t nameservice_connect(serviceid_t serviceid, nameservice_chan_t *chan_ret)
{
    // Here we essentially do routing.
    struct aos_rpc *route_rpc = NULL;
    // in init
    if (did_get_local_did(disp_get_domain_id()) == 0) {
        // local core
        if (disp_get_core_id() == sid_get_coreid(serviceid)) {
            struct spawninfo *si = NULL;
            if (!spawnstore_get(get_default_spawnstore(), sid_get_domainid(serviceid),
                                &si, NULL)) {
                return SPAWN_ERR_SPAWNSTORE_GET;
            }
            route_rpc = &si->domain_client_rpc;
        } else {  // remote core
            route_rpc = get_core_client_rpc(sid_get_coreid(serviceid));
        }
    } else {
        route_rpc = aos_rpc_get_init_channel();
    }
    assert(route_rpc != NULL);

    return nameservice_connect_explicit_route(route_rpc, serviceid, chan_ret);
}

errval_t nameservice_lookup(const char *name, nameservice_chan_t *chan)
{
    errval_t err = SYS_ERR_OK;
    while (true) {
        err = nameservice_try_lookup(name, chan);
        if (err_is_ok(err) || err_no(err) != LIB_ERR_NAMESERVICE_UNKNOWN_NAME) {
            return err;
        }
    }
}

errval_t nameservice_try_lookup(const char *name, nameservice_chan_t *chan)
{
    errval_t err;

    NsLookupRequest req = NS_LOOKUP_REQUEST__INIT;
    req.name = (char *)name;
    REQUEST_WRAP(req_wrap, ns_lookup, NS_LOOKUP, &req);
    RpcResponseWrap *res_wrap;
    err = nameservice_rpc_proto(get_nameserver_chan(), RPC_METHOD__NS_LOOKUP, &req_wrap,
                                NULL_CAP, &res_wrap, NULL);
    if (err_no(err_pop(err)) == LIB_ERR_NAMESERVICE_UNKNOWN_NAME) {
        return LIB_ERR_NAMESERVICE_UNKNOWN_NAME;
    }
    RETURN_IF_ERR(err);

    assert(res_wrap->data_case == RPC_RESPONSE_WRAP__DATA_NS_LOOKUP);
    serviceid_t sid = res_wrap->ns_lookup->sid;
    err = nameservice_connect(sid, chan);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

void free_service_info_arr(ServiceInfo **services, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        service_info__free_unpacked(services[i], NULL);
    }
    free(services);
}

errval_t nameservice_enumerate(char *query, size_t *num, char ***result)
{
    assert(result != NULL);

    ServiceInfo **services = NULL;
    errval_t err = nameservice_enumerate_services(query, num, &services);
    RETURN_IF_ERR(err);

    char **arr = malloc(*num * sizeof(char *));
    for (size_t i = 0; i < *num; ++i) {
        arr[i] = strdup(services[i]->name);
    }
    *result = arr;
    free_service_info_arr(services, *num);

    return SYS_ERR_OK;
}

/**
 * @brief enumerates all entries that match an query (prefix match)
 *
 * @param query     the query
 * @param num 		number of entries in the result array
 * @param result	an array of entries
 */
errval_t nameservice_enumerate_services(char *query, size_t *num, ServiceInfo ***result)
{
    NsEnumerateRequest req = NS_ENUMERATE_REQUEST__INIT;
    req.prefix = query;
    REQUEST_WRAP(req_wrap, ns_enumerate, NS_ENUMERATE, &req);
    RpcResponseWrap *res_wrap;
    errval_t err = nameservice_rpc_proto(get_nameserver_chan(), RPC_METHOD__NS_ENUMERATE,
                                         &req_wrap, NULL_CAP, &res_wrap, NULL);
    RETURN_IF_ERR(err);

    assert(res_wrap->data_case == RPC_RESPONSE_WRAP__DATA_NS_ENUMERATE);
    // Take out the result.
    *result = res_wrap->ns_enumerate->services;
    *num = res_wrap->ns_enumerate->n_services;
    res_wrap->ns_enumerate->services = NULL;
    res_wrap->ns_enumerate->n_services = 0;
    RESPONSE_WRAP_DESTROY(res_wrap);

    return SYS_ERR_OK;
}
