#include <stdio.h>
#include <aos/aos.h>
#include <aos/types.h>
#include <aos/nameserver.h>
#include <aos/macros.h>
#include <collections/list.h>

#define NAMESERVER "nameserver"

struct ns_state {
    // list of (ServiceInfo*)
    collections_listnode *services;
    struct thread_mutex mutex;
};

static ServiceInfo *service_info_create(const char *name, serviceid_t sid)
{
    ServiceInfo *ret = malloc(sizeof(ServiceInfo));
    service_info__init(ret);
    ret->name = strdup(name);
    ret->sid = sid;
    return ret;
}

static int32_t name_matches_fully(void *data, void *arg)
{
    ServiceInfo *cur = (ServiceInfo *)data;
    const char *query_name = (const char *)arg;
    return !strcmp(cur->name, query_name);
}

static int32_t name_matches_prefix(void *data, void *arg)
{
    ServiceInfo *cur = (ServiceInfo *)data;
    const char *prefix = (const char *)arg;
    return strncmp(cur->name, prefix, strlen(prefix)) == 0;
}

static errval_t handle_ns_register(struct ns_state *ns_state, NsRegisterRequest *req)
{
    thread_mutex_lock(&ns_state->mutex);
    // Check if entry already exists.
    struct name_sid *existing_entry = (struct name_sid *)collections_list_find_if(
        ns_state->services, name_matches_fully, req->service->name);
    uint32_t insertion_status;
    if (existing_entry == NULL) {
        insertion_status = collections_list_insert(ns_state->services, req->service);
        req->service = NULL;
    }
    thread_mutex_unlock(&ns_state->mutex);

    if (existing_entry != NULL) {
        return LIB_ERR_NAMESERVICE_NAME_ALREADY_REGISTERED;
    }

    if (insertion_status != 0) {
        return LIB_ERR_COLLECTIONS_LIST_INSERT;
    }

    return SYS_ERR_OK;
}

static errval_t handle_ns_lookup(struct ns_state *ns_state, NsLookupRequest *req,
                                 NsLookupResponse **res)
{
    *res = malloc(sizeof(NsLookupResponse));
    ns_lookup_response__init(*res);

    thread_mutex_lock(&ns_state->mutex);
    ServiceInfo *entry = (ServiceInfo *)collections_list_find_if(
        ns_state->services, name_matches_fully, req->name);
    thread_mutex_unlock(&ns_state->mutex);

    if (entry == NULL) {
        return LIB_ERR_NAMESERVICE_UNKNOWN_NAME;
    }

    (*res)->sid = entry->sid;

    return SYS_ERR_OK;
}

static errval_t handle_ns_enumerate(struct ns_state *ns_state, NsEnumerateRequest *req,
                                    NsEnumerateResponse **res)
{
    *res = malloc(sizeof(NsEnumerateResponse));
    ns_enumerate_response__init(*res);

    thread_mutex_lock(&ns_state->mutex);

    ServiceInfo **match_arr = malloc(sizeof(ServiceInfo *)
                                     * collections_list_size(ns_state->services));
    assert(collections_list_traverse_start(ns_state->services) == 1);
    ServiceInfo *entry = (ServiceInfo *)collections_list_traverse_next(ns_state->services);
    size_t match_arr_next_i = 0;
    while (entry != NULL) {
        if (name_matches_prefix(entry, req->prefix)) {
            match_arr[match_arr_next_i++] = service_info_create(entry->name, entry->sid);
        }
        entry = (ServiceInfo *)collections_list_traverse_next(ns_state->services);
    }
    assert(collections_list_traverse_end(ns_state->services) == 1);

    thread_mutex_unlock(&ns_state->mutex);

    (*res)->services = match_arr;
    (*res)->n_services = match_arr_next_i;

    return SYS_ERR_OK;
}

static errval_t handle_ns_deregister(struct ns_state *ns_state, NsDeregisterRequest *req)
{
    thread_mutex_lock(&ns_state->mutex);
    ServiceInfo *entry = (ServiceInfo *)collections_list_remove_if(
        ns_state->services, name_matches_fully, req->name);
    thread_mutex_unlock(&ns_state->mutex);

    if (entry == NULL) {
        return LIB_ERR_NAMESERVICE_INVALID_NAME;
    }

    return SYS_ERR_OK;
}

static errval_t server_handler(void *server_state, RpcMethod method,
                               RpcRequestWrap *request_wrap, struct capref request_cap,
                               RpcResponseWrap *response_wrap, struct capref *response_cap)
{
    struct ns_state *ns_state = (struct ns_state *)server_state;
    errval_t err = SYS_ERR_OK;

    switch (method) {
    case RPC_METHOD__NS_REGISTER:
        assert(request_wrap->data_case == RPC_REQUEST_WRAP__DATA_NS_REGISTER);
        err = handle_ns_register(ns_state, request_wrap->ns_register);
        break;

    case RPC_METHOD__NS_LOOKUP:
        assert(request_wrap->data_case == RPC_REQUEST_WRAP__DATA_NS_LOOKUP);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_NS_LOOKUP;
        err = handle_ns_lookup(ns_state, request_wrap->ns_lookup,
                               &response_wrap->ns_lookup);
        break;

    case RPC_METHOD__NS_ENUMERATE:
        assert(request_wrap->data_case == RPC_REQUEST_WRAP__DATA_NS_ENUMERATE);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_NS_ENUMERATE;
        err = handle_ns_enumerate(ns_state, request_wrap->ns_enumerate,
                                  &response_wrap->ns_enumerate);
        break;

    case RPC_METHOD__NS_DEREGISTER:
        assert(request_wrap->data_case == RPC_REQUEST_WRAP__DATA_NS_DEREGISTER);
        err = handle_ns_deregister(ns_state, request_wrap->ns_deregister);
        break;

    default:
        DEBUG_PRINTF("nameserver unsupported method %d\n", method);
    }
    return err;
}

int main(int argc, char *argv[])
{
    struct ns_state state;
    collections_list_create(&state.services, free);
    thread_mutex_init(&state.mutex);

    collections_list_insert(state.services,
                            service_info_create(NAMESERVER, NAMESERVER_SERVICEID));
    errval_t err = nameservice_register_proto(NAMESERVER, server_handler, &state);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "registering nameserver failed");
    }

    // Inform init.
    err = aos_rpc_call(aos_rpc_get_init_channel(), RPC_METHOD__INIT_NAMESERVER_STARTED,
                       NULL, NULL_CAP, NULL, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "informing init about nameserver start failed.");
    }

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }
    return EXIT_SUCCESS;
}
