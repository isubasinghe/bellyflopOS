#include <aos/aos_rpc_servers.h>
#include <aos/macros.h>
#include <spawn/spawn.h>
#include <errors/errno.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_lmp.h>
#include <spawn/spawn.h>
#include <aos/spawnstore.h>

#include <grading.h>

static errval_t handle_process_get_name(InitProcessGetNameRequest *req,
                                        InitProcessGetNameResponse **res)
{
    *res = malloc(sizeof(InitProcessGetNameResponse));
    init_process_get_name_response__init(*res);

    coreid_t mycore = disp_get_core_id();
    coreid_t correct_core = did_get_coreid(req->pid);
    if(mycore == correct_core) {
        grading_rpc_handler_process_get_name(req->pid);
    }

    if (correct_core != mycore) {
        char *name;
        errval_t err = aos_rpc_process_get_name(get_core_client_rpc(correct_core),
                                                req->pid, &name);
        if (err_is_fail(err)) {
            return err;
        }
        (*res)->name = name;
        return SYS_ERR_OK;
    } 

    uint32_t ith;
    struct spawninfo *si = NULL;
    if (!spawnstore_get(get_default_spawnstore(), req->pid, &si, &ith)) {
        return SPAWN_ERR_SPAWNSTORE_GET;
    }

    size_t len = strlen(si->binary_name) + 1;
    char *name_copy = malloc(len);
    (*res)->name = strncpy(name_copy, si->binary_name, len);

    return SYS_ERR_OK;
}

__unused static errval_t make_rpcs(bool should_query, domainid_t **ppids, size_t *num_pids)
{
    errval_t err = SYS_ERR_OK;

    int mycore = disp_get_core_id();

    domainid_t **pids = malloc(sizeof(domainid_t *) * NCORES);
    memset(pids, 0, sizeof(domainid_t) * NCORES);


    size_t *len_pids = malloc(sizeof(size_t) * NCORES);
    size_t total_len = 0;

    size_t my_domains = spawnstore_size(get_default_spawnstore());
    total_len += my_domains;
    domainid_t *mypids = malloc(sizeof(domainid_t) * my_domains);

    if (!spawnstore_get_all_pids(get_default_spawnstore(), mypids, my_domains)) {
        free(pids);
        free(len_pids);
        free(mypids);
        return SPAWN_ERR_SPAWNSTORE_GET;
    }

    if (!should_query) {
        grading_rpc_handler_process_get_all_pids();
        *ppids = mypids;
        *num_pids = my_domains;
        return SYS_ERR_OK;
    }

    for (int i = 0; i < NCORES; i++) {
        if (i == mycore) {
            pids[i] = mypids;
            len_pids[i] = my_domains;
            continue;
        }

        InitProcessGetAllPidsRequest req = INIT_PROCESS_GET_ALL_PIDS_REQUEST__INIT;
        req.should_query = false;

        REQUEST_WRAP(req_wrap, init_process_get_all_pids, INIT_PROCESS_GET_ALL_PIDS, &req);

        RpcResponseWrap *res = NULL;
        err = aos_rpc_call(get_core_client_rpc(i), RPC_METHOD__INIT_PROCESS_GET_ALL_PIDS,
                           &req_wrap, NULL_CAP, &res, NULL);

        if (err_is_fail(err)) {
            break;
        }
        pids[i] = res->init_process_get_all_pids->pids;
        len_pids[i] = res->init_process_get_all_pids->n_pids;
        total_len += len_pids[i];

        // Cleanup
        res->init_process_get_all_pids = NULL;
        res->data_case = RPC_RESPONSE_WRAP__DATA__NOT_SET;
        RESPONSE_WRAP_DESTROY(res);
    }

    if (err_is_fail(err)) {
        for (int i = 0; i < NCORES; i++) {
            if (pids[i] != NULL) {
                free(pids[i]);
            }
        }
        free(pids);
        free(len_pids);
        return err;
    }

    domainid_t *all_domain_buffer = malloc(sizeof(domainid_t) * total_len);
    domainid_t *start = all_domain_buffer;

    for (int i = 0; i < NCORES; i++) {
        memcpy(all_domain_buffer, pids[i], sizeof(domainid_t) * len_pids[i]);
        all_domain_buffer += len_pids[i];
    }

    *ppids = start;
    *num_pids = total_len;

    return SYS_ERR_OK;
}

static errval_t handle_get_all_pids(InitProcessGetAllPidsRequest *preq,
                                    InitProcessGetAllPidsResponse **res)
{
    (*res) = malloc(sizeof(InitProcessGetAllPidsResponse));
    init_process_get_all_pids_response__init(*res);
    domainid_t *pids = NULL;
    size_t num_pids = 0;

    errval_t err = make_rpcs(preq->should_query, &pids, &num_pids);
    if (err_is_fail(err)) {
        DEBUG_PRINTF("GOT ERR %lu\n", err);
        (*res)->pids = NULL;
        (*res)->n_pids = 0;
        return err;
    }

    (*res)->pids = pids;
    (*res)->n_pids = num_pids;

    return SYS_ERR_OK;
}

static errval_t handle_process_spawn(InitProcessSpawnRequest *req,
                                     InitProcessSpawnResponse **res)
{
    *res = malloc(sizeof(InitProcessSpawnResponse));
    init_process_spawn_response__init(*res);

    errval_t err;

    coreid_t cur_coreid = disp_get_core_id();
    struct aos_rpc *core_rpc;

    domainid_t pid;
    if (req->core == cur_coreid) {
        grading_rpc_handler_process_spawn(req->cmdline, req->core);
        struct spawninfo *si = malloc(sizeof(struct spawninfo));
        err = spawn_load_by_cmdline(req->cmdline, si, &pid);
        RETURN_IF_ERR(err);
    } else {
        core_rpc = get_core_client_rpc(req->core);
        err = aos_rpc_process_spawn(core_rpc, req->cmdline, req->core, &pid);
        RETURN_IF_ERR(err);
    }

    (*res)->pid = pid;

    return SYS_ERR_OK;
}

static errval_t handle_get_ram_cap(struct spawninfo *si, MemGetRamCapRequest *request,
                                   struct capref request_cap,
                                   MemGetRamCapResponse **response,
                                   struct capref *response_cap)
{
    size_t bytes = request->bytes;
    size_t alignment = request->alignment;
    struct memory_tracking *mt = &si->memory_tracking;

    grading_rpc_handler_ram_cap(bytes, alignment);

    if (bytes > mt->remaining_quota_B) {
        return AOS_ERR_RPC_GET_RAM_CAP_OUT_OF_QUOTA;
    }

    errval_t err = ram_alloc_aligned(response_cap, bytes, alignment);
    RETURN_IF_ERR(err);

    mt->remaining_quota_B -= bytes;
    // No touchy this will be owned by the list now.
    struct capref *cap_we_store = malloc(sizeof(struct capref));
    *cap_we_store = *response_cap;
    if (collections_list_insert(mt->allocated_ram_caps, cap_we_store) != 0) {
        DEBUG_PRINTF("Error inserting cap into list\n");
        // TODO: There's not ram_free() so for now we ignore this error.
    }

    *response = malloc(sizeof(MemGetRamCapResponse));
    mem_get_ram_cap_response__init(*response);
    (*response)->allocated_bytes = bytes;

    return SYS_ERR_OK;
}

static errval_t handle_serial_getchar(InitSerialGetcharResponse **res)
{
    *res = malloc(sizeof(InitSerialGetcharResponse));
    init_serial_getchar_response__init(*res);

    char c;
    errval_t err;
    err = sys_getchar(&c);
    RETURN_IF_ERR(err);

    grading_rpc_handler_serial_getchar();

    (*res)->value = c;

    return SYS_ERR_OK;
}

static errval_t handle_serial_put_char(InitSerialPutcharRequest *req)
{
    char c = (char)req->value;
    grading_rpc_handler_serial_putchar(c);

    errval_t err = sys_print(&c, 1);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

static errval_t handle_serial_put_string(InitSerialPutStringRequest *req)
{
    size_t len = strlen(req->str);
    errval_t err = sys_print(req->str, len);
    RETURN_IF_ERR(err);
    for (size_t i = 0; i < len; i++) {
        grading_rpc_handler_serial_putchar(req->str[i]);
    }

    return SYS_ERR_OK;
}

static errval_t handle_init_establish_domain_server(struct spawninfo *si,
                                                    struct capref remote_ep)
{
    errval_t err = aos_rpc_establish_lmp_client(&si->domain_client_rpc, remote_ep);
    RETURN_IF_ERR(err);
    si->has_domain_client_rpc = true;

    return SYS_ERR_OK;
}

static errval_t handle_init_inform_death(domainid_t did)
{
    spawnstore_remove_by_pid(get_default_spawnstore(), did);
    return SYS_ERR_OK;
}

static errval_t handle_route(RpcRequestWrap *req_wrap, struct capref request_cap,
                             RouteResponse **route_response, struct capref *response_cap)
{
    assert(req_wrap->data_case == RPC_REQUEST_WRAP__DATA_ROUTE);

    RouteRequest *req = req_wrap->route;
    serviceid_t sid = req->destination_sid;
    coreid_t dest_coreid = sid_get_coreid(sid);
    struct aos_rpc *next_hop_rpc = NULL;

    if (dest_coreid == disp_get_core_id()) {
        domainid_t did = sid_get_domainid(sid);
        uint32_t ith;
        struct spawninfo *si = NULL;
        if (!spawnstore_get(get_default_spawnstore(), did, &si, &ith)) {
            return SPAWN_ERR_SPAWNSTORE_GET;
        }

        if (!si->has_domain_client_rpc) {
            return AOS_ERR_RPC_NO_RPC_TO_CHILD;
        }
        next_hop_rpc = &si->domain_client_rpc;
    } else {
        next_hop_rpc = get_core_client_rpc(dest_coreid);
    }

    RpcResponseWrap *res_wrap_call = NULL;
    errval_t err = aos_rpc_call(next_hop_rpc, RPC_METHOD__ROUTE, req_wrap, request_cap,
                                &res_wrap_call, response_cap);
    RETURN_IF_ERR(err);
    assert(res_wrap_call->data_case == RPC_RESPONSE_WRAP__DATA_ROUTE);
    // Take out the response.
    *route_response = res_wrap_call->route;
    res_wrap_call->data_case = RPC_RESPONSE_WRAP__DATA__NOT_SET;
    res_wrap_call->route = NULL;
    RESPONSE_WRAP_DESTROY(res_wrap_call);

    return SYS_ERR_OK;
}

// Server state is either spawninfo of given child that has connection to us, or NULL
// in case of a remote core.
errval_t init_eventhandler(void *server_state, RpcMethod method, RpcRequestWrap *req,
                           struct capref request_cap, RpcResponseWrap *response_wrap,
                           struct capref *response_cap)
{
    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = (struct spawninfo *)server_state;

    switch (method) {
    case RPC_METHOD__INIT_SEND_NUMBER:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_SEND_NUMBER);
        grading_rpc_handle_number(req->init_send_number->number);
        break;

    case RPC_METHOD__INIT_SEND_STRING:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_SEND_STRING);
        grading_rpc_handler_string(req->init_send_string->str);
        break;

    case RPC_METHOD__INIT_SERIAL_GETCHAR:
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_INIT_SERIAL_GETCHAR;
        err = handle_serial_getchar(&response_wrap->init_serial_getchar);
        break;

    case RPC_METHOD__INIT_SERIAL_PUT_STRING:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_SERIAL_PUT_STRING);
        err = handle_serial_put_string(req->init_serial_put_string);
        break;

    case RPC_METHOD__INIT_SERIAL_PUTCHAR:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_SERIAL_PUTCHAR);
        err = handle_serial_put_char(req->init_serial_putchar);
        break;

    case RPC_METHOD__INIT_PROCESS_GET_ALL_PIDS:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_PROCESS_GET_ALL_PIDS);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_INIT_PROCESS_GET_ALL_PIDS;
        err = handle_get_all_pids(req->init_process_get_all_pids,
                                  &response_wrap->init_process_get_all_pids);
        break;

    case RPC_METHOD__INIT_PROCESS_GET_NAME:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_PROCESS_GET_NAME);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_INIT_PROCESS_GET_NAME;
        err = handle_process_get_name(req->init_process_get_name,
                                      &response_wrap->init_process_get_name);
        break;

    case RPC_METHOD__INIT_PROCESS_SPAWN:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_INIT_PROCESS_SPAWN);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_INIT_PROCESS_SPAWN;
        err = handle_process_spawn(req->init_process_spawn,
                                   &response_wrap->init_process_spawn);
        break;

    case RPC_METHOD__INIT_ESTABLISH_DOMAIN_SERVER:
        assert(si != NULL && !capref_is_null(request_cap));
        err = handle_init_establish_domain_server(si, request_cap);
        break;
    case RPC_METHOD__INIT_PROCESS_INFORM_DEATH:
        err = handle_init_inform_death(req->init_process_inform_death->pid);
    case RPC_METHOD__INIT_NAMESERVER_STARTED:
        set_is_nameserver_started(true);
        break;
    case RPC_METHOD__ROUTE:
        assert(req->data_case == RPC_REQUEST_WRAP__DATA_ROUTE);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_ROUTE;
        err = handle_route(req, request_cap, &response_wrap->route, response_cap);
        break;
    default:
        DEBUG_PRINTF("Unknown RPC_METHOD: %d\n", method);
    }

    return err;
}

static struct waitset mem_server_ws;

struct waitset *mem_server_get_ws(void)
{
    return &mem_server_ws;
}

errval_t mem_eventhandler(void *server_state, RpcMethod method, RpcRequestWrap *req,
                          struct capref request_cap, RpcResponseWrap *response_wrap,
                          struct capref *response_cap)
{
    assert(response_wrap != NULL);

    errval_t err = SYS_ERR_OK;
    struct spawninfo *si = (struct spawninfo *)server_state;

    switch (method) {
    case RPC_METHOD__MEM_GET_RAM_CAP:
        assert(si != NULL && req->data_case == RPC_REQUEST_WRAP__DATA_MEM_GET_RAM_CAP);
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_MEM_GET_RAM_CAP;
        err = handle_get_ram_cap(si, req->mem_get_ram_cap, request_cap,
                                 &response_wrap->mem_get_ram_cap, response_cap);
        break;
    default:
        DEBUG_PRINTF("Unsupported RPC_METHOD: %d.\n", method);
    }

    return err;
}
