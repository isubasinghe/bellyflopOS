#include <stdio.h>

#include <aos/aos.h>
#include <aos/nameserver.h>
#include <aos/macros.h>
#include <aos/deferred.h>

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define WHITE "\x1b[37m"
#define COLOR_RESET "\x1b[0m"

static void frame_alloc_and_map(size_t size, struct capref *cap, void **buf)
{
    errval_t err = frame_alloc(cap, size, NULL);
    ASSERT_ERR_OK(err);
    err = paging_map_frame_complete(get_current_paging_state(), buf, *cap);
    ASSERT_ERR_OK(err);
}

static errval_t server_handler(void *server_state, RpcMethod method,
                               RpcRequestWrap *request_wrap, struct capref request_cap,
                               RpcResponseWrap *response_wrap, struct capref *response_cap)
{
    errval_t err;

    switch (method) {
    case RPC_METHOD__TEST_INCREMENT: {
        TestIncrementResponse *res = malloc(sizeof(TestIncrementResponse));
        test_increment_response__init(res);
        res->number = request_wrap->test_increment->number + 1;
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TEST_INCREMENT;
        response_wrap->test_increment = res;
    } break;
    case RPC_METHOD__TEST_CAP_INCREMENT: {
        TestCapIncrementResponse *res = malloc(sizeof(TestCapIncrementResponse));
        test_cap_increment_response__init(res);
        res->number = request_wrap->test_cap_increment->number + 1;
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_TEST_CAP_INCREMENT;
        response_wrap->test_cap_increment = res;

        uint64_t *buf;
        err = paging_map_frame_complete(get_current_paging_state(), (void **)&buf,
                                        request_cap);
        ASSERT_ERR_OK(err);
        assert(buf[0] == 234234252623452);

        uint64_t *res_buf;
        frame_alloc_and_map(BASE_PAGE_SIZE, response_cap, (void **)&res_buf);
        res_buf[0] = 9879702823;
    } break;
    default:
        DEBUG_PRINTF("Unimplemented method %d\n", method);
    }
    return SYS_ERR_OK;
}

static errval_t run_server(const char *name)
{
    errval_t err;

    // CREATE SERVICE.
    err = nameservice_register_proto(name, server_handler, NULL);
    RETURN_IF_ERR(err);

    // SPAWN CLIENTS.
    // The first client will be connected via LMP, the other via UMP.
    assert(disp_get_core_id() != 0);
    coreid_t client_cores[2] = { disp_get_core_id(), 0 };

    char cmdline[100] = { 0 };
    sprintf(cmdline, "clientserver client %s", name);

    for (size_t i = 0; i < sizeof(client_cores); ++i) {
        err = aos_rpc_process_spawn(aos_rpc_get_init_channel(), cmdline, client_cores[i],
                                    NULL);
        RETURN_IF_ERR(err);
    }

    // Wait a few seconds for the clients to finish.
    barrelfish_usleep(3 * 1000 * 1000);

    // DEREGISTER SERVICE
    err = nameservice_deregister(name);
    RETURN_IF_ERR(err);

    // TRY LOOKUP
    nameservice_chan_t chan;
    err = nameservice_try_lookup(name, &chan);
    if (err_no(err) != LIB_ERR_NAMESERVICE_UNKNOWN_NAME) {
        DEBUG_PRINTF(RED "(Failure) Expected server %s to be deregistered." COLOR_RESET,
                     name);
    }

    while (true) {
        ASSERT_ERR_OK(event_dispatch(get_default_waitset()));
    }
}

static errval_t run_client(const char *name)
{
    errval_t err;

    nameservice_chan_t chan;
    err = nameservice_lookup(name, &chan);
    RETURN_IF_ERR(err);

    // Uses direct channel
    {
        TestIncrementRequest req = TEST_INCREMENT_REQUEST__INIT;
        req.number = 40;
        REQUEST_WRAP(req_wrap, test_increment, TEST_INCREMENT, &req);
        RpcResponseWrap *res_wrap = NULL;
        err = nameservice_rpc_proto(chan, RPC_METHOD__TEST_INCREMENT, &req_wrap, NULL_CAP,
                                    &res_wrap, NULL);
        RETURN_IF_ERR(err);
        assert(res_wrap->data_case == RPC_RESPONSE_WRAP__DATA_TEST_INCREMENT);
        assert(res_wrap->test_increment->number == 41);
        RESPONSE_WRAP_DESTROY(res_wrap);
    }

    // Sending/receiving caps cross-core uses routing.
    {
        struct capref request_cap, response_cap;
        // Prepare request_cap.
        uint64_t *buf;
        frame_alloc_and_map(BASE_PAGE_SIZE, &request_cap, (void **)&buf);
        buf[0] = 234234252623452;

        // Prepare request proto.
        TestCapIncrementRequest req = TEST_CAP_INCREMENT_REQUEST__INIT;
        req.number = 40;
        RpcResponseWrap *res_wrap;
        REQUEST_WRAP(req_wrap, test_cap_increment, TEST_CAP_INCREMENT, &req);

        // Send
        err = nameservice_rpc_proto(chan, RPC_METHOD__TEST_CAP_INCREMENT, &req_wrap,
                                    request_cap, &res_wrap, &response_cap);
        RETURN_IF_ERR(err);

        assert(res_wrap->data_case == RPC_RESPONSE_WRAP__DATA_TEST_CAP_INCREMENT);
        assert(res_wrap->test_cap_increment->number == 41);
        RESPONSE_WRAP_DESTROY(res_wrap);

        // Check response cap.
        err = paging_map_frame_complete(get_current_paging_state(), (void **)&buf,
                                        response_cap);
        RETURN_IF_ERR(err);
        assert(buf[0] = 9879702823);
    }

    return SYS_ERR_OK;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        DEBUG_PRINTF(RED "Invalid number of arguments for clientserver app.\n");
        return 1;
    }

    const char *name = argv[2];
    errval_t err = SYS_ERR_OK;
    if (strcmp(argv[1], "server") == 0) {
        DEBUG_PRINTF(MAGENTA "SERVER '%s' on core %d\n" COLOR_RESET, name,
                     disp_get_core_id());
        err = run_server(name);
    }


    if (strcmp(argv[1], "client") == 0) {
        DEBUG_PRINTF(MAGENTA "CLIENT of '%s' on core %d\n" COLOR_RESET, name,
                     disp_get_core_id());
        err = run_client(name);
    }

    if (err_is_fail(err)) {
        DEBUG_ERR(err, "clientserver failed");
    }

    return EXIT_SUCCESS;
}
