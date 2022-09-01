
#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/test_utils.h>
#include <aos/systime.h>

#define TIME(t) do {                \
    INSTR_BARRIER;                      \
    DATA_BARRIER;                       \
    *t = systime_now();   \
    INSTR_BARRIER;                      \
    DATA_BARRIER;                       \
} while(0)
/*


TODO: Commented out, reimplement with nameserver infra later.


static char * create_large_str(size_t size)
{
    char * str = (char *) malloc(size);
    memset(str, 'a', size);
    str[size - 1] = '\0';
    return str;
}

// Old version:
// Create Server: 6.194660 creates/s

static int cur_port = 150;

#define NUM_MSGS 1000000
#define BYTES (10 * 1024 * 1024)

CREATE_TEST(throughput, rpc_bench,
{
    DEBUG_PRINTF(MAGENTA "\nRunning BENCHMARK: %s \n" COLOR_RESET, __func__);
    errval_t err;
    systime_t tstart;
    systime_t tend;

    struct aos_rpc *init_channel = aos_rpc_get_init_channel();
    TEST_REQUIRE(init_channel != NULL);

    int port = cur_port++;

    // Create server.
    struct aos_rpc_server_socket server;
    DEBUG_PRINTF(MAGENTA "CREATE server on core %d on port %d\n" COLOR_RESET,
disp_get_core_id(), port); err = aos_rpc_create_server_on_port(&server, (uint16_t) port);
    TEST_REQUIRE_OK(err);

    struct aos_rpc_client client;

    // Setup client process.
    domainid_t pid = 0;
    char throughput_client_cmd[80];
    sprintf(throughput_client_cmd, "remote_bench throughput_client %d", port);

    err = aos_rpc_process_spawn(init_channel, throughput_client_cmd, 2, &pid);
    TEST_REQUIRE_OK(err);

    DEBUG_PRINTF(MAGENTA "waiting for accept\n" COLOR_RESET);

    err = aos_rpc_accept_connection(&server, &client);
    DEBUG_PRINTF(MAGENTA "waiting for accept done\n" COLOR_RESET);
    TEST_REQUIRE_OK(err);

    // Receive data and measure throughput.
    DEBUG_PRINTF(MAGENTA "RECEIVING %d messages\n" COLOR_RESET, NUM_MSGS);

    TIME(&tstart);

    for (int i = 0; i < NUM_MSGS; i++) {
        struct aos_rpc_msg msg;
        err = aos_rpc_recv_blocking(&client.channel, &msg);
        TEST_REQUIRE_OK(err);
    }

    TIME(&tend);

    // Print results.
    DEBUG_PRINTF(MAGENTA "Throughput (recv %d small msgs): %f msgs/ns\n" COLOR_RESET,
NUM_MSGS, (double) NUM_MSGS  / (double) (systime_to_ns(tend) - systime_to_ns(tstart)));

    // --------------------------------------------------

    TIME(&tstart);

    struct aos_rpc_msg msg;
    err = aos_rpc_recv_blocking(&client.channel, &msg);
    TEST_REQUIRE_OK(err);

    TIME(&tend);

    // Check that we received the correct message.
    TEST_REQUIRE(strcmp((char *) create_large_str(BYTES), aos_rpc_msg_to_string(&msg)) ==
0);

    aos_rpc_msg_destroy(&msg);
    DEBUG_PRINTF(MAGENTA "Throughput (recv large message): %f B/ns\n" COLOR_RESET,
(double) BYTES / (double) (systime_to_ns(tend) - systime_to_ns(tstart)));
})


static int throughput_client(int port)
{
    systime_t tstart;
    systime_t tend;

    struct aos_rpc_msg msg = aos_rpc_msg_from_string("TEST");
    msg.method = AOS_RPC_METHOD_SendString;

    struct aos_rpc_client client;
    errval_t err;
    // DEBUG_PRINTF(CYAN "Binding to server on port %d\n" COLOR_RESET, disp_get_core_id(),
port); err = aos_rpc_connect_to_port(&client, port);

    TIME(&tstart);

    for (int i = 0; i < NUM_MSGS; i++) {
        aos_rpc_send(&client.channel, msg);
    }

    TIME(&tend);

    DEBUG_PRINTF(MAGENTA "Throughput (send %d small msgs): %f msgs/ns\n" COLOR_RESET,
NUM_MSGS, (double) NUM_MSGS  / (double) (systime_to_ns(tend) - systime_to_ns(tstart)));


    // ------------------------------------------------------------


    msg = aos_rpc_msg_from_string(create_large_str(BYTES));
    msg.method = AOS_RPC_METHOD_SendString;

    TIME(&tstart);
    aos_rpc_send(&client.channel, msg);
    TIME(&tend);

    aos_rpc_msg_destroy(&msg);

    DEBUG_PRINTF(MAGENTA "Throughput (send large message): %f B/ns\n" COLOR_RESET,
(double) BYTES / (double) (systime_to_ns(tend) - systime_to_ns(tstart)));

    return 0;
}


CREATE_TEST(create_server, rpc_bench,
{
    DEBUG_PRINTF(MAGENTA "\nRunning BENCHMARK: %s \n" COLOR_RESET, __func__);
    int rounds = 60;
    systime_t tstart;
    TIME(&tstart);

    for (int i = 0; i < rounds; i++) {
        struct aos_rpc_server_socket server;
        aos_rpc_create_server_on_port(&server, (uint16_t) cur_port++);
    }

    systime_t tend;
    TIME(&tend);

    DEBUG_PRINTF(MAGENTA "Create Server: %f creates/s\n" COLOR_RESET, (double) rounds *
1000000000. / (double) (systime_to_ns(tend) - systime_to_ns(tstart)));
});

*/
#include <aos/deferred.h>

CREATE_TEST(malloc, rpc_bench,
{

    barrelfish_usleep(1000 * 1000 * 2);
    debug_printf(MAGENTA "\nRunning BENCHMARK: %s \n" COLOR_RESET, __func__);
    systime_t tstart;
    TIME(&tstart);

    size_t size = 128 * 1024 * 1024;
    volatile char* buf = malloc(size);

    for (int i = 0; i < size; i+= BASE_PAGE_SIZE) {
        buf[i] = 'a';
    }

    systime_t tend;
    TIME(&tend);

    debug_printf(MAGENTA "alllocated and used  %d pages in  : %f ms\n" COLOR_RESET, size/BASE_PAGE_SIZE , (double)  (systime_to_ns(tend) - systime_to_ns(tstart)) /1000000.  );
});


int main(int argc, char *argv[])
{
    // Dummy main.
    // debug_printf(MAGENTA "\nRunning BENCHMARK: %s \n" COLOR_RESET, __func__);
    // //return 0;
    // if (argc == 1) {
    //     RUN_TESTS(rpc_bench);
    //     return EXIT_SUCCESS;
    // }

    // char *cmd = NULL;
    // if (argc >= 2) {
    //     cmd = argv[1];
    // }

    // if (strcmp(cmd, "throughput_client") == 0) {
    //     assert(argc == 3);
    //     int port = atoi(argv[2]);
    //     return throughput_client(port);
    // }

    // DEBUG_PRINTF(MAGENTA "Unknown command: %s\n" COLOR_RESET, cmd);
    // return 1;
    return 1;
}
