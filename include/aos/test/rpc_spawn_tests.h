#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/test_utils.h>
#include <string.h>

CREATE_TEST(spawn_hello, rpc_spawn_tests, {
    coreid_t my_coreid = disp_get_core_id();
    coreid_t target_coreid = (my_coreid + 3) % 4;

    char cmd[80];
    sprintf(cmd, "hello spawned from core %d", my_coreid);
    domainid_t pid = 0;
    struct aos_rpc *init_channel = aos_rpc_get_init_channel();
    TEST_REQUIRE(init_channel != NULL);

    errval_t err = aos_rpc_process_spawn(init_channel, cmd, target_coreid, &pid);

    err = aos_rpc_process_spawn(init_channel, cmd, target_coreid, &pid);

    TEST_REQUIRE_OK(err);
});
