#include <aos/aos.h>
#include <aos/aos_rpc.h>
#include <aos/test_utils.h>
#include <aos/deferred.h>
#include <aos/nameserver.h>
#include <string.h>

CREATE_TEST(nameservice_test_proto, nameservice_tests, {
    errval_t err;

    coreid_t my_coreid = disp_get_core_id();

    if (my_coreid != 0)
        TEST_EXIT_EARLY();


    domainid_t pid = 0;
    struct aos_rpc *init_channel = aos_rpc_get_init_channel();
    TEST_REQUIRE(init_channel != NULL);

    err = aos_rpc_process_spawn(init_channel, "clientserver server test_serverA", 3, &pid);
    TEST_REQUIRE_OK(err);

    err = aos_rpc_process_spawn(init_channel, "clientserver server test_serverB", 3, &pid);
    TEST_REQUIRE_OK(err);


    size_t num;
    ServiceInfo **result;
    err = nameservice_enumerate_services("name", &num, &result);
    TEST_REQUIRE_OK(err);
    TEST_REQUIRE(num == 1);
    TEST_REQUIRE(strcmp(result[0]->name, "nameserver") == 0);
    TEST_REQUIRE(result[0]->sid == NAMESERVER_SERVICEID);

    for (size_t i = 0; i < num; ++i) {
        free(result[i]);
    }
    free(result);
});

CREATE_TEST(ta_provided_nameservice_test, nameservice_tests, {
    errval_t err;

    coreid_t my_coreid = disp_get_core_id();

    if (my_coreid != 0)
        TEST_EXIT_EARLY();


    domainid_t pid = 0;
    struct aos_rpc *init_channel = aos_rpc_get_init_channel();
    TEST_REQUIRE(init_channel != NULL);

    err = aos_rpc_process_spawn(init_channel, "nameservicetest run server", 3, &pid);
    TEST_REQUIRE_OK(err);
});
