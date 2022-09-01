/**
 * \file
 * \brief Hello world application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */


#include <stdio.h>

#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/aos_rpc.h>
#include <aos/domain.h>
#include <spawn/spawn.h>
#include <grading.h>

__unused static void send_number_test(void)
{
    bool passed = true;

    errval_t err;
    err = aos_rpc_send_number(aos_rpc_get_init_channel(), 75);
    if (err_is_fail(err)) {
        passed = false;
        DEBUG_ERR(err, "Failed sending number over RPC.\n");;
    }

    err = aos_rpc_send_number(aos_rpc_get_init_channel(), 80);
    if (err_is_fail(err)) {
        passed = false;
        DEBUG_ERR(err, "Failed sending number over RPC.\n");;
    }

    if (passed) {
        DEBUG_PRINTF("RPC (child): Number test passed.\n");
    } else {
        DEBUG_PRINTF("RPC (child): Number test failed.\n");
    }
}

__unused static void send_string_test(void)
{
    bool passed = true;
    char *goldens[] = STRING_GOLDENS;
    size_t golends_len = sizeof(goldens) / sizeof(char *);

    for (size_t i = 0; i < golends_len; ++i) {
        errval_t err = aos_rpc_send_string(aos_rpc_get_init_channel(), goldens[i]);
        if (err_is_fail(err)) {
            passed = false;
            DEBUG_ERR(err, "Failed sending string over RPC.\n");;
        }
    }

    if (passed) {
        DEBUG_PRINTF("RPC (child): String test passed.\n");
    } else {
        DEBUG_PRINTF("RPC (child): String test failed.\n");
    }
}

__unused static void get_ram_cap_test(void)
{
    bool passed = true;
    struct capref cap;
    size_t bytes;

    errval_t err = aos_rpc_get_ram_cap(aos_rpc_get_memory_channel(), 2 * BASE_PAGE_SIZE,
                                       BASE_PAGE_SIZE, &cap, &bytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "get_ram_cap failed\n");
        passed = false;
        goto end;
    }

    // Checks.
    struct capability c;
    err = cap_direct_identify(cap, &c);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "failed to get capability\n");
        passed = false;
        goto end;
    }

    if (c.type != ObjType_RAM) {
        DEBUG_PRINTF("Return capability is of wrong type: %d\n", c.type);
        passed = false;
        goto end;
    }

    if (c.u.ram.bytes != 2 * BASE_PAGE_SIZE) {
        DEBUG_PRINTF("Return capability is of wrong size: %d\n", c.u.ram.bytes);
        passed = false;
        goto end;
    }

end:
    if (passed) {
        DEBUG_PRINTF("RPC (child): Get ram cap test passed.\n");
    } else {
        DEBUG_PRINTF("RPC (child): Get ram cap test failed.\n");
    }
}

__unused static void get_ram_cap_hit_quota_test(void)
{
    bool passed = true;
    struct capref cap;
    size_t bytes;


    errval_t err = aos_rpc_get_ram_cap(aos_rpc_get_memory_channel(),
                                       DEFAULT_MEMORY_QUOTA_B + 1, BASE_PAGE_SIZE, &cap,
                                       &bytes);
    if (!(err_no(err) == AOS_ERR_RPC_REMOTE_ERR
          && err_no(err_pop(err)) == AOS_ERR_RPC_GET_RAM_CAP_OUT_OF_QUOTA)) {
        DEBUG_ERR(err, "Different error was expected.\n");;
        passed = false;
        goto end;
    }

end:
    if (passed) {
        DEBUG_PRINTF("RPC (child): Get ram cap hit quota test passed.\n");
    } else {
        DEBUG_PRINTF("RPC (child): Get ram cap hit quota test failed.\n");
    }
}

__unused static void exhaust_slots_test(void)
{
    bool passed = true;
    for (size_t i = 0; i < 1000; ++i) {
        struct capref cap;
        errval_t err = slot_alloc(&cap);
        if (err_is_fail(err)) {
            passed = false;
            DEBUG_ERR(err, "exhaust_slots\n");
            break;
        }
    }
}

__unused static void process_management_test(void)
{
    errval_t err;

    struct aos_rpc *process_rpc = aos_rpc_get_process_channel();
    bool passed = true;

    struct test_case {
        char *argstring;
        char *want_name;
    };

    struct test_case test_cases[] = {
        { "hello These args are from rpc_test1.", "hello" },
        { "hello These args are from rpc_test2.", "hello" },
        { "hello These args are from rpc_test3.", "hello" },
        { "hello These args are from rpc_test4.", "hello" },
    };

    for (int i = 0; i < sizeof(test_cases) / sizeof(struct test_case); i++) {
        // DEBUG_PRINTF("%s(): test_case #%d\n", __func__, i);
        struct test_case tc = test_cases[i];
        domainid_t pid = 0;

        err = aos_rpc_process_spawn(process_rpc, tc.argstring, disp_get_core_id(), &pid);

        if (err_is_fail(err) || pid == 0 || pid == INIT_DOMAINID) {
            passed = false;
            DEBUG_ERR(err, "Failed to spawn on test_case %d", i);
            break;
        }
        // DEBUG_PRINTF("SPAWNED PID %d\n", pid);

        char *name = NULL;
        err = aos_rpc_process_get_name(process_rpc, pid, &name);

        if (err_is_fail(err) || name == NULL || 0 != strcmp(name, tc.want_name)) {
            passed = false;
            DEBUG_ERR(err, "Failed to obtain name on test_case %d", i);
            break;
        }
        free(name);
    }

    domainid_t *pids = NULL;
    size_t num_pids = 0;

    err = aos_rpc_process_get_all_pids(process_rpc, &pids, &num_pids);
    if (err_is_fail(err)) {
        passed = false;
        DEBUG_ERR(err, "Failed to obtain process ids");
    }

    for (int i = 0; i < num_pids; i++) {
        debug_printf("PID %d alive\n", pids[i]);
    }
    free(pids);


    if (passed) {
        DEBUG_PRINTF("Test process_management_test passed.\n");
    } else {
        DEBUG_PRINTF("Test process_management_test failed.\n");
    }
}

static char *msg = "MSG FROM SERIAL TEST\n";
__unused static void terminal_test(void)
{
    errval_t err;
    bool passed = true;
    struct aos_rpc *serial_rpc = aos_rpc_get_serial_channel();

    for (size_t i = 0; msg[i] != '\0'; ++i) {
        err = aos_rpc_serial_putchar(serial_rpc, msg[i]);
        if (err_is_fail(err)) {
            passed = false;
            DEBUG_ERR(err, "Failed to write char");
        }
    }

    DEBUG_PRINTF("(press a key)\n");
    char c;
    err = aos_rpc_serial_getchar(serial_rpc, &c);
    if (err_is_fail(err)) {
        passed = false;
        DEBUG_ERR(err, "Failed to get char");
    }

    err = aos_rpc_serial_put_string(serial_rpc, msg, strlen(msg));
    if (err_is_fail(err)) {
        passed = false;
        DEBUG_ERR(err, "Failed to write string");
    }


    if (passed) {
        DEBUG_PRINTF("(RPC Child) Test terminal_test passed.\n");
    } else {
        DEBUG_PRINTF("(RPC Child) Test terminal_test failed.\n");
    }
}

int main(int argc, char *argv[])
{
    send_number_test();
    send_string_test();
    terminal_test();
    exhaust_slots_test();
    get_ram_cap_test();
    get_ram_cap_hit_quota_test();
    process_management_test();

    // Let the init know we're done.
    errval_t err = aos_rpc_send_number(aos_rpc_get_init_channel(), RPC_TEST_END_MAGIC);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Failed sending magic test end number over RPC.\n");
    }

    return EXIT_SUCCESS;
}
