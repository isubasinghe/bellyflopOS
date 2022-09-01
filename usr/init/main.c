/**
 * \file
 * \brief init process for child spawning
 */

/*
 * Copyright (c) 2007, 2008, 2009, 2010, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#include <stdio.h>
#include <stdlib.h>

#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/morecore.h>
#include <aos/nameserver.h>
#include <aos/paging.h>
#include <aos/waitset.h>
#include <aos/aos_rpc.h>
#include <aos/aos_rpc_servers.h>
#include <spawn/spawn.h>
#include <aos/kernel_cap_invocations.h>
#include <mm/mm.h>
#include <grading.h>

#include "mem_alloc.h"
#include "setup.h"


struct bootinfo *bi;

coreid_t my_core_id;
struct platform_info platform_info;

static size_t urpc_offset(size_t from, size_t to)
{
    return to * BASE_PAGE_SIZE + from * NCORES * BASE_PAGE_SIZE;
}

static errval_t init_crosscore_ump_channels(void *urpc_start_void)
{
    errval_t err;
    char *urpc_start = (char *)urpc_start_void;
    static struct aos_rpc core_server_rpcs[MAX_COREID];
    static struct aos_rpc core_client_rpcs[MAX_COREID];

    for (size_t i = 0; i < NCORES; ++i) {
        if (my_core_id == i) {
            continue;
        }
        char *from_i_to_me_urpc = urpc_start + urpc_offset(/*from=*/i, /*to=*/my_core_id);
        err = aos_rpc_init_ump_server(&core_server_rpcs[i], from_i_to_me_urpc,
                                      BASE_PAGE_SIZE, get_default_waitset(),
                                      init_eventhandler, NULL);
        RETURN_IF_ERR(err);
        set_core_server_rpc(i, &core_server_rpcs[i]);

        char *from_me_to_i_urpc = urpc_start + urpc_offset(/*from=*/my_core_id, /*to=*/i);
        aos_rpc_init_ump_client(&core_client_rpcs[i], from_me_to_i_urpc, BASE_PAGE_SIZE);
        set_core_client_rpc(i, &core_client_rpcs[i]);
    }
    return SYS_ERR_OK;
}

static int bsp_main(int argc, char *argv[])
{
    errval_t err;

    // Grading
    grading_setup_bsp_init(argc, argv);

    // First argument contains the bootinfo location, if it's not set
    bi = (struct bootinfo *)strtol(argv[1], NULL, 10);
    assert(bi);

    err = initialize_ram_alloc();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "initialize_ram_alloc");
    }
    // Grading
    grading_test_early();

    // TODO: initialize mem allocator, vspace management here

    // Mem server needs to run in a separate thread because clients might request
    // memory while being served by the init server.
    run_dispatcher_threads(1, mem_server_get_ws());


    // Spawn nameserver.
    err = setup_nameserver_bsp();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "setup_nameserver_bsp failed");
    }

    size_t retbytes = 0;
    // one for writing request and one for writing a reply
    err = frame_alloc_aligned(&cap_urpc, 2 * NCORES * NCORES * BASE_PAGE_SIZE,
                              CACHE_LINE_SIZE, &retbytes);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "frame_alloc_aligned for urpc failed.");
    }

    char *urpc_start = NULL;
    err = paging_map_frame_complete(get_current_paging_state(), (void **)&urpc_start,
                                    cap_urpc);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "paging_map_frame_complete for urpc failed.");
    }

    // TODO: Spawn system processes, boot second core etc. here

    for (size_t i = 1; i < NCORES; ++i) {
        char *from_i_to_0_urpc = urpc_start + urpc_offset(/*from=*/i, /*to=*/0);
        err = spawn_core(from_i_to_0_urpc, i, platform_info.platform);
        if (err_is_fail(err)) {
            DEBUG_ERR(err, "Failed spawning a new core");
        }
    }
    err = init_crosscore_ump_channels(urpc_start);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "unable to init cross core UMP channels.");
    }

    err = setup_terminal_driver();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error starting the terminal driver");
    }
    // Start the enet driver
    /* err = setup_network_driver();
    DEBUG_ERR(err, "Error starting the network driver.");
     */

     err = setup_filesystem();
     if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error starting the network driver.");
     }
    // Grading
    grading_test_late();

    // Run more dispatchers to prevent deadlocks from nested RPCs.
    run_dispatcher_threads(3, get_default_waitset());

    // Start the enet driver
    err = setup_network_driver();
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error starting the network driver.");
    }
    // domainid_t pid_nettest;
    // err = aos_rpc_process_spawn(
    //     get_core_client_rpc(2), "echoserver tcp 1234", 2, &pid_nettest);
    // if (err_is_fail(err)) {
    //     DEBUG_ERR(err, "Error starting the network driver test.");
    // }

    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }

    return EXIT_SUCCESS;
}

static int app_main(int argc, char *argv[])
{
    // Map URPC
    char *urpc_start;
    struct capability c;
    ASSERT_ERR_OK(cap_direct_identify(cap_urpc, &c));
    ASSERT_ERR_OK(paging_map_frame_complete(get_current_paging_state(),
                                            (void **)&urpc_start, cap_urpc));


    // Init mem server. The values of urpc[] are filled in the spawn_core().
    struct capref core_ram_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };
    uintptr_t *urpc = (uintptr_t *)(urpc_start + urpc_offset(my_core_id, 0));

    ASSERT_ERR_OK(ram_forge(core_ram_cap, urpc[0], urpc[1], my_core_id));
    ASSERT_ERR_OK(initialize_ram_alloc_app_core(core_ram_cap));

    run_dispatcher_threads(1, mem_server_get_ws());

    // Init bootinfo
    struct capref bi_cap = {
        .cnode = cnode_task,
        .slot = TASKCN_SLOT_BOOTINFO,
    };
    ASSERT_ERR_OK(frame_forge(bi_cap, urpc[2], urpc[3], my_core_id));
    ASSERT_ERR_OK(
        paging_map_frame_complete(get_current_paging_state(), (void **)&bi, bi_cap));
    ASSERT_ERR_OK(cnode_create_foreign_l2(cap_root, ROOTCN_SLOT_MODULECN, &cnode_module));
    ASSERT_ERR_OK(frame_forge(cap_mmstrings, urpc[4], urpc[5], my_core_id));

    for (size_t i = 0; i < bi->regions_length; ++i) {
        if (bi->regions[i].mr_type == RegionType_Module) {
            struct capref module_cap = {
                .cnode = cnode_module,
                .slot = bi->regions[i].mrmod_slot,
            };
            size_t size = bi->regions[i].mrmod_size;
            ASSERT_ERR_OK(frame_forge(module_cap, bi->regions[i].mr_base,
                                      ROUND_UP(size, BASE_PAGE_SIZE), my_core_id));
        }
    }
    // Now bootinfo is initilized.
    grading_setup_app_init(bi);
    // clear the first bytes passed in via 0's init process
    memset(urpc, 0, BASE_PAGE_SIZE);

    ASSERT_ERR_OK(init_crosscore_ump_channels(urpc_start));

    setup_nameserver_app();

    // Run more dispatchers to prevent deadlocks from nested RPCs.
    run_dispatcher_threads(3, get_default_waitset());


    if (my_core_id == 1) {
        struct spawninfo *shell_si = malloc(sizeof(struct spawninfo));
        domainid_t shell_pid;
        ASSERT_ERR_OK(spawn_load_by_name("shell", shell_si, &shell_pid));
    }

    grading_test_late();
    
    // Hang around
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }

    return EXIT_SUCCESS;
}


int main(int argc, char *argv[])
{
    errval_t err;

    /* Set the core id in the disp_priv struct */
    err = invoke_kernel_get_core_id(cap_kernel, &my_core_id);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the core id from the kernel\n");
    }


    disp_set_core_id(my_core_id);

    /* obtain the platform information */
    err = invoke_kernel_get_platform_info(cap_kernel, &platform_info);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "failed to obtain the platform info from the kernel\n");
    }

    char *platform;
    switch (platform_info.platform) {
    case PI_PLATFORM_QEMU:
        platform = "QEMU";
        break;
    case PI_PLATFORM_IMX8X:
        platform = "IMX8X";
        break;
    default:
        platform = "UNKNOWN";
    }

    debug_printf("init domain starting on core %" PRIuCOREID " (%s), invoked as:",
                 my_core_id, platform);
    for (int i = 0; i < argc; i++) {
        printf(" %s", argv[i]);
    }
    printf("\n");


    fflush(stdout);


    if (my_core_id == 0)
        return bsp_main(argc, argv);
    else
        return app_main(argc, argv);
}
