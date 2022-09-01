// We used this to run our tests from this file.

#include <stdio.h>
#include <aos/aos.h>
#include <aos/capabilities.h>
#include <aos/ram_alloc.h>
#include <aos/aos_rpc.h>
#include <grading.h>
#include <spawn/spawn.h>
#include <mm/mm.h>
#include <aos/test_utils.h>

// #define DO_TESTING
//#define BENCHMARK
//#define RUN_REMOTE_TEST
//#define RUN_FS_TEST


void grading_setup_bsp_init(int argc, char **argv) { }

void grading_setup_app_init(struct bootinfo *bi) { }

void grading_setup_noninit(int *argc, char ***argv) { }

#include "mm_test.h"
void grading_test_mm(struct mm *test)
{
#ifdef DO_TESTING
    test_mm = test;
    RUN_TESTS(mm_tests);
#endif
}


__unused static void module_load_hello_test(void)
{
    bool passed = true;

    // TODO: Make actual checks in this test.
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t pid;
    errval_t err = spawn_load_by_name("hello", si, &pid);
    if (err_is_fail(err)) {
        passed = false;
        DEBUG_ERR(err, "Loading hello failed");
    }

    if (passed) {
        DEBUG_PRINTF("Test module_load_hello_test passed.\n");
    } else {
        DEBUG_PRINTF("Test module_load_hello_test failed.\n");
    }
}


__unused static void module_load_two_loophellos_test(void)
{
    bool passed = true;
    /*struct spawnstore *ss = get_default_spawnstore();*/

    // TODO: Make actual checks in this test.
    {
        struct spawninfo *si = malloc(sizeof(struct spawninfo));
        domainid_t pid;
        errval_t err = spawn_load_by_name("loophello", si, &pid);
        if (err_is_fail(err)) {
            passed = false;
            DEBUG_ERR(err, "Loading hello failed");
        }
    }

    {
        struct spawninfo *si = malloc(sizeof(struct spawninfo));
        domainid_t pid;
        char *argv[3] = { "loophello", "Other name", "Other name" };
        errval_t err = spawn_load_argv(2, argv, si, &pid);
        if (err_is_fail(err)) {
            passed = false;
            DEBUG_ERR(err, "Loading hello failed");
        }
        struct spawninfo *sinf = NULL;
        spawnstore_get_by_name(get_default_spawnstore(), &sinf, "loophello");
        printf("GOT loophello with pid %d\n", sinf->pid);

        size_t num_processes = spawnstore_size(get_default_spawnstore());
        domainid_t *pids = malloc(sizeof(domainid_t) * num_processes);
        assert(spawnstore_get_all_pids(get_default_spawnstore(), pids, num_processes));
        printf("Got %ld num processes \n", num_processes);
        for (int i = 0; i < num_processes; i++) {
            printf("Got pid %d\n", pids[i]);
        }
        free(pids);


        volatile int count = 0;
        DEBUG_PRINTF("waiting\n");
        while (count++ < 1000000000)
            ;

        DEBUG_PRINTF("killing child\n");
        /*spawn_kill_by_pid(ss, si.pid);*/
        assert(err_is_ok(spawn_kill_by_pid( get_default_spawnstore(),si->pid)));
        DEBUG_PRINTF("done killing child\n");
    }


    if (passed) {
        DEBUG_PRINTF("Test module_load_two_loophellos_test passed.\n");
    } else {
        DEBUG_PRINTF("Test module_load_two_loophellos_test failed.\n");
    }
}


#include <aos/test/paging_test.h>
#include <aos/test/thread_test.h>
#include <aos/test/cap_store_tests.h>
#include <aos/test/ump_chan_tests.h>
void grading_test_early(void)
{
#ifdef DO_TESTING
    RUN_TESTS(paging_tests);
    RUN_TESTS(paging_tests_slow);
    RUN_TESTS(self_paging_tests);
    RUN_TESTS(cap_store_tests);
    RUN_TESTS(thread_tests);
    RUN_TESTS(ump_chan_tests);
#endif
}

__unused static void spawn_by_module_name(char *module_name)
{
    struct spawninfo *si = malloc(sizeof(struct spawninfo));
    domainid_t pid;
    errval_t err = spawn_load_by_name(module_name, si, &pid);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Spawning module failed.");
    }
}

void grading_test_late(void)
{
    // We spawn RPC tests here because after `grading_test_late()` the init main jumps
    // into the event handling loop.
#ifndef BENCHMARK
#    ifdef RUN_REMOTE_TEST
    DEBUG_PRINTF("\n----------------------------------------------\n");
    DEBUG_PRINTF("Starting threads tests by spawning threads_test module:\n");
    // spawn_by_module_name("rpc_test");
    spawn_by_module_name("remote_test");
#    endif

#    ifdef RUN_FS_TEST
    if (disp_get_core_id() == 1) spawn_by_module_name("filereader");
#    endif
#endif

#ifdef BENCHMARK
#    ifdef RUN_REMOTE_BENCH
    if (disp_get_core_id() == 0) {
        spawn_by_module_name("remote_bench");
    }
#    endif
#endif
}
