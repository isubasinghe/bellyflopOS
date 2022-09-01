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


#include <stdlib.h>
#include <aos/debug.h>
#include <aos/threads.h>
#include <aos/test_utils.h>
#include <aos/ump_ringbuffer.h>

__unused static int stack_overflow(int x, int y, int z, int j, int k)
{
    volatile char buf[4096] = { 0 };
    for (int i = 0; i < 4096; i++) {
        x += buf[i];
    }
    if (z < 0) {
        return x + y + z + j + buf[0];
    }
    return stack_overflow(x + 1, y + 1, z + 1, j + 1,
                          stack_overflow(x + 1, y + 1, z + 1, j + 1, k + 1));
}

#include <aos/test/thread_test.h>
#include <aos/test/malloc_test.h>
#include <aos/test/rpc_spawn_tests.h>
#include <aos/test/nameservice_tests.h>
int main(int argc, char *argv[])
{
    // RUN_TESTS(thread_tests);
    // RUN_TESTS(malloc_test);
    // RUN_TESTS(rpc_spawn_tests);
    // RUN_TESTS(nameservice_tests);
    return EXIT_SUCCESS;
}
