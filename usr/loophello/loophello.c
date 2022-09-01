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

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("No name given.");
        return EXIT_SUCCESS;
    }
    while (1) {
        printf("Hello from %s\n", argv[1]);
        int x = 1000000000;
        while (x--)
            ;
    }
    return EXIT_SUCCESS;
}
