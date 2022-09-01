/**
 * \file
 * \brief create child process library
 */

/*
 * Copyright (c) 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetsstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef _INIT_SPAWN_H_
#define _INIT_SPAWN_H_
#include <collections/list.h>
#include <barrelfish_kpi/platform.h>
#include <aos/spawnstore.h>
#include "aos/slot_alloc.h"
#include "aos/paging.h"
#include <aos/aos_rpc.h>

#define DEFAULT_MEMORY_QUOTA_B (1 << 27)  // 128MB


struct memory_tracking {
    size_t remaining_quota_B;

    // List of caprefs.
    collections_listnode *allocated_ram_caps;
};

struct spawninfo {
    // the next in the list of spawned domains
    struct spawninfo *next;

    // Information about the binary
    char *binary_name;  // Name of the binary

    // TODO(M2): Add fields you need to store state
    //           when spawning a new dispatcher,
    //           e.g. references to the child's
    //           capabilities or paging state

    domainid_t pid;
    struct single_slot_allocator single_slot_alloc;

    struct capref disp_cap;
    struct capref disp_frame;
    lvaddr_t disp_frame_addr;

    struct cnoderef rootcn;
    struct cnoderef taskcn;
    struct cnoderef pagecn;
    struct cnoderef basecn;

    struct capref rootcn_cap;
    struct capref pagecn_cap;

    struct capref l0_cap;

    struct paging_state *paging_state;

    struct mem_region *module;

    // Pointers to loaded ELF segments in parent's VSpace. We keep track of them to
    // unmap them after ELF is loaded into child's VSpace.
    void **loaded_segments_arr;
    size_t loaded_segments_arr_size;
    size_t loaded_segments_arr_next_idx;

    genvaddr_t binary_entry_addr;
    genvaddr_t args_ptr_child_vspace;

    struct capref pmap_frame;

    struct spawn_domain_params *sdp;

    struct memory_tracking memory_tracking;

    struct aos_rpc init_server_rpc;
    struct aos_rpc mem_server_rpc;
    struct aos_rpc domain_client_rpc;
    bool has_domain_client_rpc;
};

// Start a child process using the multiboot command line. Fills in si.
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_by_cmdline(char *cmd_line, struct spawninfo *si, domainid_t *pid);
errval_t spawn_load_by_cmdline_argcn(char *cmd_line_string, struct spawninfo *si,
                                     domainid_t *pid, struct capref argcn0,
                                     struct capref argcn1, struct capref argcn2);

// Start a child with an explicit command line. Fills in si.
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid);
errval_t spawn_load_argv_argcn(int argc, char *argv[], struct spawninfo *si,
                               domainid_t *pid, struct capref argcn0,
                               struct capref argcn1, struct capref argcn2);

errval_t spawn_kill_and_free(struct spawninfo *si);

errval_t spawn_kill_by_pid(struct spawnstore *ss, domainid_t pid);

// Spawn new core
errval_t spawn_core(void *from_i_to_0_urpc, size_t coreid, enum pi_platform platform);

#endif /* _INIT_SPAWN_H_ */
