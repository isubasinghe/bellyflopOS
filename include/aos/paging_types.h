/**
 * \file
 * \brief PMAP Implementaiton for AOS
 */

/*
 * Copyright (c) 2019 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef PAGING_TYPES_H_
#define PAGING_TYPES_H_ 1

#include <aos/solution.h>
#include <aos/cap_store.h>
#include <aos/free_list.h>
#include <aos/used_list.h>


#define VADDR_OFFSET ((lvaddr_t)512UL * 1024 * 1024 * 1024)  // 1GB
#define VREGION_FLAGS_READ 0x01                              // Reading allowed
#define VREGION_FLAGS_WRITE 0x02                             // Writing allowed
#define VREGION_FLAGS_EXECUTE 0x04                           // Execute allowed
#define VREGION_FLAGS_NOCACHE 0x08                           // Caching disabled
#define VREGION_FLAGS_MPB 0x10                               // Message passing buffer
#define VREGION_FLAGS_GUARD 0x20                             // Guard page
#define VREGION_FLAGS_MASK 0x2f  // Mask of all individual VREGION_FLAGS

#define VREGION_FLAGS_READ_WRITE (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE)
#define VREGION_FLAGS_READ_EXECUTE (VREGION_FLAGS_READ | VREGION_FLAGS_EXECUTE)
#define VREGION_FLAGS_READ_WRITE_NOCACHE                                                 \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_NOCACHE)
#define VREGION_FLAGS_READ_WRITE_MPB                                                     \
    (VREGION_FLAGS_READ | VREGION_FLAGS_WRITE | VREGION_FLAGS_MPB)

typedef int paging_flags_t;

struct page_table {
    enum objtype type;
    struct capref cap;
    struct page_table *children[PTABLE_ENTRIES];
    struct capref children_mapping[PTABLE_ENTRIES];
    // If a region starts at this size it contains the size.
    // Otherwise it is 0.
    size_t region_size[PTABLE_ENTRIES];
};

#define USED_AND_FREE_LIST_BLOCK_SIZE                                                    \
    (USED_LIST_BLOCK_SIZE > FREE_LIST_BLOCK_SIZE ? USED_LIST_BLOCK_SIZE                  \
                                                 : FREE_LIST_BLOCK_SIZE)

// struct to store the paging status of a process
struct paging_state {
    struct slot_allocator *slot_alloc;
    struct slab_allocator used_and_free_list_slabs;
    struct slab_allocator page_table_slabs;
    struct slab_allocator cap_store_slabs;
    struct free_list free_list;
    struct used_list lazy_mapped;
    struct cap_store lazy_mem_cap_store;
    struct page_table l0_ptable;
    lvaddr_t start_vaddr;
    char init_used_and_free_list_slabs_space[SLAB_STATIC_SIZE(
        32, USED_AND_FREE_LIST_BLOCK_SIZE)];
    char init_page_table_slabs_space[SLAB_STATIC_SIZE(16, sizeof(struct page_table))];
    char init_cap_store_slabs_space[SLAB_STATIC_SIZE(32, CAP_STORE_SLAB_BLOCKSIZE)];
    bool free_list_slab_refilling;
    bool page_table_slab_refilling;
    bool cap_store_slab_refilling;
};


#endif  /// PAGING_TYPES_H_
