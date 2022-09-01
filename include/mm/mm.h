/**
 * \file
 * \brief Memory manager header
 */

/*
 * Copyright (c) 2008, 2011, ETH Zurich.
 * Copyright (c), 2022, The University of British Columbia
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Haldeneggsteig 4, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef AOS_MM_H
#define AOS_MM_H

#include <sys/cdefs.h>
#include <errors/errno.h>
#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include "slot_alloc.h"
#include <aos/free_list.h>


__BEGIN_DECLS


// cap_container_node is a substruct of free_container_node
// do not reorder the first 3 attributes.
struct cap_container_node {
    struct capref cap;
    struct free_list free_list;
    struct cap_container_node *next;
};

#define MM_BLOCK_SIZE sizeof(struct cap_container_node)

struct cap_container {
    struct cap_container_node *pos;
    void *free_list_pos;
};

errval_t mm_refill_slabs(struct mm *mm);

void mm_cap_container_init(struct cap_container *cap_container);

errval_t mm_cap_container_add(struct mm *mm, const struct capref *cap, size_t base,
                              size_t size);

errval_t mm_find_next_free_node(struct cap_container *container, size_t size,
                                size_t alignment, size_t *new_base,
                                struct cap_container_node **res_node);

#define MM_SLAB_CAP_CONTAINER_REFILL_THRESHOLD 2
#define MM_SLAB_FREE_LIST_REFILL_THRESHOLD FREE_LIST_REFILL_THRESHOLD

/**
 * \brief Memory manager instance data
 *
 * This should be opaque from the perspective of the client, but to allow
 * them to allocate its memory, we declare it in the public header.
 */
struct mm {
    struct slab_allocator slabs;  ///< Slab allocator used for allocating nodes
    struct slab_allocator slabs_free_list;
    slot_alloc_t slot_alloc;    ///< Slot allocator for allocating cspace
    slot_refill_t slot_refill;  ///< Slot allocator refill function
    void *slot_alloc_inst;      ///< Opaque instance pointer for slot allocator
    enum objtype objtype;       ///< Type of capabilities stored
    struct cap_container free_caps;
    bool is_refilling;

    // mem allocator needs to be thread-safe because the mem server is running on a
    // separate thread.
    struct thread_mutex mutex;
};

errval_t mm_init(struct mm *mm, enum objtype objtype, slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func, slot_refill_t slot_refill_func,
                 void *slot_alloc_inst);
errval_t mm_add(struct mm *mm, struct capref cap);
errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                          struct capref *retcap);
errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap);
errval_t mm_free(struct mm *mm, struct capref cap);
void mm_destroy(struct mm *mm);

__END_DECLS

#endif /* AOS_MM_H */
