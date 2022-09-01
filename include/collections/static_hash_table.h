/**
 * \file
 * \brief Barrelfish collections library hash table
 */
/*
 * Copyright (c) 2010, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstrasse 6, CH-8092 Zurich. Attn: Systems Group.
 */

#ifndef __STATIC_HASH_TABLE_H_
#define __STATIC_HASH_TABLE_H_

#include <stdint.h>
#include <string.h>
#include <assert.h>

/*
 * a simple hash table.
 */

#define STATIC_NUM_BUCKETS 1011


/*
 * Structure of a hash table element.
 */
typedef struct _collections_static_hash_elem {
    struct _collections_static_hash_elem *next;
    uint64_t key;

    void *data;
} collections_static_hash_elem;


typedef struct _collections_static_hash_table {
    // pointer to the buckets.
    struct _collections_static_hash_elem *buckets[STATIC_NUM_BUCKETS];
    struct slab_allocator *slabs;

    // total number of elements in the table.
    uint32_t num_elems;
} collections_static_hash_table;


#define STATIC_HASH_TABLE_SLAB_BLOCKSIZE sizeof(collections_static_hash_elem)

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus


/*
 * functions ...
 */
void collections_static_hash_create(collections_static_hash_table *t,
                                    struct slab_allocator *slabs);
void collections_static_hash_release(collections_static_hash_table *t);
void collections_static_hash_insert(collections_static_hash_table *t, uint64_t key,
                                    void *data);
void *collections_static_hash_find(collections_static_hash_table *t, uint64_t key);
void *collections_static_hash_delete(collections_static_hash_table *t, uint64_t key);
uint32_t collections_static_hash_size(collections_static_hash_table *t);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif
