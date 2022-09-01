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

#include "collections/static_hash_table.h"
#include "inttypes.h"
#include <stdio.h>
#include <aos/aos.h>


/******************************************************
 * a simple hash table implementation
 ******************************************************/

/*
 * Create a hash table.
 */
void collections_static_hash_create(collections_static_hash_table *t,
                                    struct slab_allocator *slabs)
{
    memset(t, 0, sizeof(collections_static_hash_table));
    t->slabs = slabs;
    t->num_elems = 0;
    return;
}


// delete the entire hash table
void collections_static_hash_release(collections_static_hash_table *t)
{
    assert(t->num_elems == 0);
}

static collections_static_hash_elem *
collections_static_hash_find_elem(collections_static_hash_table *t, uint64_t key)
{
    uint32_t bucket_num;
    collections_static_hash_elem *elem;

    bucket_num = key % STATIC_NUM_BUCKETS;
    elem = t->buckets[bucket_num];
    while (elem != NULL) {
        if (elem->key == key) {
            return elem;
        }
        elem = elem->next;
    }
    return NULL;
}

/*
 * Inserts an element into the hash table.
 */
void collections_static_hash_insert(collections_static_hash_table *t, uint64_t key,
                                    void *data)
{
    uint32_t bucket_num;
    collections_static_hash_elem *elem;

    elem = collections_static_hash_find_elem(t, key);
    if (elem != NULL) {
        printf("Error: key %" PRIu64 " already present in hash table %" PRIu64 "\n", key,
               elem->key);
        assert(0);
        return;
    }

    bucket_num = key % STATIC_NUM_BUCKETS;
    elem = (collections_static_hash_elem *)slab_alloc(t->slabs);
    elem->key = key;
    elem->data = data;
    elem->next = t->buckets[bucket_num];
    t->buckets[bucket_num] = elem;
    t->num_elems++;
}

/*
 * Retrieves an element from the hash table.
 */
void *collections_static_hash_find(collections_static_hash_table *t, uint64_t key)
{
    collections_static_hash_elem *he = collections_static_hash_find_elem(t, key);
    return (he) ? he->data : NULL;
}

/*
 * Removes a specific element from the table and returns it
 */
void *collections_static_hash_delete(collections_static_hash_table *t, uint64_t key)
{
    uint32_t bucket_num;
    collections_static_hash_elem *elem;

    bucket_num = key % STATIC_NUM_BUCKETS;
    elem = t->buckets[bucket_num];
    collections_static_hash_elem **prev_next = &t->buckets[bucket_num];
    while (elem != NULL) {
        if (elem->key == key) {
            void *data = elem->data;
            *prev_next = elem->next;
            t->num_elems--;
            slab_free(t->slabs, elem);
            return data;
        }
        prev_next = &elem->next;
        elem = elem->next;
    }

    return NULL;
}

/*
 * Returns the number of elements in the hash table.
 */
uint32_t collections_static_hash_size(collections_static_hash_table *t)
{
    return (t->num_elems);
}
