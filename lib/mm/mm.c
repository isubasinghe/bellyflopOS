/**
 * \file
 * \brief A library for managing physical memory (i.e., caps)
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

#include <errors/errno.h>

#include <mm/mm.h>
#include <aos/debug.h>
#include <aos/solution.h>
#include <aos/macros.h>

// Nested lock because memory allocs might trigger more memory allocs.
#define MM_LOCK(mm) thread_mutex_lock_nested(&(mm)->mutex)
#define MM_UNLOCK(mm) thread_mutex_unlock(&(mm)->mutex)

errval_t mm_refill_slabs(struct mm *mm)
{
    if (mm->is_refilling) {
        // This is recursively comming from this function.
        return SYS_ERR_OK;
    }

    mm->is_refilling = true;

    if (slab_freecount(&mm->slabs) <= MM_SLAB_CAP_CONTAINER_REFILL_THRESHOLD) {
        errval_t err = slab_default_refill(&mm->slabs);
        if (err_is_fail(err)) {
            mm->is_refilling = false;
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
    }

    if (slab_freecount(&mm->slabs_free_list) <= MM_SLAB_FREE_LIST_REFILL_THRESHOLD) {
        errval_t err = slab_default_refill(&mm->slabs_free_list);
        if (err_is_fail(err)) {
            mm->is_refilling = false;
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
    }

    mm->is_refilling = false;
    return SYS_ERR_OK;
}

void mm_cap_container_init(struct cap_container *cap_container)
{
    // Nothing much to be done here, for the simple implementation.
    cap_container->pos = NULL;
}

errval_t mm_cap_container_add(struct mm *mm, const struct capref *cap, size_t base,
                              size_t size)
{
    struct cap_container_node *new_node = slab_alloc(&mm->slabs);
    if (new_node == NULL) {
        DEBUG_PRINTF("Slab allocator inside mm ran out of memory.");
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }


    new_node->cap = *cap;

    errval_t err = free_list_init(&new_node->free_list, &mm->slabs_free_list, base, size,
                                  false);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FREE_LIST_INIT);

    if (mm->free_caps.pos == NULL) {
        mm->free_caps.pos = new_node;
        new_node->next = new_node;
    } else {
        new_node->next = mm->free_caps.pos->next;
        mm->free_caps.pos->next = new_node;
    }
    return SYS_ERR_OK;
}

errval_t mm_find_next_free_node(struct cap_container *container, size_t size,
                                size_t alignment, size_t *new_base,
                                struct cap_container_node **res_node)
{
    struct cap_container_node *begin = container->pos;
    do {
        errval_t err = free_list_alloc_next(&container->pos->free_list, size, alignment,
                                            new_base);
        if (err != LIB_ERR_FREE_LIST_NO_SPACE && err != LIB_ERR_FREE_LIST_NO_NEXT) {
            *res_node = container->pos;
            return SYS_ERR_OK;
        }
        container->pos = container->pos->next;
    } while (begin != container->pos);

    return MM_ERR_OUT_OF_MEMORY;
}

errval_t mm_init(struct mm *mm, enum objtype objtype, slab_refill_func_t slab_refill_func,
                 slot_alloc_t slot_alloc_func, slot_refill_t slot_refill_func,
                 void *slot_alloc_inst)
{
    thread_mutex_init(&mm->mutex);
    slab_init(&mm->slabs, MM_BLOCK_SIZE, slab_refill_func);
    slab_init(&mm->slabs_free_list, FREE_LIST_BLOCK_SIZE, slab_refill_func);
    mm->slot_alloc = slot_alloc_func;
    mm->slot_refill = slot_refill_func;
    mm->slot_alloc_inst = slot_alloc_inst;
    mm->objtype = objtype;
    mm_cap_container_init(&mm->free_caps);
    mm->is_refilling = false;
    return SYS_ERR_OK;
}

void mm_destroy(struct mm *mm)
{
    assert(!"NYI");
}

errval_t mm_add(struct mm *mm, struct capref cap)
{
    struct capability c;
    errval_t err = cap_direct_identify(cap, &c);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_IDENTIFY);

    MM_LOCK(mm);
    err = mm_cap_container_add(mm, &cap, c.u.ram.base, c.u.ram.bytes);
    GOTO_IF_ERR(err, end);

    err = mm_refill_slabs(mm);
    GOTO_IF_ERR(err, end);

end:
    MM_UNLOCK(mm);
    return err;
}

errval_t mm_alloc_aligned(struct mm *mm, size_t size, size_t alignment,
                          struct capref *retcap)
{
    MM_LOCK(mm);

    errval_t err;
    // Refill the slot allocator, it only refills if needed.
    if (mm->slot_refill != NULL) {
        err = mm->slot_refill(mm->slot_alloc_inst);
        PUSH_GOTO_IF_ERR(err, LIB_ERR_SLOT_REFILL, end);
    }

    // Round up the size to a multiple of BASE_PAGE_SIZE.
    size = round_page(size);
    size_t new_base = 0;
    struct cap_container_node *res_node;
    err = mm_find_next_free_node(&mm->free_caps, size, alignment, &new_base, &res_node);
    GOTO_IF_ERR(err, end);

    err = mm_refill_slabs(mm);
    GOTO_IF_ERR(err, end);


    // Get the result capability.
    err = mm->slot_alloc(mm->slot_alloc_inst, 1, retcap);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_SLOT_ALLOC, end);

    gensize_t offset = new_base - res_node->free_list.base;
    err = cap_retype(*retcap, res_node->cap, offset, mm->objtype, size, 1);
    if (err_is_fail(err)) {
        // If the retype fails should we reinsert the region?
        PUSH_GOTO_IF_ERR(err, LIB_ERR_CAP_RETYPE, end);
    }

end:
    MM_UNLOCK(mm);
    return err;
}

errval_t mm_alloc(struct mm *mm, size_t size, struct capref *retcap)
{
    return mm_alloc_aligned(mm, size, BASE_PAGE_SIZE, retcap);
}

errval_t mm_free(struct mm *mm, struct capref cap)
{
    struct capability c;
    errval_t err = cap_direct_identify(cap, &c);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_IDENTIFY);

    MM_LOCK(mm);
    struct cap_container_node *begin = mm->free_caps.pos;
    struct cap_container_node *pos = begin;

    while ((c.u.ram.base < pos->free_list.base
            || pos->free_list.base + pos->free_list.size < c.u.ram.base)) {
        pos = pos->next;
        if (pos == begin) {
            err = MM_ERR_CAP_NOT_OWNED;
            goto end;
        }
    }

    err = free_list_add_free(&pos->free_list, c.u.ram.base, c.u.ram.bytes);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_FREE_LIST_ADD_FREE, end);

    err = mm_refill_slabs(mm);
    GOTO_IF_ERR(err, end);

    // TODO: Who frees the cap slot?
    err = cap_destroy(cap);
    GOTO_IF_ERR(err, end);

end:
    MM_UNLOCK(mm);
    return err;
}
