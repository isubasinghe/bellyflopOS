/**
 * \file
 * \brief AOS paging helpers.
 */

/*
 * Copyright (c) 2012, 2013, 2016, ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, Universitaetstr. 6, CH-8092 Zurich. Attn: Systems Group.
 */

#include <aos/aos.h>
#include <aos/paging.h>
#include <aos/except.h>
#include <aos/slab.h>
#include <aos/macros.h>
#include "threads_priv.h"
#include <arch/aarch64/arch/threads.h>


#include <stdio.h>
#include <string.h>

static struct paging_state current;

static struct thread_mutex paging_mutex;

#define EXCEPTION_STACK_SIZE (1 << 14)
static char stack_first[EXCEPTION_STACK_SIZE];

#define LAZY_MAP_CAP_SIZE (BASE_PAGE_SIZE * 128)

errval_t static paging_map_fixed_attr_internal(struct paging_state *st, lvaddr_t vaddr,
                                               struct capref frame, size_t frame_offset,
                                               size_t bytes, int flags);


/**
 * \brief Helper function that allocates a slot and
 *        creates a aarch64 page table capability for a certain level
 */
static errval_t pt_alloc(struct paging_state * st, enum objtype type,
                         struct capref *ret)
{
    errval_t err;
    err = st->slot_alloc->alloc(st->slot_alloc, ret);
    if (err_is_fail(err)) {
        debug_printf("slot_alloc failed: %s\n", err_getstring(err));
        return err;
    }
    err = vnode_create(*ret, type);
    if (err_is_fail(err)) {
        debug_printf("vnode_create failed: %s\n", err_getstring(err));
        return err;
    }
    return SYS_ERR_OK;
}

__attribute__((unused)) static errval_t pt_alloc_l1(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l1, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l2(struct paging_state *st,
                                                    struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l2, ret);
}

__attribute__((unused)) static errval_t pt_alloc_l3(struct paging_state * st, struct capref *ret)
{
    return pt_alloc(st, ObjType_VNode_AARCH64_l3, ret);
}


errval_t paging_refill_slabs(struct paging_state *st)
{
    if (!st->page_table_slab_refilling && slab_freecount(&st->page_table_slabs) <= 20) {
        st->page_table_slab_refilling = true;

        struct capref frame;
        errval_t err;
        err = st->slot_alloc->alloc(st->slot_alloc, &frame);
        if (err_is_fail(err)) {
            debug_printf("slot_alloc failed: %s\n", err_getstring(err));
            st->page_table_slab_refilling = false;
            return err_push(err, LIB_ERR_SLOT_ALLOC);
        }

        err = slab_refill_no_pagefault(&st->page_table_slabs, frame,
                                       sizeof(struct page_table) * 32);
        st->page_table_slab_refilling = false;
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
    }


    if (!st->free_list_slab_refilling
        && slab_freecount(&st->used_and_free_list_slabs) <= 32) {
        st->free_list_slab_refilling = true;
        errval_t err = slab_default_refill(&st->used_and_free_list_slabs);
        st->free_list_slab_refilling = false;
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
    }


    if (!st->cap_store_slab_refilling && slab_freecount(&st->cap_store_slabs) <= 16) {
        st->cap_store_slab_refilling = true;
        errval_t err = slab_default_refill(&st->cap_store_slabs);
        st->cap_store_slab_refilling = false;
        if (err_is_fail(err)) {
            return err_push(err, LIB_ERR_SLAB_REFILL);
        }
    }


    return SYS_ERR_OK;
}

static void return_mem_cap(struct capref mem_cap)
{
    // TODO: free the mem cap:
    // DEBUG_PRINTF("TODO: Free the mem_cap from the lazy memory\n");
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging
 *        state of the calling process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state(struct paging_state *st, lvaddr_t start_vaddr,
                           struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    assert(st != NULL);

    st->slot_alloc = ca;
    st->start_vaddr = start_vaddr;
    st->l0_ptable.cap = pdir;
    st->l0_ptable.type = ObjType_VNode_AARCH64_l0;
    for (size_t i = 0; i < PTABLE_ENTRIES; i++) {
        st->l0_ptable.children[i] = NULL;
    }

    st->free_list_slab_refilling = false;
    st->page_table_slab_refilling = false;

    slab_init(&st->used_and_free_list_slabs, USED_AND_FREE_LIST_BLOCK_SIZE, NULL);
    slab_grow(&st->used_and_free_list_slabs, st->init_used_and_free_list_slabs_space,
              sizeof(st->init_used_and_free_list_slabs_space));

    slab_init(&st->page_table_slabs, sizeof(struct page_table), NULL);
    slab_grow(&st->page_table_slabs, st->init_page_table_slabs_space,
              sizeof(st->init_page_table_slabs_space));

    slab_init(&st->cap_store_slabs, CAP_STORE_SLAB_BLOCKSIZE, NULL);
    slab_grow(&st->cap_store_slabs, st->init_cap_store_slabs_space,
              sizeof(st->init_cap_store_slabs_space));

    // Use all of the 48 bit address space.
    ssize_t region_size = BIT(48);
    errval_t err = free_list_init(&st->free_list, &st->used_and_free_list_slabs,
                                  start_vaddr, region_size, true);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FREE_LIST_INIT);

    used_list_init(&st->lazy_mapped, &st->used_and_free_list_slabs);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_USED_LIST_INIT);

    cap_store_init(&st->lazy_mem_cap_store, &st->cap_store_slabs, return_mem_cap);

    return SYS_ERR_OK;
}

/**
 * TODO(M2): Implement this function.
 * TODO(M4): Improve this function.
 * \brief Initialize the paging_state struct for the paging state
 *        of a child process.
 *
 * \param st The struct to be initialized, must not be NULL.
 * \param start_vaddr Virtual address allocation should start at
 *        this address.
 * \param pdir Reference to the cap of the L0 VNode.
 * \param ca The slot_allocator to be used by the paging state.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t paging_init_state_foreign(struct paging_state *st, lvaddr_t start_vaddr,
                                   struct capref pdir, struct slot_allocator *ca)
{
    // TODO (M2): Implement state struct initialization
    // TODO (M4): Implement page fault handler that installs frames when a page fault
    // occurs and keeps track of the virtual address space.
    return paging_init_state(st, start_vaddr, pdir, ca);
}

void paging_state_destroy(struct paging_state *st) {
    free_list_destroy(&st->free_list);
    used_list_destroy(&st->lazy_mapped);
}

errval_t static get_region_size(struct paging_state *st, lvaddr_t vaddr,
                                size_t *res_reg_size)
{
    const size_t slot_for_level[4] = { VMSAv8_64_L0_INDEX(vaddr),
                                       VMSAv8_64_L1_INDEX(vaddr),
                                       VMSAv8_64_L2_INDEX(vaddr),
                                       VMSAv8_64_L3_INDEX(vaddr) };
    struct page_table *cur_pt = &st->l0_ptable;

    for (size_t i = 0; i < 4; i++) {
        size_t slot = slot_for_level[i];
        *res_reg_size = cur_pt->region_size[slot];
        if (cur_pt->children[slot] == NULL) {
            // Child is either not mapped or we found a super page mapping.
            break;
        }
        cur_pt = cur_pt->children[slot];
    }


    if (*res_reg_size == 0) {
        return LIB_ERR_PMAP_NOT_MAPPED;
    }
    return SYS_ERR_OK;
}

static errval_t handle_pagefault(void *addr)
{
    if (addr < (void *)BASE_PAGE_SIZE) {
        return LIB_ERR_PMAP_HANDLE_PAGEFAULT_ADDR_NULLPOINTER;
    }
    thread_mutex_lock_nested(&paging_mutex);

    errval_t err = SYS_ERR_OK;
    struct paging_state *st = get_current_paging_state();

    size_t base, size;
    used_region_type_t region_type;
    err = used_list_get_region(&st->lazy_mapped, (lvaddr_t)addr, &base, &size,
                               &region_type);
    if (err == LIB_ERR_USED_LIST_REGION_NOT_FOUND) {
        err = LIB_ERR_PMAP_HANDLE_PAGEFAULT_ADDR_NO_MAPPED;
        goto end;
    }
    PUSH_GOTO_IF_ERR(err, LIB_ERR_USED_LIST_GET_REGION, end);

    lvaddr_t rounded_addr = ROUND_DOWN((lvaddr_t)addr, BASE_PAGE_SIZE);

    size_t used_size;
    err = get_region_size(st, (lvaddr_t)rounded_addr, &used_size);
    if (err == SYS_ERR_OK) {
        // A other thread mapped this in the mean time, so we can just return.
        goto end;
    }

    if (region_type == REGION_TYPE_STACK) {
        if ((lvaddr_t)addr < base + BASE_PAGE_SIZE) {
            // We hit the guard page of the stack.
            USER_PANIC("Stack overflow detected!\n");
        }
    }

    struct cap_list_header *cap_list;
    cap_store_get_active(&st->lazy_mem_cap_store, base, &cap_list);
    if (capref_is_null(cap_list->active_cap)) {
        struct capref frame;
        err = frame_alloc(&frame, LAZY_MAP_CAP_SIZE, NULL);
        if(err_is_fail(err)) { 
            DEBUG_PRINTF("OUT OF MEMORY?: ERR CODE: %lu\n", err);
        }
        PUSH_GOTO_IF_ERR(err, LIB_ERR_FRAME_ALLOC, end);
        cap_list->active_cap = frame;
        cap_list->offset = 0;
    }


    err = paging_map_fixed_attr_internal(st, rounded_addr, cap_list->active_cap,
                                         cap_list->offset, BASE_PAGE_SIZE,
                                         VREGION_FLAGS_READ_WRITE);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_MAP, end);
    cap_list->offset += BASE_PAGE_SIZE;

    if (cap_list->offset == LAZY_MAP_CAP_SIZE) {
        push_back_active(&st->lazy_mem_cap_store, cap_list);
    }

    paging_refill_slabs(st);


end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}


static void exception_handler(enum exception_type type, int subtype, void *addr,
                              arch_registers_state_t *regs)
{
    if (type == EXCEPT_PAGEFAULT) {
        errval_t err = handle_pagefault(addr);
        if (err_is_fail(err)) {
            USER_PANIC_ERR(err,
                           ": unhandled page fault (error code 0x%" PRIxPTR
                           ") on %" PRIxPTR " at IP %" PRIxPTR "\n",
                           type, addr, registers_get_ip(regs));
        }
    } else {
        USER_PANIC(": unhandled exception (error code 0x%" PRIxPTR ") on %" PRIxPTR
                   " at IP %" PRIxPTR "\n",
                   type, addr, registers_get_ip(regs));
    }
}

/**
 * @brief This function initializes the paging for this domain
 *
 * Note: The function is called once before main.
 */
errval_t paging_init(void)
{
    // TODO (M2): Call paging_init_state for &current
    // TODO (M4): initialize self-paging handler
    // TIP: use thread_set_exception_handler() to setup a page fault handler
    // TIP: Think about the fact that later on, you'll have to make sure that
    // you can handle page faults in any thread of a domain.
    // TIP: it might be a good idea to call paging_init_state() from here to
    // avoid code duplication.

    struct capref root_ptable = { .cnode = cnode_page, .slot = 0 };

    // By starting with VADDR_OFFSET we skip the first entry in the L0 page_table,
    // which is already mapped.
    errval_t err = paging_init_state(&current, VADDR_OFFSET, root_ptable,
                                     get_default_slot_allocator());
    if (err_is_fail(err)) {
        return err;
    }

    thread_mutex_init(&paging_mutex);

    void *stack_top = stack_first + EXCEPTION_STACK_SIZE;
    stack_top = (void *)ALIGNED_STACK_TOP(stack_top);

    err = thread_set_exception_handler(exception_handler, NULL, stack_first, stack_top,
                                       NULL, NULL);
    RETURN_IF_ERR(err);

    set_current_paging_state(&current);

    return SYS_ERR_OK;
}


/**
 * @brief Initializes the paging functionality for the calling thread
 *
 * @param[in] t   the tread to initialize the paging state for.
 *
 * This function prepares the thread to handing its own page faults
 */
errval_t paging_init_onthread(struct thread *t)
{
    // TODO (M4):
    //   - setup exception handler for thread `t'.
    struct capref cap;
    size_t retbytes;
    errval_t err = frame_alloc(&cap, EXCEPTION_STACK_SIZE, &retbytes);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    void *exception_stack;
    err = paging_map_frame(get_current_paging_state(), &exception_stack, retbytes, cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_VSPACE_MAP);

    t->exception_handler = exception_handler;
    t->exception_stack = exception_stack;
    t->exception_stack_top = (void *)ALIGNED_STACK_TOP(exception_stack
                                                       + EXCEPTION_STACK_SIZE);
    return SYS_ERR_OK;
}


/**
 * @brief Find a free region of virtual address space that is large enough to accomodate a
 *        buffer of size 'bytes'.
 *
 * @param[in]  st          A pointer to the paging state to allocate from
 * @param[out] buf         Returns the free virtual address that was found.
 * @param[in]  bytes       The requested (minimum) size of the region to allocate
 * @param[in]  alignment   The address needs to be a multiple of 'alignment'.
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
errval_t paging_alloc(struct paging_state *st, void **buf, size_t bytes, size_t alignment)
{
    /**
     * TODO(M2): Implement this function
     *   - Find a region of free virtual address space that is large enough to
     *     accommodate a buffer of size `bytes`.
     */
    thread_mutex_lock_nested(&paging_mutex);

    genvaddr_t base;
    *buf = NULL;

    errval_t err = free_list_alloc_next(&st->free_list, bytes, alignment, &base);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_FREE_LIST_ALLOC, end);
    *buf = (void *)base;
end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}

/**
 * @brief mapps the provided frame at the supplied address in the paging state
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] vaddr   the virtual address to create the mapping at does not check that
 * this is actually free.
 * @param[in] frame   the frame to map in
 * @param[in] bytes   the number of bytes that will be mapped.
 * @param[in] flags   The flags that are to be set for the newly mapped region,
 *                    see 'paging_flags_t' in paging_types.h .
 *
 * @return SYS_ERR_OK on success.
 */
errval_t static paging_map_fixed_attr_internal(struct paging_state *st, lvaddr_t vaddr,
                                               struct capref frame, size_t frame_offset,
                                               size_t bytes, int flags)
{
    thread_mutex_lock_nested(&paging_mutex);

    struct capability c;
    errval_t err = cap_direct_identify(frame, &c);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_FRAME_IDENTIFY, end);

    assert(c.type == ObjType_Frame || c.type == ObjType_DevFrame);

    genpaddr_t paddr = c.u.frame.base;

    size_t region_size_flag = bytes;
    size_t base_pages_to_map = bytes / BASE_PAGE_SIZE;
    while (bytes >= BASE_PAGE_SIZE) {
        struct page_table *cur_pt = &st->l0_ptable;

        // DEBUG_PRINTF("Mapping %lu to %lu of size %lu \n", paddr, vaddr, bytes);

        bool map_super_page = bytes >= LARGE_PAGE_SIZE && (vaddr % LARGE_PAGE_SIZE) == 0
                              && (paddr % LARGE_PAGE_SIZE) == 0;

        // DEBUG_PRINTF("Mapping map_super_page: %lu\n", map_super_page);

        const size_t slot_for_level[4] = { VMSAv8_64_L0_INDEX(vaddr),
                                           VMSAv8_64_L1_INDEX(vaddr),
                                           VMSAv8_64_L2_INDEX(vaddr),
                                           VMSAv8_64_L3_INDEX(vaddr) };

        size_t iterations = map_super_page ? 3 : 4;
        size_t mappig_count = 1;

        for (size_t i = 0; i < iterations; i++) {
            size_t slot = slot_for_level[i];
            struct page_table *res_pt = NULL;
            if (i == 3) {
                mappig_count = VMSAv8_64_PTABLE_NUM_ENTRIES - slot;
                if (mappig_count > base_pages_to_map) {
                    mappig_count = base_pages_to_map;
                }
            }
            err = paging_map(st, cur_pt, slot, mappig_count, frame, frame_offset,
                             map_super_page, flags, region_size_flag, &res_pt);
            // DEBUG_PRINTF("Freecount after pmap: %lu
            // \n",slab_freecount(&st->page_table_slabs)); DEBUG_PRINTF("AT level %lu", i);
            if (err_is_fail(err)) {
                // DEBUG_ERR(err, "Err in paging at level: %lu.\n", i);
                goto end;
            }
            cur_pt = res_pt;
        }

        base_pages_to_map -= mappig_count;

        size_t mapped_pages = map_super_page ? LARGE_PAGE_SIZE : BASE_PAGE_SIZE;
        size_t mapped_size = mappig_count * mapped_pages;

        vaddr += mapped_size;
        paddr += mapped_size;
        bytes -= mapped_size;
        frame_offset += mapped_size;
        region_size_flag = 0;

        paging_refill_slabs(st);
    }
end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}

errval_t paging_map_lazy(struct paging_state *st, void **buf, size_t bytes,
                         size_t alignment, int flags, used_region_type_t region_type)
{
    // TODO: use the flags by storing it in the used list.
    thread_mutex_lock_nested(&paging_mutex);

    errval_t err = SYS_ERR_OK;
    err = paging_alloc(st, buf, bytes, alignment);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_ALLOC, end);

    err = used_list_add_region(&st->lazy_mapped, (size_t)*buf, bytes, region_type);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_USED_LIST_ADD_REGION, end);
end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}

/**
 * \brief Finds a free virtual address and maps `bytes` of the supplied frame at that address
 *
 * @param[in]  st      the paging state to create the mapping in
 * @param[out] buf     returns the virtual address at which this frame has been mapped.
 * @param[in]  bytes   the number of bytes to map.
 * @param[in]  frame   the frame capability to be mapped
 * @param[in]  flags   The flags that are to be set for the newly mapped region,
 *                     see 'paging_flags_t' in paging_types.h .
 *
 * @return Either SYS_ERR_OK if no error occured or an error indicating what went wrong
 * otherwise.
 */
errval_t paging_map_frame_attr(struct paging_state *st, void **buf, size_t bytes,
                               struct capref frame, int flags)
{
    // TODO(M2):
    // - Find and allocate free region of virtual address space of at least bytes in size.
    // - Map the user provided frame at the free virtual address
    // - return the virtual address in the buf parameter
    //
    // Hint:
    //  - think about what mapping configurations are actually possible
    thread_mutex_lock_nested(&paging_mutex);

    errval_t err = SYS_ERR_OK;

    err = paging_alloc(st, buf, bytes, BASE_PAGE_SIZE);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_ALLOC, end);

    // TODO: if paging_map_fixed_attr_internal fails should we return the space
    // to the free list in paging_alloc.
    err = paging_map_fixed_attr_internal(st, (lvaddr_t)*buf, frame, 0, bytes, flags);
end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}


errval_t paging_map(struct paging_state *st, struct page_table *pt, size_t slot,
                    size_t mapping_count, struct capref frame, size_t frame_offset,
                    bool map_super_page, int flags, size_t region_size_flag,
                    struct page_table **next_level_res)
{
    thread_mutex_lock_nested(&paging_mutex);
    errval_t err = SYS_ERR_OK;

    if (pt->children[slot] != NULL) {
        *next_level_res = pt->children[slot];
        goto end;
    }

    if (!capref_is_null(pt->children_mapping[slot])) {
        // This is a super page mapping.
        // Think about super page size in vnode map
        if (pt->type == ObjType_VNode_AARCH64_l2) {
            err = LIB_ERR_PMAP_MAPPING_SUPERPAGE_ALREADY;
            goto end;
        } else {
            err = LIB_ERR_PMAP_EXISTING_MAPPING;
            goto end;
        }
    }

    // Child PT does not exist so we need to create it.
    struct capref child_cap;
    enum objtype child_type = ObjType_Null;
    size_t offset = 0;
    if (pt->type == ObjType_VNode_AARCH64_l3) {
        // Children should be the frame.
        child_cap = frame;
        offset = frame_offset;
    } else if (pt->type == ObjType_VNode_AARCH64_l2 && map_super_page) {
        // Children should be the frame as well.
        child_cap = frame;
        offset = frame_offset;
    } else {
        // We only want to set this if we map to a frame.
        region_size_flag = 0;
        if (pt->type == ObjType_VNode_AARCH64_l0) {
            child_type = ObjType_VNode_AARCH64_l1;
        } else if (pt->type == ObjType_VNode_AARCH64_l1) {
            child_type = ObjType_VNode_AARCH64_l2;
        } else if (pt->type == ObjType_VNode_AARCH64_l2) {
            child_type = ObjType_VNode_AARCH64_l3;
        } else {
            err = LIB_ERR_PMAP_MAP_LEVEL;
            goto end;
        }

        err = pt_alloc(st, child_type, &child_cap);
        PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_ALLOC_VNODE, end);
        // PT alloc might have caused a recursive slab_refill
        // which might have created the child already.
        if (pt->children[slot] != NULL) {
            cap_destroy(child_cap);
            *next_level_res = pt->children[slot];
            goto end;
        }
    }

    struct capref mapping;
    err = st->slot_alloc->alloc(st->slot_alloc, &mapping);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_SLOT_ALLOC, end);

    // slot alloc might have caused a recursive slab_refill
    // which might have created the child already.
    if (pt->children[slot] != NULL) {
        cap_destroy(child_cap);
        st->slot_alloc->free(st->slot_alloc, mapping);
        *next_level_res = pt->children[slot];
        err = SYS_ERR_OK;
        goto end;
    }

    pt->children_mapping[slot] = mapping;
    pt->region_size[slot] = region_size_flag;

    err = vnode_map(pt->cap, child_cap, slot, flags, offset, mapping_count,
                    pt->children_mapping[slot]);
    if (err_is_fail(err)) {
        st->slot_alloc->free(st->slot_alloc, pt->children_mapping[slot]);
        PUSH_GOTO_IF_ERR(err, LIB_ERR_VNODE_MAP, end);
    }


    if (child_type != ObjType_Null) {
        // Cannot cause refill since we call refill early enough.
        pt->children[slot] = slab_alloc(&st->page_table_slabs);

        if (pt->children[slot] == NULL) {
            // TODO: Possibly clean up?
            err = LIB_ERR_SLAB_ALLOC_FAIL;
            goto end;
        }

        // Sett all pointers and children to NULL.
        memset(pt->children[slot], 0, sizeof(struct page_table));

        pt->children[slot]->type = child_type;
        pt->children[slot]->cap = child_cap;

        *next_level_res = pt->children[slot];
    } else {
        *next_level_res = NULL;
    }

end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}

/**
 * @brief mapps the provided frame at the supplied address in the paging state
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] vaddr   the virtual address to create the mapping at
 * @param[in] frame   the frame to map in
 * @param[in] bytes   the number of bytes that will be mapped.
 * @param[in] flags   The flags that are to be set for the newly mapped region,
 *                    see 'paging_flags_t' in paging_types.h .
 *
 * @return SYS_ERR_OK on success.
 */
errval_t paging_map_fixed_attr(struct paging_state *st, lvaddr_t vaddr,
                               struct capref frame, size_t bytes, int flags)
{
    // We call paging_map_fixed_attr_internal after checking that the vaddr is
    // actually free and to also remove it from the free list.
    thread_mutex_lock_nested(&paging_mutex);

    errval_t err = SYS_ERR_OK;
    err = free_list_alloc_region(&st->free_list, vaddr, bytes);

    if (err == LIB_ERR_FREE_LIST_ADDR_NOT_FREE) {
        err = LIB_ERR_PMAP_ADDR_NOT_FREE;
        goto end;
    } else
        PUSH_GOTO_IF_ERR(err, LIB_ERR_FREE_LIST_ALLOC_REGION, end);

    err = paging_map_fixed_attr_internal(st, vaddr, frame, 0, bytes, flags);

end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}


errval_t static paging_unmap_single(struct paging_state *st, struct page_table *pt,
                                    size_t slot, bool mapped_lazily)
{
    thread_mutex_lock_nested(&paging_mutex);
    errval_t err = SYS_ERR_OK;
    if (capref_is_null(pt->children_mapping[slot])) {
        // We need to check for null since we dont store a mapping in every slot.
        // TODO: We should be able to optimize this and only call this functions on actual
        // mappings.
        goto end;
    }
    err = vnode_unmap(pt->cap, pt->children_mapping[slot]);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_VNODE_UNMAP, end);

    err = cap_delete(pt->children_mapping[slot]);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_CAP_DELETE, end);

    // TODO: This might not be required, since cap_delete might do this.
    err = st->slot_alloc->free(st->slot_alloc, pt->children_mapping[slot]);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_SLOT_FREE, end);

    // Now actually free the child page_table
    slab_free(&st->page_table_slabs, pt->children[slot]);

    pt->children[slot] = NULL;
    pt->children_mapping[slot] = NULL_CAP;
    pt->region_size[slot] = 0;

end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}

static errval_t paging_unmap_rec(struct paging_state *st, struct page_table *cur_pt,
                                 size_t level, const size_t slot_for_level[4],
                                 bool mapped_lazily, size_t *un_map_size)
{
    const static size_t level_to_size[4] = { VMSAv8_64_L0_SIZE, VMSAv8_64_L1_BLOCK_SIZE,
                                             VMSAv8_64_L2_BLOCK_SIZE,
                                             VMSAv8_64_BASE_PAGE_SIZE };
    errval_t err;

    size_t slot = slot_for_level[level];
    if (cur_pt->children[slot] == NULL) {
        if (!capref_is_null(cur_pt->children_mapping[slot])) {
            // This is is a super or normal page mapping.
            assert(level == 2 || level == 3);
            err = paging_unmap_single(st, cur_pt, slot, mapped_lazily);
            RETURN_IF_ERR(err);
            *un_map_size = level_to_size[level];
        } else if (mapped_lazily) {
            // There is nothing mapped so we can progress the hole pt.
            *un_map_size = level_to_size[level];
        } else {
            // This happens due to the fact that we create a bigger mapping in an earlier slot.
            *un_map_size = level_to_size[level];
        }
    } else {
        assert(level < 3);
        err = paging_unmap_rec(st, cur_pt->children[slot], level + 1, slot_for_level,
                               mapped_lazily, un_map_size);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_UNMAP_REC);
    }
    return SYS_ERR_OK;
}

/**
 * @brief Unmaps the region starting at the supplied pointer.
 *
 * @param[in] st      the paging state to create the mapping in
 * @param[in] region  starting address of the region to unmap
 *
 * @return SYS_ERR_OK on success, or error code indicating the kind of failure
 *
 * The supplied `region` must be the start of a previously mapped frame.
 */
errval_t paging_unmap(struct paging_state *st, const void *region)
{
    errval_t err;
    lvaddr_t vaddr = (lvaddr_t)region;
    thread_mutex_lock_nested(&paging_mutex);

    size_t bytes;
    // Check if the memory was mapped lazily.
    bool mapped_lazily;
    err = used_list_get_region(&st->lazy_mapped, vaddr, NULL, &bytes, NULL);
    if (err == LIB_ERR_USED_LIST_REGION_NOT_FOUND) {
        mapped_lazily = false;
        err = get_region_size(st, vaddr, &bytes);
        GOTO_IF_ERR(err, end);
    } else {
        PUSH_GOTO_IF_ERR(err, LIB_ERR_USED_LIST_GET_REGION, end);
        mapped_lazily = true;
        err = used_list_remove_region(&st->lazy_mapped, vaddr);
        cap_store_free(&st->lazy_mem_cap_store, vaddr);
    }

    err = free_list_add_free(&st->free_list, (size_t)region, bytes);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_FREE_LIST_ADD_FREE, end);

    do {
        struct page_table *cur_pt = &st->l0_ptable;
        const size_t slot_for_level[4] = { VMSAv8_64_L0_INDEX(vaddr),
                                           VMSAv8_64_L1_INDEX(vaddr),
                                           VMSAv8_64_L2_INDEX(vaddr),
                                           VMSAv8_64_L3_INDEX(vaddr) };

        size_t un_mpa_size = 0;

        err = paging_unmap_rec(st, cur_pt, 0, slot_for_level, mapped_lazily, &un_mpa_size);
        PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_UNMAP_REC, end);

        vaddr += un_mpa_size;
        bytes -= un_mpa_size;
    } while (bytes >= BASE_PAGE_SIZE);

end:
    thread_mutex_unlock(&paging_mutex);
    return err;
}
