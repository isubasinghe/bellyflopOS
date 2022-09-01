/**
 * \file
 * \brief Local memory allocator for init till mem_serv is ready to use
 */

#include "mem_alloc.h"
#include <mm/mm.h>
#include <aos/paging.h>
#include <aos/macros.h>
#include <grading.h>

/// MM allocator instance data
struct mm aos_mm;

errval_t aos_ram_alloc_aligned(struct capref *ret, size_t size, size_t alignment)
{
    return mm_alloc_aligned(&aos_mm, size, alignment, ret);
}

errval_t aos_ram_free(struct capref cap)
{
    return mm_free(&aos_mm, cap);
}

static inline errval_t initialize_ram_allocator(void)
{
    errval_t err;

    // Init slot allocator
    static struct slot_prealloc init_slot_alloc;
    struct capref cnode_cap = {
        .cnode = {
            .croot = CPTR_ROOTCN,
            .cnode = ROOTCN_SLOT_ADDR(ROOTCN_SLOT_SLOT_ALLOC0),
            .level = CNODE_TYPE_OTHER,
        },
        .slot = 0,
    };
    err = slot_prealloc_init(&init_slot_alloc, cnode_cap, L2_CNODE_SLOTS, &aos_mm);
    PUSH_RETURN_IF_ERR(err, MM_ERR_SLOT_ALLOC_INIT);

    // Initialize aos_mm
    err = mm_init(&aos_mm, ObjType_RAM, slab_default_refill, slot_alloc_prealloc,
                  slot_prealloc_refill, &init_slot_alloc);
    if (err_is_fail(err)) {
        USER_PANIC_ERR(err, "Can't initalize the memory manager.");
    }

    // Give aos_mm a bit of memory for the initialization
    // M1 TODO: grow be with some memory!
    static char slab_init_memory[SLAB_STATIC_SIZE(512, MM_BLOCK_SIZE)];
    slab_grow(&aos_mm.slabs, slab_init_memory, SLAB_STATIC_SIZE(512, MM_BLOCK_SIZE));

    static char slab_init_free_list_memory[SLAB_STATIC_SIZE(512, FREE_LIST_BLOCK_SIZE)];
    slab_grow(&aos_mm.slabs_free_list, slab_init_free_list_memory,
              SLAB_STATIC_SIZE(512, FREE_LIST_BLOCK_SIZE));

    DEBUG_PRINTF("Static memory allocated.\n");

    return SYS_ERR_OK;
}

/**
 * \brief Setups a local memory allocator for init to use till the memory server
 * is ready to be used. Inspects bootinfo for finding memory region.
 */
errval_t initialize_ram_alloc(void)
{
    errval_t err;

    err = initialize_ram_allocator();
    if (err_is_fail(err)) {
        return err;
    }

    // Walk bootinfo and add all RAM caps to allocator handed to us by the kernel
    uint64_t mem_avail = 0;
    struct capref mem_cap = {
        .cnode = cnode_super,
        .slot = 0,
    };

    for (int i = 0; i < bi->regions_length; i++) {
        if (bi->regions[i].mr_type == RegionType_Empty) {
            struct capability c;
            err = cap_direct_identify(mem_cap, &c);
            if (err_is_fail(err)) {
                DEBUG_ERR(err, "failed to get the frame info\n");
            }

            // some santity checks
            assert(c.type == ObjType_RAM);
            assert(c.u.ram.base == bi->regions[i].mr_base);
            assert(c.u.ram.bytes == bi->regions[i].mr_bytes);

            err = mm_add(&aos_mm, mem_cap);
            if (err_is_ok(err)) {
                mem_avail += bi->regions[i].mr_bytes;
            } else {
                DEBUG_ERR(err, "Warning: adding RAM region %d (%p/%zu) FAILED", i,
                          bi->regions[i].mr_base, bi->regions[i].mr_bytes);
            }

            mem_cap.slot++;
        }
    }
    debug_printf("Added %" PRIu64 " MB of physical memory.\n", mem_avail / 1024 / 1024);

    // Finally, we can initialize the generic RAM allocator to use our local allocator
    err = ram_alloc_set(aos_ram_alloc_aligned);
    if (err_is_fail(err)) {
        return err_push(err, LIB_ERR_RAM_ALLOC_SET);
    }

    ram_free_set(aos_ram_free);

    // Grading
    grading_test_mm(&aos_mm);

    return SYS_ERR_OK;
}

errval_t initialize_ram_alloc_app_core(struct capref core_ram_cap)
{
    errval_t err;

    err = initialize_ram_allocator();
    PUSH_RETURN_IF_ERR(err, MM_ERR_SLOT_ALLOC_INIT);

    err = mm_add(&aos_mm, core_ram_cap);
    PUSH_RETURN_IF_ERR(err, MM_ERR_MM_ADD);

    err = ram_alloc_set(aos_ram_alloc_aligned);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_RAM_ALLOC_SET);

    ram_free_set(aos_ram_free);

    return SYS_ERR_OK;
}
