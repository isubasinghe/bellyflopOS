

#include <aos/paging_state_rebase.h>

#include <aos/macros.h>

#include <string.h>

static size_t get_page_table_count(struct page_table *pt)
{
    size_t res = 1;
    for (size_t i = 0; i < PTABLE_ENTRIES; ++i) {
        if (pt->children[i] != NULL) {
            res += get_page_table_count(pt->children[i]);
        }
    }
    return res;
}

size_t rebase_get_page_table_storage_size(struct page_table *pt)
{
    size_t page_table_count = get_page_table_count(pt);
    return page_table_count * sizeof(struct page_table);
}

static errval_t copy_page_tables(struct page_table *dst_base, size_t dst_pos,
                                 size_t *next_alloc, size_t buf_size,
                                 struct page_table *src, struct slot_allocator *slot_alloc)
{
    errval_t err;

    struct page_table *dst = &dst_base[dst_pos];
    dst->type = src->type;

    err = slot_alloc->alloc(slot_alloc, &dst->cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);

    err = cap_copy(dst->cap, src->cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);

    for (size_t i = 0; i < PTABLE_ENTRIES; ++i) {
        dst->region_size[i] = src->region_size[i];
        if (!capref_is_null(src->children_mapping[i])
            && src->type != ObjType_VNode_AARCH64_l3) {
            // We do __not__ copy mappings to BASE_PAGE sized frames (we do for superpages
            // as of convenience and having less edgecases). Copy the mapping:
            err = slot_alloc->alloc(slot_alloc, &dst->children_mapping[i]);
            PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);

            err = cap_copy(dst->children_mapping[i], src->children_mapping[i]);
            PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);
        }
        if (src->children[i] != NULL) {
            size_t child_pos = *next_alloc;
            // TODO: Maybe this should be an ERROR.
            assert(child_pos < buf_size);
            dst->children[i] = (struct page_table *)child_pos;
            *next_alloc = *next_alloc + 1;
            err = copy_page_tables(dst_base, child_pos, next_alloc, buf_size,
                                   src->children[i], slot_alloc);
            RETURN_IF_ERR(err);
        } else {
            dst->children[i] = NULL;
        }
    }
    return SYS_ERR_OK;
}


/**
 * \brief Create a new frame to copy the page table into, with relative addresses.
 *
 * \param pst       The paging state to copy.
 * \param buf       Buffer to write the serialised paging state into.
 * \param buf_size  Size of the buffer.
 * \param slot_alloc Slot allocator to allocate slots for capapbilites in the
 * child pagecn space.
 *
 * \return Either SYS_ERR_OK if no error occured or an error indicating what
 * went wrong otherwise.
 */
errval_t rebase_to_relative_frame(struct paging_state *pst, void *buf, size_t buf_size,
                                  struct slot_allocator *slot_alloc)
{
    assert(pst != NULL);
    assert(buf != NULL);

    memset(buf, 0, buf_size);

    struct page_table *base = buf;
    buf_size = buf_size / sizeof(struct page_table *);

    // Position 0 is used in the call below for the L0 page table, that's why we set
    // next_alloc to 1.
    size_t next_alloc = 1;
    errval_t err = copy_page_tables(base, 0, &next_alloc, buf_size, &pst->l0_ptable,
                                    slot_alloc);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_REBASE_COPY_PTABLE);
    return SYS_ERR_OK;
}


void static fix_pointers_to_vaddrs(struct page_table *pst_base, struct page_table *cur)
{
    for (size_t i = 0; i < PTABLE_ENTRIES; ++i) {
        if (cur->children[i] != NULL) {
            struct page_table *child = &pst_base[(size_t)cur->children[i]];
            cur->children[i] = child;
            fix_pointers_to_vaddrs(pst_base, cur->children[i]);
        }
    }
}

void reconstruct_page_table(struct page_table *pt)
{
    fix_pointers_to_vaddrs(pt, pt);
}


static void print_mappings_addr(struct page_table *pt, lvaddr_t cur_address, size_t level)
{
    for (size_t slot = 0; slot < PTABLE_ENTRIES; ++slot) {
        if (pt->region_size[slot] != 0) {
            lvaddr_t child_addr = (cur_address << VMSAv8_64_PTABLE_BITS) | slot;
            bool is_super_page = level == 2;
            size_t shift_by = is_super_page ? VMSAv8_64_L2_BLOCK_BITS
                                            : VMSAv8_64_BASE_PAGE_BITS;
            __unused lvaddr_t address = child_addr << shift_by;
            DEBUG_PRINTF("At address %lu a region of size %lu was mapped at level %lu in "
                         "slot %lu.\n",
                         address, pt->region_size[slot], level, slot);
        } else if (pt->children[slot] != NULL) {
            lvaddr_t child_addr = (cur_address << VMSAv8_64_PTABLE_BITS) | slot;
            print_mappings_addr(pt->children[slot], child_addr, level + 1);
        }
    }
}

void print_mappings(struct page_table *pt)
{
    DEBUG_PRINTF("Printing Page Table:\n");
    print_mappings_addr(pt, 0, 0);
    DEBUG_PRINTF("Printing Page Table done!\n\n");
}
