#include <errors/errno.h>


#include <aos/free_list.h>
#include <sys/cdefs.h>
#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/slab.h>
#include <aos/macros.h>


errval_t free_list_init(struct free_list *fl, struct slab_allocator *slabs, size_t base,
                        size_t size, bool circulate)
{
    fl->base = base;
    fl->size = size;
    fl->slabs = slabs;
    fl->circulate = circulate;

    // TODO return error on Nullptr result.
    struct free_list_node *new_free_node = (struct free_list_node *)slab_alloc(slabs);
    if (new_free_node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    new_free_node->base = base;
    new_free_node->size = size;
    new_free_node->next = NULL;
    new_free_node->prev = (struct free_list_node *)fl;

    fl->next = new_free_node;
    fl->alloc_pos = new_free_node;

    return SYS_ERR_OK;
}

errval_t free_list_destroy(struct free_list *fl) {
    struct free_list_node *curr = fl->next;
    struct free_list_node *next = NULL;

    while (curr != NULL) {
        next = curr->next;
        slab_free(fl->slabs, curr);
        curr = next;
    }

    return SYS_ERR_OK;
}

errval_t free_list_create_and_insert_node_after(struct free_list *fl,
                                                struct free_list_node *after, size_t base,
                                                size_t size)
{
    struct free_list_node *new_free_node = slab_alloc(fl->slabs);
    if (new_free_node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }

    new_free_node->base = base;
    new_free_node->size = size;

    new_free_node->next = after->next;
    new_free_node->prev = after;

    if (after->next != NULL) {
        after->next->prev = new_free_node;
    }
    after->next = new_free_node;

    return SYS_ERR_OK;
}

void free_list_remove_and_free_node(struct free_list *fl, struct free_list_node *to_delete)
{
    if (to_delete->next != NULL) {
        to_delete->next->prev = to_delete->prev;
    }
    to_delete->prev->next = to_delete->next;
    slab_free(fl->slabs, to_delete);
}

errval_t static cut_front_and_back(struct free_list *fl, struct free_list_node *node,
                                   size_t before_size, size_t size)
{
    bool cut_front = before_size != 0;
    bool cut_back = node->size >= (size + before_size);

    if (cut_front && cut_back) {
        // Have 2 nodes instead of node
        // Use node for first one and insert on after it.
        size_t r_base = node->base + size + before_size;
        ;
        size_t r_size = node->size - (size + before_size);
        errval_t err = free_list_create_and_insert_node_after(fl, node, r_base, r_size);
        RETURN_IF_ERR(err);


        node->base = node->base;
        node->size = before_size;
    } else if (cut_front) {
        // Have 1 node instead of
        node->base = node->base;
        node->size = before_size;
    } else if (cut_back) {
        // Have 1 node instead of

        node->base = node->base + size + before_size;
        node->size = node->size - (size + before_size);
    } else {
        // Have 0 nodes instead of node
        // Delete node
        free_list_remove_and_free_node(fl, node);
    }
    return SYS_ERR_OK;
}


errval_t free_list_alloc_region(struct free_list *fl, size_t base, size_t size)
{
    struct free_list_node *cur = fl->next;
    while (cur != NULL) {
        if (cur->base <= base && base + size <= cur->base + cur->size) {
            return cut_front_and_back(fl, cur, base - cur->base, size);
        }
        cur = cur->next;
    }
    return LIB_ERR_FREE_LIST_ADDR_NOT_FREE;
}

errval_t free_list_get_region(struct free_list *fl, size_t pos, size_t *base, size_t *size)
{
    struct free_list_node *cur = fl->next;
    while (cur != NULL) {
        if (cur->base <= pos && pos <= cur->base + cur->size) {
            if (base != NULL) {
                *base = cur->base;
            }
            if (size != NULL) {
                *size = cur->size;
            }
            return SYS_ERR_OK;
        }
        cur = cur->next;
    }
    return LIB_ERR_FREE_LIST_ADDR_NOT_FREE;
}


errval_t free_list_alloc_next(struct free_list *fl, size_t size, size_t alignment,
                              size_t *base)
{
    struct free_list_node *begin = fl->alloc_pos;

    size_t alignment_space = 0;
    bool itered = false;
    do {
        alignment_space = (alignment - fl->alloc_pos->base % alignment) % alignment;
        if (fl->alloc_pos->size >= (size + alignment_space)) {
            break;
        }
        itered = true;
        fl->alloc_pos = fl->alloc_pos->next;
        if (fl->alloc_pos == NULL) {
            fl->alloc_pos = fl->next;
            if (!fl->circulate) {
                if (begin == fl->next) {
                    // We started at the beginning so there is no more space.
                    return LIB_ERR_FREE_LIST_NO_SPACE;
                } else {
                    // We reached the end of the list and could not find the result
                    return LIB_ERR_FREE_LIST_NO_NEXT;
                }
            }
        }
    } while (begin != fl->alloc_pos);
    if (itered && begin == fl->alloc_pos) {
        return LIB_ERR_FREE_LIST_NO_SPACE;
    }

    *base = fl->alloc_pos->base + alignment_space;

    return cut_front_and_back(fl, fl->alloc_pos, alignment_space, size);
}

errval_t free_list_add_free(struct free_list *fl, size_t base, size_t bytes)
{
    struct free_list_node *free_pos = (struct free_list_node *)fl;
    while (free_pos) {
        if (free_pos->next != NULL && free_pos->next->base <= base
            && base < free_pos->next->base + free_pos->next->size) {
            // This means we overlap with the next entry.
            // This means some kind of double free happened.
            return LIB_ERR_FREE_LIST_DOUBLE_FREE;
        }

        bool merge_with_next = free_pos->next != NULL
                               && base + bytes == free_pos->next->base;
        if (free_pos->base + free_pos->size == base) {
            // Merge with free_pos
            free_pos->size += bytes;
            if (merge_with_next) {
                // We merge with left and right.
                if (fl->alloc_pos == free_pos->next) {
                    fl->alloc_pos = free_pos;
                }
                free_pos->size += free_pos->next->size;
                free_list_remove_and_free_node(fl, free_pos->next);
            }
            return SYS_ERR_OK;
        } else if (merge_with_next) {
            // Merge with free_pos.next
            free_pos->next->base = base;
            free_pos->next->size += bytes;
            return SYS_ERR_OK;
        } else if (free_pos->next == NULL || base < free_pos->next->base) {
            // Insert after free_pos (before free_pos->next)
            errval_t err = free_list_create_and_insert_node_after(fl, free_pos, base,
                                                                  bytes);
            RETURN_IF_ERR(err);
            return SYS_ERR_OK;
        }
        free_pos = free_pos->next;
    }

    assert(false);
    return LIB_ERR_IMPOSSIBLE;
}
