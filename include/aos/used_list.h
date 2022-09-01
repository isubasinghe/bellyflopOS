

#ifndef AOS_UL_H
#define AOS_UL_H

#include <errors/errno.h>
#include <aos/types.h>
#include <aos/free_list.h>


__BEGIN_DECLS

typedef enum used_region_type {
    REGION_TYPE_STACK,
    REGION_TYPE_HEAP,
    REGION_TYPE_UNKNOWN
} used_region_type_t;

struct used_list_node {
    struct used_list_node *next;
    size_t base;
    size_t bytes;
    used_region_type_t region_type;
};

#define USED_LIST_BLOCK_SIZE sizeof(struct used_list_node)
struct used_list {
    struct used_list_node *head;
    struct slab_allocator *slabs;
};

inline void used_list_init(struct used_list *ul, struct slab_allocator *slabs)
{
    ul->head = NULL;
    ul->slabs = slabs;
}

inline void used_list_destroy(struct used_list *ul) {
    struct used_list_node *curr = ul->head;
    while (curr != NULL) {
        struct used_list_node *next = curr->next;
        slab_free(ul->slabs, curr);
        curr = next;
    }
}

inline errval_t used_list_add_region(struct used_list *ul, size_t base, size_t bytes,
                                     used_region_type_t region_type)
{
    struct used_list_node *new_used_node = slab_alloc(ul->slabs);
    if (new_used_node == NULL) {
        return LIB_ERR_SLAB_ALLOC_FAIL;
    }
    new_used_node->base = base;
    new_used_node->bytes = bytes;
    new_used_node->region_type = region_type;
    new_used_node->next = ul->head;
    ul->head = new_used_node;
    return SYS_ERR_OK;
}

inline errval_t used_list_remove_region(struct used_list *ul, size_t base)
{
    struct used_list_node *curr = ul->head;
    struct used_list_node *prev = NULL;
    while (curr != NULL) {
        if (curr->base == base) {
            if (prev == NULL) {
                ul->head = curr->next;
            } else {
                prev->next = curr->next;
            }
            slab_free(ul->slabs, curr);
            return SYS_ERR_OK;
        }
        prev = curr;
        curr = curr->next;
    }
    return LIB_ERR_USED_LIST_REGION_NOT_FOUND;
}

inline void used_list_print(struct used_list *ul)
{
    struct used_list_node *curr = ul->head;
    while (curr != NULL) {
        printf("base: %zu, bytes: %zu\n", curr->base, curr->bytes);
        curr = curr->next;
    }
}

inline errval_t used_list_get_region(struct used_list *ul, size_t pos, size_t *base,
                                     size_t *bytes, used_region_type_t *region_type)
{
    struct used_list_node *cur = ul->head;
    while (cur != NULL) {
        if (pos >= cur->base && pos < cur->base + cur->bytes) {
            if (base != NULL) {
                *base = cur->base;
            }
            if (bytes != NULL) {
                *bytes = cur->bytes;
            }
            if (region_type != NULL) {
                *region_type = cur->region_type;
            }
            return SYS_ERR_OK;
        }
        cur = cur->next;
    }
    return LIB_ERR_USED_LIST_REGION_NOT_FOUND;
}

__END_DECLS


#endif /* AOS_UL_H */