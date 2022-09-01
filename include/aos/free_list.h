

#ifndef AOS_FL_H
#define AOS_FL_H

#include <errors/errno.h>
#include <aos/types.h>


__BEGIN_DECLS

#define FREE_LIST_REFILL_THRESHOLD 32

struct free_list_node {
    size_t base;
    size_t size;
    struct free_list_node *next;
    struct free_list_node *prev;
};

#define FREE_LIST_BLOCK_SIZE sizeof(struct free_list_node)

struct free_list {
    size_t base;
    size_t size;
    struct free_list_node *next;
    struct slab_allocator *slabs;
    struct free_list_node *alloc_pos;
    bool circulate;
};

errval_t free_list_init(struct free_list *fl, struct slab_allocator *slabs, size_t base,
                        size_t size, bool circulate);

errval_t free_list_destroy(struct free_list *fl);

errval_t free_list_create_and_insert_node_after(struct free_list *fl,
                                                struct free_list_node *after, size_t base,
                                                size_t size);

void free_list_remove_and_free_node(struct free_list *fl,
                                    struct free_list_node *to_delete);

errval_t free_list_alloc_next(struct free_list *fl, size_t size, size_t alignment,
                              size_t *base);

errval_t free_list_alloc_region(struct free_list *fl, size_t base, size_t size);
errval_t free_list_get_region(struct free_list *fl, size_t pos, size_t *base,
                              size_t *size);
errval_t free_list_add_free(struct free_list *fl, size_t base, size_t bytes);

__END_DECLS


#endif /* AOS_MM_H */