

#ifndef AOS_MEM_CAP_STORE_H
#define AOS_MEM_CAP_STORE_H

#include <errors/errno.h>
#include <aos/types.h>
#include <collections/static_hash_table.h>


__BEGIN_DECLS


typedef void (*cap_store_release_cap)(struct capref data);


struct cap_list_node {
    struct capref cap;
    struct cap_list_node *next;
};

struct cap_list_header {
    struct cap_list_node *head;
    struct capref active_cap;
    size_t offset;
};

#define CAP_LIST_SLAB_BLOCKSIZE                                                          \
    (sizeof(struct cap_list_node) > sizeof(struct cap_list_header)                       \
         ? sizeof(struct cap_list_node)                                                  \
         : sizeof(struct cap_list_header))

#define CAP_STORE_SLAB_BLOCKSIZE                                                         \
    (STATIC_HASH_TABLE_SLAB_BLOCKSIZE > CAP_LIST_SLAB_BLOCKSIZE                          \
         ? STATIC_HASH_TABLE_SLAB_BLOCKSIZE                                              \
         : CAP_LIST_SLAB_BLOCKSIZE)


struct cap_store {
    struct _collections_static_hash_table ht;
    cap_store_release_cap release_cap;
    struct slab_allocator *slabs;
};

void cap_store_init(struct cap_store *store, struct slab_allocator *slabs,
                    cap_store_release_cap release);


void cap_store_add(struct cap_store *store, uint64_t addr, struct capref capref);
void cap_store_free(struct cap_store *store, uint64_t addr);

void push_back_active(struct cap_store *store, struct cap_list_header *list_header);
void cap_store_get_active(struct cap_store *store, uint64_t addr,
                          struct cap_list_header **list_header_out);


void cap_store_delete(struct cap_store *store);


__END_DECLS


#endif /* AOS_MM_H */