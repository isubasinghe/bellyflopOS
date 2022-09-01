#include <errors/errno.h>


#include <aos/types.h>
#include <aos/capabilities.h>
#include <aos/macros.h>
#include <aos/cap_store.h>


void cap_store_init(struct cap_store *store, struct slab_allocator *slabs,
                    cap_store_release_cap release_cap)
{
    collections_static_hash_create(&store->ht, slabs);
    store->release_cap = release_cap;
    store->slabs = slabs;
}

void cap_store_get_active(struct cap_store *store, uint64_t addr,
                          struct cap_list_header **list_header_out)
{
    struct cap_list_header *list_header = collections_static_hash_find(&store->ht, addr);
    if (list_header == NULL) {
        list_header = (struct cap_list_header *)slab_alloc(store->slabs);
        list_header->head = NULL;
        list_header->active_cap = NULL_CAP;
        list_header->offset = 0;
        collections_static_hash_insert(&store->ht, addr, list_header);
    }
    *list_header_out = list_header;
}

void push_back_active(struct cap_store *store, struct cap_list_header *list_header)
{
    if (capref_is_null(list_header->active_cap)) {
        struct cap_list_node *new_node = (struct cap_list_node *)slab_alloc(store->slabs);
        new_node->cap = list_header->active_cap;
        new_node->next = list_header->head;
        list_header->head = new_node;
    }
    list_header->active_cap = NULL_CAP;
    list_header->offset = 0;
}

void cap_store_add(struct cap_store *store, uint64_t addr, struct capref capref)
{
    struct cap_list_header *list_header = collections_static_hash_find(&store->ht, addr);
    struct cap_list_node *new_node = (struct cap_list_node *)slab_alloc(store->slabs);
    new_node->cap = capref;
    new_node->next = NULL;

    if (list_header == NULL) {
        list_header = (struct cap_list_header *)slab_alloc(store->slabs);
        list_header->head = new_node;
        collections_static_hash_insert(&store->ht, addr, list_header);
    } else {
        new_node->next = list_header->head;
        list_header->head = new_node;
    }
}

void cap_store_free(struct cap_store *store, uint64_t addr)
{
    struct cap_list_header *header = collections_static_hash_delete(&store->ht, addr);
    assert(header != NULL);
    struct cap_list_node *node = header->head;
    while (node) {
        store->release_cap(node->cap);
        struct cap_list_node *next = node->next;
        slab_free(store->slabs, node);
        node = next;
    }
    slab_free(store->slabs, header);
}

void cap_store_delete(struct cap_store *store)
{
    collections_static_hash_release(&store->ht);
}