#ifndef LIBBARRELFISH_PAGING_STATE_REBASE_H
#define LIBBARRELFISH_PAGING_STATE_REBASE_H


#include <errors/errno.h>
#include <aos/capabilities.h>
#include <aos/paging_types.h>

size_t rebase_get_page_table_storage_size(struct page_table *pt);

errval_t rebase_to_relative_frame(struct paging_state *pst, void *buf, size_t buf_size,
                                  struct slot_allocator *slot_alloc);

void reconstruct_page_table(struct page_table *pt);

void print_mappings(struct page_table *pt);


#endif  // LIBBARRELFISH_PAGING_H