#include "devqtx_manager.h"


errval_t init_devqtx_manager(struct devqtx_manager *devqtx_manager,
                             struct enet_queue *queue, regionid_t rid)
{
    thread_mutex_init(&devqtx_manager->mutex);
    devqtx_manager->queue = queue;
    devqtx_manager->free_buffs = NULL;


    struct region_entry *region_entry = queue->regions;
    // We only support one region for now.
    assert(region_entry != NULL);
    assert(region_entry->next == NULL);
    devqtx_manager->rid = region_entry->rid;
    size_t cure_node = 0;
    devqtx_manager->region_base = region_entry->mem.vbase;
    size_t size = region_entry->mem.size;
    size_t base_offset = 0;
    while (base_offset < size) {
        assert(cure_node < TX_RING_SIZE);
        devqtx_manager->static_list[cure_node].base = devqtx_manager->region_base
                                                      + base_offset;
        devqtx_manager->static_list[cure_node].next = devqtx_manager->free_buffs;
        devqtx_manager->free_buffs = &devqtx_manager->static_list[cure_node];
        base_offset += ENET_MAX_BUF_SIZE;
        cure_node++;
    }
    assert(cure_node == TX_RING_SIZE);
    devqtx_manager->free_buf_count = TX_RING_SIZE;

    return SYS_ERR_OK;
}

__unused static size_t get_list_size(struct devqtx_manager *devqtx_manager) {
    size_t size = 0;
    struct devqtx_list* list = devqtx_manager->free_buffs;
    while (list != NULL) {
        size++;
        list = list->next;
    }
    return size;
}

static errval_t recover_free_buffs(struct devqtx_manager *devqtx_manager)
{
    //DEBUG_PRINTF("Recovering free buffers buf_count %d\n", buf_count);
    errval_t err;
    size_t recovered_buffs = 0;
    do {
        struct devq_buf buf;
        err = devq_dequeue((struct devq *)devqtx_manager->queue, &buf.rid, &buf.offset,
                           &buf.length, &buf.valid_data, &buf.valid_length, &buf.flags);
        if (err_is_fail(err)) {
            if(recovered_buffs > 0) {
                // Stall till we recover some buffers.
                break;
            }          
        } else {
            size_t array_index = buf.offset / ENET_MAX_BUF_SIZE;
            struct devqtx_list *list_entry = &devqtx_manager->static_list[array_index];
            list_entry->next = devqtx_manager->free_buffs;
            devqtx_manager->free_buffs = list_entry;
            recovered_buffs++;
            devqtx_manager->free_buf_count++;
        }
    } while (1);
    if (err != DEVQ_ERR_QUEUE_EMPTY) {
        return err;
    }
    return SYS_ERR_OK;
}

errval_t devqtx_manager_get_free_context(struct devqtx_manager *devqtx_manager,
                                         lvaddr_t *ret)
{
    thread_mutex_lock(&devqtx_manager->mutex);
    errval_t err;
    
    if (devqtx_manager->free_buf_count < 250) {
        err = recover_free_buffs(devqtx_manager);
        if(err_is_fail(err)) {
            thread_mutex_unlock(&devqtx_manager->mutex);
            return err;
        }
        if (devqtx_manager->free_buffs == NULL) {
            thread_mutex_unlock(&devqtx_manager->mutex);
            return ENET_ERR_NO_FREE_SEND_BUFFS;
        }
    }
    devqtx_manager->free_buf_count--;
    *ret = devqtx_manager->free_buffs->base;
    // Remove the entry from the list.
    devqtx_manager->free_buffs = devqtx_manager->free_buffs->next;
    thread_mutex_unlock(&devqtx_manager->mutex);
    return SYS_ERR_OK;
}

errval_t devqtx_manager_send_context(struct devqtx_manager *devqtx_manager, lvaddr_t base,
                                     size_t length)
{
    thread_mutex_lock(&devqtx_manager->mutex);
    lvaddr_t offset = base - devqtx_manager->region_base;
    errval_t err = devq_enqueue((struct devq *)devqtx_manager->queue, devqtx_manager->rid, offset,
                        ENET_MAX_BUF_SIZE, 0, length, 0);
    thread_mutex_unlock(&devqtx_manager->mutex);
    return err;
}
