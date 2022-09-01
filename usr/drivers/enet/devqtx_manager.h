
#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <aos/deferred.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>
#include <netutil/etharp.h>
#include <aos/aos.h>
#include <aos/macros.h>
#include "enet.h"


struct devqtx_list {
    lvaddr_t base;
    struct devqtx_list *next;
};

struct devqtx_manager {
    struct thread_mutex mutex;
    struct enet_queue *queue;
    struct devqtx_list *free_buffs;
    regionid_t rid;
    lvaddr_t region_base;
    size_t free_buf_count;
    struct devqtx_list static_list[sizeof(struct devqtx_list) * TX_RING_SIZE];
};


errval_t init_devqtx_manager(struct devqtx_manager *devqtx_manager,
                             struct enet_queue *queue, regionid_t rid);
errval_t devqtx_manager_get_free_context(struct devqtx_manager *devqtx_manager,
                                         lvaddr_t *ret);
errval_t devqtx_manager_send_context(struct devqtx_manager *devqtx_manager, lvaddr_t base,
                                     size_t length);