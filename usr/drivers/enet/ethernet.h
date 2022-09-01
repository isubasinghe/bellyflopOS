#ifndef _ETH_ETHERNET_H_
#define _ETH_ETHERNET_H_


#include <devif/queue_interface_backend.h>
#include <devif/backends/net/enet_devif.h>
#include <aos/aos.h>
#include <driverkit/driverkit.h>
#include <dev/imx8x/enet_dev.h>
#include <netutil/etharp.h>
#include <aos/macros.h>
#include "enet.h"
#include "devqtx_manager.h"


extern struct eth_addr BROADCAST;

struct eth_send_context {
    struct eth_hdr *pkt;
};


struct ethernet_handler {
    struct eth_addr mac_addr;
    struct enet_queue *rxq;
    struct devqtx_manager default_devqtx_manager;
};

errval_t init_ethernet_handler(struct enet_driver_state *st);

errval_t ethernet_get_send_context(struct eth_send_context *ret, struct eth_addr dst,
                                   uint16_t type);
errval_t ethernet_send_context(struct eth_send_context context, size_t payload_length);
struct eth_addr ethernet_get_mac(void);


void handle_ethernet(struct devq_buf *buf, size_t packet_length);


#endif
