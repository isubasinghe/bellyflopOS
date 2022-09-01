#include <aos/aos.h>
#include <aos/macros.h>
#include "ethernet.h"
#include "arp.h"

#include <netutil/htons.h>

struct eth_addr BROADCAST = (struct eth_addr) { .addr = { 0xff, 0xff, 0xff, 0xff, 0xff,
                                                          0xff } };

struct ethernet_handler eh;


errval_t init_ethernet_handler(struct enet_driver_state *st)
{
    init_devqtx_manager(&eh.default_devqtx_manager, st->txq, 0);
    uint64_t mac = st->mac;
    for (int i = ETH_ADDR_LEN - 1; i >= 0; --i) {
        eh.mac_addr.addr[i] = mac & 0xff;
        mac >>= 8;
    }
    eh.rxq = st->rxq;
    return SYS_ERR_OK;
}

static bool eth_addr_equal(struct eth_addr *a, struct eth_addr *b)
{
    return a->addr[0] == b->addr[0] && a->addr[1] == b->addr[1]
           && a->addr[2] == b->addr[2] && a->addr[3] == b->addr[3]
           && a->addr[4] == b->addr[4] && a->addr[5] == b->addr[5];
}

static bool is_broadcast(struct eth_addr *addr)
{
    return addr->addr[0] == 0xff && addr->addr[1] == 0xff && addr->addr[2] == 0xff
           && addr->addr[3] == 0xff && addr->addr[4] == 0xff && addr->addr[5] == 0xff;
}

static struct region_entry *find_region(struct enet_queue *st, uint32_t rid)
{
    struct region_entry *entry = st->regions;
    // We only support one region for now.
    assert(entry != NULL);
    assert(entry->next == NULL);
    assert(entry->rid == rid);
    return entry;
}


errval_t ethernet_get_send_context(struct eth_send_context *ret, struct eth_addr dst,
                                   uint16_t type)
{
    lvaddr_t base;
    errval_t err;
    err = devqtx_manager_get_free_context(&eh.default_devqtx_manager, &base);
    RETURN_IF_ERR(err);
    ret->pkt = (struct eth_hdr *)base;
    ret->pkt->src = eh.mac_addr;
    ret->pkt->dst = dst;
    ret->pkt->type = htons(type);

    return SYS_ERR_OK;
}

errval_t ethernet_send_context(struct eth_send_context context, size_t payload_length)
{
    errval_t err;
    size_t total_length = payload_length + sizeof(struct eth_hdr);
    err = devqtx_manager_send_context(&eh.default_devqtx_manager, (lvaddr_t)context.pkt,
                                      total_length);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

struct eth_addr ethernet_get_mac(void)
{
    return eh.mac_addr;
}

ip_addr_t last_ip = 0;

void handle_ethernet(struct devq_buf *buf, size_t packet_length)
{
    struct region_entry *entry = find_region(eh.rxq, buf->rid);

    struct eth_hdr *eth_hdr = (struct eth_hdr *)(entry->mem.vbase + buf->offset
                                                 + buf->valid_data);


    uint16_t eth_type = ntohs(eth_hdr->type);

    if (!is_broadcast(&eth_hdr->dst) && !eth_addr_equal(&eth_hdr->dst, &eh.mac_addr)) {
        DEBUG_PRINTF("Received packet for %02x:%02x:%02x:%02x:%02x:%02x\n",
                     eth_hdr->dst.addr[0], eth_hdr->dst.addr[1], eth_hdr->dst.addr[2],
                     eth_hdr->dst.addr[3], eth_hdr->dst.addr[4], eth_hdr->dst.addr[5]);
        DEBUG_PRINTF("Dropped packet: not for me\n");
        return;
    }
    errval_t err;
    switch (eth_type) {
    case ETH_TYPE_IP: {
        struct ip_hdr *ip_hdr = (struct ip_hdr *)eth_hdr->payload;
        if (ip_hdr->src != last_ip) {
            arp_add_new_entry(eth_hdr->src, ntohl(ip_hdr->src));
        }
        last_ip = ip_hdr->src;
        err = ip_handle_packet(ip_hdr, packet_length - sizeof(struct eth_hdr));
        break;
    }
    case ETH_TYPE_ARP:
        err = arp_handle_packet((struct arp_hdr *)eth_hdr->payload);
        break;
    default:
        err = SYS_ERR_OK;
        break;
    }
    if(err_is_fail(err)) {
        //DEBUG_ERR(err, "Error in ethernet handler\n");
    }
    
}