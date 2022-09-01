#include "arp.h"
#include "aos/macros.h"

struct arp_handler {
    collections_hash_table *arp_table;
    // collections_hash_create waiting_requests;
};

struct arp_handler ah;

void init_arp_handler(void)
{
    collections_hash_create(&ah.arp_table, free);
}

errval_t get_arp_table(ip_addr_t** ips, size_t** macs, size_t* count)
{
    size_t size = collections_hash_size(ah.arp_table);
    *ips = malloc(sizeof(ip_addr_t) * size);
    *macs = malloc(sizeof(size_t) * size);
    *count = size; 

    if(collections_hash_traverse_start(ah.arp_table) != 1) {
        return SYS_ERR_OK;
    }

    size_t i = 0;
    while(true) {
        size_t ip_arg;
        void* data = collections_hash_traverse_next(ah.arp_table, &ip_arg);
        if(data == NULL) {
            break;
        }
        ip_addr_t ip = (ip_addr_t) ip_arg;
        (*ips)[i] = ip;
        (*macs)[i] = eth_addr_to_uint64((struct eth_addr*) data);
        i++;
    }

    if(collections_hash_traverse_end(ah.arp_table) != 1) {
        return SYS_ERR_OK;
    }
    
    return SYS_ERR_OK;
}

static errval_t arp_send(ip_addr_t src_ip, ip_addr_t dst_ip, struct eth_addr dest_mac,
                         uint16_t opcode)
{
    errval_t err;
    struct eth_send_context context;
    err = ethernet_get_send_context(&context, dest_mac, ETH_TYPE_ARP);
    RETURN_IF_ERR(err);

    struct arp_hdr *arp = (struct arp_hdr *)context.pkt->payload;
    arp->hwtype = htons(ARP_HW_TYPE_ETH);
    arp->proto = htons(ARP_PROT_IP);
    arp->hwlen = 0x6;
    arp->protolen = 0x4;
    arp->opcode = opcode;
    arp->eth_src = ethernet_get_mac();
    arp->ip_src = src_ip;
    arp->eth_dst = dest_mac;
    arp->ip_dst = dst_ip;

    ethernet_send_context(context, sizeof(struct arp_hdr));
    return SYS_ERR_OK;
}

// The process is pretty straight forward, send a few ARP Probes (typically 3),
// and if no one responds, officially claim the IP address with an ARP Announcement.
errval_t arp_probe(void)
{
    errval_t err;

    for (int i = 0; i < 3; i++) {
        err = arp_send(0, htonl(STATIC_IP_ADDRESS), BROADCAST, htons(ARP_OP_REQ));
        RETURN_IF_ERR(err);
    }
    // TODO: Wait for responses and fail if someone responds.
    // Claim the IP address.
    err = arp_send(htonl(STATIC_IP_ADDRESS), htonl(STATIC_IP_ADDRESS), BROADCAST,
                   htons(ARP_OP_REP));
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

errval_t arp_request(ip_addr_t ip_addr)
{
    // DEBUG_PRINTF("Sending ARP Entry for %d.\n", ip_addr);
    return arp_send(htonl(STATIC_IP_ADDRESS), htonl(ip_addr), BROADCAST,
                    htons(ARP_OP_REQ));
}

struct eth_addr *arp_lookup_mac(ip_addr_t ip_addr)
{
    return collections_hash_find(ah.arp_table, ip_addr);
}

void arp_add_new_entry(struct eth_addr eth_src, ip_addr_t ip_src)
{
    struct eth_addr *eth_src_data = malloc(sizeof(struct eth_addr));
    *eth_src_data = eth_src;
    // DEBUG_PRINTF("Got Arp Entry for %d.\n", ip_src);
    collections_hash_insert_or_overwrite(ah.arp_table, ip_src, (void *)eth_src_data);
}

errval_t arp_handle_packet(struct arp_hdr *pkt)
{
    errval_t err;
    switch (ntohs(pkt->opcode)) {
    case ARP_OP_REQ:
        if (ntohl(pkt->ip_dst) == STATIC_IP_ADDRESS) {
            // WOHO: someone is asking is something.
            err = arp_send(htonl(STATIC_IP_ADDRESS), htonl(pkt->ip_src), pkt->eth_src,
                           htons(ARP_OP_REP));
            RETURN_IF_ERR(err);
        } else if (pkt->ip_src == pkt->ip_dst) {
            arp_add_new_entry(pkt->eth_src, htonl(pkt->ip_src));
        } else {
            // DEBUG_PRINTF("Not for us.\n");
        }
        break;
    case ARP_OP_REP:
        if (ntohl(pkt->ip_dst) == STATIC_IP_ADDRESS || pkt->ip_dst == 0) {
            arp_add_new_entry(pkt->eth_src, htonl(pkt->ip_src));
        }
        break;
    }
    return SYS_ERR_OK;
}