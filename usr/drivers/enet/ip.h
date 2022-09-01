#ifndef _ETH_IP_H_
#define _ETH_IP_H_


#include <stdint.h>
#include <aos/aos.h>
#include <errors/errno.h>

#include "ethernet.h"
#include <netutil/ip.h>
#include <netutil/icmp.h>


struct ip_context {
    struct eth_send_context __eth_context;
    struct ip_hdr *pkt;
};


errval_t ip_handle_packet(struct ip_hdr *ip, size_t packet_length);
void arp_add_new_entry(struct eth_addr eth_src, ip_addr_t ip_src);

errval_t ip_get_send_context(ip_addr_t dst, uint8_t protocol, struct ip_context *ret);
errval_t ip_send_context(struct ip_context context, size_t payload_length);


#endif