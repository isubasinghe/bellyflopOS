#ifndef _ETH_ARP_H_
#define _ETH_ARP_H_

#include <collections/hash_table.h>
#include <netutil/htons.h>
#include "ethernet.h"
#include "ip.h"

void init_arp_handler(void);

errval_t arp_probe(void);

errval_t arp_request(ip_addr_t ip_addr);

errval_t get_arp_table(ip_addr_t** ips, size_t** macs, size_t* count);

errval_t arp_handle_packet(struct arp_hdr *pkt);

struct eth_addr *arp_lookup_mac(ip_addr_t ip_addr);

#endif
