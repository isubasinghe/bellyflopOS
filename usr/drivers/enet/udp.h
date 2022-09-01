#ifndef _ETH_UDP_H_
#define _ETH_UDP_H_

#include <stdint.h>
#include <aos/aos.h>
#include <errors/errno.h>

#include "ip.h"
#include <netutil/udp.h>

struct udp_context {
    struct ip_context __ip_context;
    struct udp_hdr *pkt;
};

errval_t udp_get_context(uint16_t dst_port, uint16_t src_port, ip_addr_t dst_ip,
                         struct udp_context *ret);

errval_t udp_send_context(struct udp_context context, size_t length);

errval_t handle_udp_packet(struct udp_hdr *udp_hdr, ip_addr_t src_ip);

#endif