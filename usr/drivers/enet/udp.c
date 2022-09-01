#include "udp.h"

#include "netutil/htons.h"
#include "netutil/checksum.h"
#include "net_socket_servers.h"

errval_t udp_get_context(uint16_t dst_port, uint16_t src_port, ip_addr_t dst_ip,
                         struct udp_context *ret)
{
    errval_t err;
    err = ip_get_send_context(dst_ip, IP_PROTO_UDP, &ret->__ip_context);
    RETURN_IF_ERR(err);
    ret->pkt = (struct udp_hdr *)ret->__ip_context.pkt->payload;
    ret->pkt->src_port = htons(src_port);
    ret->pkt->dst_port = htons(dst_port);
    return SYS_ERR_OK;
}

errval_t udp_send_context(struct udp_context context, size_t length)
{
    errval_t err;
    uint16_t total_length = length + sizeof(struct udp_hdr);
    context.pkt->len = htons(total_length);
    context.pkt->chksum = 0;
    context.pkt->chksum = udp_checksum(context.pkt, total_length,
                                       context.__ip_context.pkt);
    err = ip_send_context(context.__ip_context, total_length);
    RETURN_IF_ERR(err);
    return SYS_ERR_OK;
}

errval_t handle_udp_packet(struct udp_hdr *udp_hdr, ip_addr_t src_ip)
{
    errval_t err;
    uint16_t dst_port = ntohs(udp_hdr->dst_port);
    uint16_t src_port = ntohs(udp_hdr->src_port);
    size_t payload_length = ntohs(udp_hdr->len) - sizeof(struct udp_hdr);

    err = udp_servers_handle_packet(src_ip, src_port, dst_port, udp_hdr->payload,
                                    payload_length);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}
