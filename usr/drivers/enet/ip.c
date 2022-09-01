#include "ip.h"
#include <aos/aos.h>
#include <aos/macros.h>
#include <netutil/htons.h>
#include <netutil/checksum.h>

#include "arp.h"
#include "udp.h"
#include "tcp.h"

//#define PRINT_PING_DEBUG

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3
#define ICMP_TYPE_SOURCE_QUENCH 4
#define ICMP_TYPE_REDIRECT 5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAMETER_PROBLEM 12


static errval_t handle_icmp_echo(struct ip_hdr *ip_hdr)
{
    errval_t err;

#ifdef PRINT_PING_DEBUG
    DEBUG_PRINTF("Got ICMP echo request from %u.%u.%u.%u\n",
                ip_hdr->src & 0xff,
                (ip_hdr->src >> 8) & 0xff,
                (ip_hdr->src >> 16) & 0xff,
                ip_hdr->src >> 24);
#endif

    struct ip_context context;
    err = ip_get_send_context(htonl(ip_hdr->src), IP_PROTO_ICMP, &context);
    RETURN_IF_ERR(err);

    *context.pkt = *ip_hdr;
    ip_addr_t dest = context.pkt->dest;
    context.pkt->dest = context.pkt->src;
    context.pkt->src = dest;

    size_t payload_length = ntohs(ip_hdr->len) - (ip_hdr->ihl * 4);
    memcpy(context.pkt->payload, ip_hdr->payload, payload_length);

    struct icmp_echo_hdr *icmp_hdr_send = (struct icmp_echo_hdr *)context.pkt->payload;
    icmp_hdr_send->type = ICMP_ECHO_REPLY;

    icmp_hdr_send->chksum = 0;
    icmp_hdr_send->chksum = inet_checksum(icmp_hdr_send, payload_length);

    err = ip_send_context(context, payload_length);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

static errval_t handle_icmp(struct ip_hdr *ip_hdr)
{
    struct icmp_echo_hdr *icmp_echo_hdr = (struct icmp_echo_hdr *)(ip_hdr->payload);

    switch (icmp_echo_hdr->type) {
    case ICMP_ECHO_REQUEST:
        handle_icmp_echo(ip_hdr);
        break;
    case ICMP_TYPE_ECHO_REPLY:
        DEBUG_PRINTF("ICMP echo reply\n");
        break;
    case ICMP_TYPE_DEST_UNREACHABLE:
        DEBUG_PRINTF("ICMP dest unreachable\n");
        break;
    case ICMP_TYPE_TIME_EXCEEDED:
        DEBUG_PRINTF("ICMP time exceeded\n");
        break;
    case ICMP_TYPE_PARAMETER_PROBLEM:
        DEBUG_PRINTF("ICMP parameter problem\n");
        break;
    case ICMP_TYPE_SOURCE_QUENCH:
        DEBUG_PRINTF("ICMP source quench\n");
        break;
    case ICMP_TYPE_REDIRECT:
        DEBUG_PRINTF("ICMP redirect\n");
        break;
    default:
        DEBUG_PRINTF("ICMP type %d\n", icmp_echo_hdr->type);
        break;
    }
    return SYS_ERR_OK;
}

errval_t ip_get_send_context(ip_addr_t dest, uint8_t protocol, struct ip_context *ret)
{
    errval_t err;
    struct eth_addr *dest_mac = arp_lookup_mac(dest);
    assert(dest_mac != NULL);
    err = ethernet_get_send_context(&ret->__eth_context, *dest_mac, ETH_TYPE_IP);
    RETURN_IF_ERR(err);
    ret->pkt = (struct ip_hdr *)ret->__eth_context.pkt->payload;
    ret->pkt->version = 4;
    ret->pkt->tos = 0;
    ret->pkt->ihl = 5;
    ret->pkt->id = 42;
    ret->pkt->frag_off = htons(0x4000);
    ret->pkt->ttl = 64;
    ret->pkt->proto = protocol;
    // csum is set in send_context.
    ret->pkt->src = htonl(STATIC_IP_ADDRESS);
    ret->pkt->dest = htonl(dest);
    return SYS_ERR_OK;
}

errval_t ip_send_context(struct ip_context context, size_t payload_length)
{
    size_t total_length = payload_length + sizeof(struct ip_hdr);
    context.pkt->len = htons(total_length);
    context.pkt->chksum = 0;
    context.pkt->chksum = inet_checksum(context.pkt, sizeof(struct ip_hdr));

    errval_t err;
    err = ethernet_send_context(context.__eth_context, total_length);
    RETURN_IF_ERR(err);
    return SYS_ERR_OK;
}


errval_t ip_handle_packet(struct ip_hdr *ip_hdr, size_t __packet_length)
{
    assert(ip_hdr->version == 4);
    size_t header_length = (ip_hdr->ihl * 4);
    size_t payload_length = ntohs(ip_hdr->len) - header_length;
    // Packet filter to drop packets or not for us or are fragmented.
    if (ip_hdr->dest != htonl(STATIC_IP_ADDRESS) ||
            ip_hdr->frag_off & htons(0x1FFF)) {
        // DEBUG_PRINTF("Dropping ip packet\n");
        return SYS_ERR_OK;
    } 
    errval_t err;
    switch (ip_hdr->proto) {
    case IP_PROTO_ICMP:
        err = handle_icmp(ip_hdr);
        break;
    case IP_PROTO_TCP:
        err = tcp_handle_packet((struct tcp_hdr *)ip_hdr->payload, htonl(ip_hdr->src),
                          payload_length);
        break;
    case IP_PROTO_UDP:
        err = handle_udp_packet((struct udp_hdr *)ip_hdr->payload, htonl(ip_hdr->src));
        break;
    default:
        err = SYS_ERR_OK;
        break;
    }

    return err;
}
