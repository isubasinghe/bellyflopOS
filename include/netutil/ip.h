#ifndef _IP_H_
#define _IP_H_

#include <aos/aos.h>
#include <stdint.h>
#include <stddef.h>

//#define IP_DEBUG_OPTION 1

#if defined(IP_DEBUG_OPTION)
#    define IP_DEBUG(x...) debug_printf("[ip] " x);
#else
#    define IP_DEBUG(fmt, ...) ((void)0)
#endif

#define IP_RF 0x8000U      /* reserved fragment flag */
#define IP_DF 0x4000U      /* dont fragment flag */
#define IP_MF 0x2000U      /* more fragments flag */
#define IP_OFFMASK 0x1fffU /* mask for fragmenting bits */
#define IP_HLEN 20         /* Default size for ip header */
#define IP_PROTO_ICMP 1
#define IP_PROTO_IGMP 2
#define IP_PROTO_UDP 17
#define IP_PROTO_UDPLITE 136
#define IP_PROTO_TCP 6

typedef uint32_t ip_addr_t;
#define MK_IP(a, b, c, d) (((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

#define IPH_V(hdr) ((hdr)->v_hl >> 4)
#define IPH_HL(hdr) ((hdr)->v_hl & 0x0f)
#define IPH_VHL_SET(hdr, v, hl) (hdr)->v_hl = (((v) << 4) | (hl))

struct ip_hdr {
    /* version / header length */
    uint8_t ihl : 4;
    uint8_t version : 4;
    /* type of service */
    uint8_t tos;
    /* total length */
    uint16_t len;
    /* identification */
    uint16_t id;
    /* fragment offset field */
    uint16_t frag_off;
    /* time to live */
    uint8_t ttl;
    /* protocol*/
    uint8_t proto;
    /* checksum */
    uint16_t chksum;
    /* source and destination IP addresses */
    ip_addr_t src;
    ip_addr_t dest;
    uint8_t payload[];
} __attribute__((__packed__));

/**
 * Calculate checksum
 */
uint16_t ip_inet_chksum(void *dataptr, uint16_t len);


/* '0.0.0.0' is not a valid IP address, so this uses the value 0 to
   indicate an invalid IP address. */
#define INVALID 0

// https://www.lemoda.net/c/ip-to-integer/
ip_addr_t str_to_ip_addr(const char *ip);

// https://stackoverflow.com/questions/1680365/integer-to-ip-address-c
static inline void print_ip(ip_addr_t ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);        
}


#endif
