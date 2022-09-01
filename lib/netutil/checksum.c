#include <netutil/checksum.h>
#include <netutil/htons.h>


static uint16_t lwip_standard_chksum(void *dataptr, uint16_t len, uint32_t acc)
{
    uint16_t src;
    uint8_t *octetptr;

    /* dataptr may be at odd or even addresses */
    octetptr = (uint8_t *)dataptr;
    while (len > 1) {
        /* declare first octet as most significant
           thus assume network order, ignoring host order */
        src = (*octetptr) << 8;
        octetptr++;
        /* declare second octet as least significant */
        src |= (*octetptr);
        octetptr++;
        acc += src;
        len -= 2;
    }
    if (len > 0) {
        /* accumulate remaining octet */
        src = (*octetptr) << 8;
        acc += src;
    }
    /* add deferred carry bits */
    acc = (acc >> 16) + (acc & 0x0000ffffUL);
    if ((acc & 0xffff0000UL) != 0) {
        acc = (acc >> 16) + (acc & 0x0000ffffUL);
    }
    /* This maybe a little confusing: reorder sum using htons()
       instead of ntohs() since it has a little less call overhead.
       The caller must invert bits for Internet sum ! */
    return htons((uint16_t)acc);
};

/**
 * Calculate a short such that ret + dataptr[..] becomes 0
 */
uint16_t inet_checksum(void *dataptr, uint16_t len)
{
    return ~lwip_standard_chksum(dataptr, len, 0);
};


/**
 * Calculate a short such that ret + dataptr[..] becomes 0
 */
uint16_t udp_checksum(void *dataptr, uint16_t len, struct ip_hdr *ip)
{
    uint32_t acc = 0;

    uint32_t src = ntohl(ip->src);
    uint32_t dst = ntohl(ip->dest);
    acc += (src >> 16) + ((uint16_t)src);
    acc += (dst >> 16) + ((uint16_t)dst);
    acc += ip->proto;
    acc += len;

    return ~lwip_standard_chksum(dataptr, len, acc);
};
