#ifndef _ETH_TCP_H_
#define _ETH_TCP_H_


#include <stdint.h>
#include <aos/aos.h>
#include <errors/errno.h>
#include <aos/systime.h>
#include <aos/ump_chan.h>
#include <aos/nameserver.h>

#include "ip.h"

struct tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t reserved_and_ns : 4;
    uint8_t data_offset : 4;
    uint8_t fin : 1;
    uint8_t syn : 1;
    uint8_t rst : 1;
    uint8_t psh : 1;
    uint8_t ack : 1;
    uint8_t urg : 1;
    uint8_t ece : 1;
    uint8_t cwr : 1;
    uint16_t window_size;
    uint16_t chksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

struct tcp_context {
    struct ip_context __ip_context;
    struct tcp_hdr *pkt;
};


#define MAX_TCP_DATA_SIZE (1500 - sizeof(struct ip_hdr))
#define SEND_BUF_SLOTS 512
#define TCP_RETRANSMISSION_RTT_MULTIPLIER 2

struct send_buf_slot {
    uint8_t data[MAX_TCP_DATA_SIZE];
    uint32_t expected_ack;
    systime_t time_sent;
    size_t length;
    bool is_used;
};

struct tcp_connection_state {
    bool is_in_handshake;
    bool is_in_fin;
    bool is_reset;
    bool is_closed;
    systime_t rtt_timer;


    uint16_t src_port;
    uint16_t dst_port;
    ip_addr_t dst_ip;

    uint32_t next_seq_num;
    uint32_t last_seq_num_sent;
    uint32_t max_to_ack;

    struct send_buf_slot send_buf[SEND_BUF_SLOTS];
    uint64_t next_send_slot;
    uint64_t not_acked_slot;
    uint64_t higest_ack_recv;
    struct ump_chan ump_chan;
    struct thread_mutex mutex;
};


enum port_state {
    PORT_UNUSED = 0,
    PORT_SERVER = 1,
    PORT_CLIENT = 2,
};

void tcp_create_server(uint16_t port, nameservice_chan_t chan, bool is_high_speed_connection);

void tcp_destroy_connection(uint16_t src_port, uint16_t dst_port, ip_addr_t dst_ip);

inline uint8_t *tcp_hdr_get_payload(struct tcp_hdr *tcp_hdr)
{
    return (uint8_t *)tcp_hdr + tcp_hdr->data_offset * 4;
}

errval_t tcp_get_context(struct tcp_connection_state *connection, struct tcp_context *ret);

errval_t tcp_send_context(struct tcp_connection_state *connection,
                          struct tcp_context context, size_t length);

errval_t tcp_handle_packet(struct tcp_hdr *tcp_hdr, ip_addr_t src_ip,
                           size_t packet_length);

errval_t tcp_init(void);

size_t tcp_send_buf_free_bytes(uint16_t src_port, uint16_t dst_port);

errval_t tcp_start_handshake(struct tcp_connection_state **ret, ip_addr_t dst_ip,
                             uint16_t src_port, uint16_t dst_port);

#endif
