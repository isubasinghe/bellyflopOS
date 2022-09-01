#ifndef UDP_SERVERS_H
#define UDP_SERVERS_H


#include <errors/errno.h>
#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/nameserver.h>
#include <netutil/ip.h>
#include <netutil/net_sockets.h>
#include <tcp.h>

struct udp_endpoint {
    nameservice_chan_t chan;
    struct ump_chan ump_chan;
    uint16_t src_port;
};


errval_t init_netsocket_servers(void);
errval_t udp_servers_handle_packet(ip_addr_t src, uint16_t src_port, uint16_t dst_port,
                                   uint8_t *buf, size_t buflen);

errval_t tcp_servers_tcp_handle_packet(struct tcp_connection_state *connection,
                                       uint8_t *buf, size_t buflen);
errval_t tcp_servers_handle_connection_request(struct tcp_connection_state *connection,
                                               nameservice_chan_t chan, bool is_high_speed);
errval_t tcp_servers_tcp_handle_close(struct tcp_connection_state *connection);


#endif
