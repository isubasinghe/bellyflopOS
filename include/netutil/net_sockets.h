#ifndef NETUTIL_SERVERS_H
#define NETUTIL_SERVERS_H

#include <errors/errno.h>
#include <aos/nameserver.h>
#include <netutil/ip.h>
#include <aos/aos.h>


struct udp_ump_header {
    ip_addr_t address;
    uint16_t port;
} __attribute__((__packed__));

struct udp_socket {
    struct ump_chan ump_chan;
    struct capref urpc_frame;
    uint16_t src_port;
};

struct tcp_socket {
    struct ump_chan ump_chan;
    struct capref urpc_frame;
    bool is_connected;
};

struct tcp_server {
    char *server_name;
};

typedef void (*tcp_accept_handler_t)(struct tcp_socket *tcp_socket);

errval_t net_socket_arp_request(ip_addr_t addr, delayus_t timeout);

errval_t net_sockets_print_arp_table(void);

errval_t udp_socket_create(struct udp_socket *udp_socket, uint16_t src_port, bool is_high_speed_connection);
errval_t udp_socket_ump_send(struct ump_chan *ump_chan, ip_addr_t dst_address,
                             uint16_t dst_port, uint8_t *buf, size_t buflen);
inline errval_t udp_socket_send(struct udp_socket *udp_socket, ip_addr_t address,
                                uint16_t port, uint8_t *buf, size_t buflen)
{
    if(buflen > 1472) {
        return INET_ERR_UDP_PAYLOAD_TO_BIG;
    }
    return udp_socket_ump_send(&udp_socket->ump_chan, address, port, buf, buflen);
}

errval_t udp_socket_ump_start_recv(struct ump_chan *ump_chan, ip_addr_t *address,
                                   uint16_t *port);
errval_t udp_socket_recv(struct udp_socket *udp_socket, ip_addr_t *address,
                         uint16_t *port, uint8_t **buf, size_t *buflen);
errval_t udp_socket_close(struct udp_socket *udp_socket);


errval_t tcp_connect(struct tcp_socket *tcp_socket, uint16_t src_port, uint16_t dst_port,
                     ip_addr_t dst_ip, delayus_t timeout, bool is_high_speed_connection);
errval_t tcp_socket_send(struct tcp_socket *tcp_socket, uint8_t *buf, size_t buflen);
errval_t tcp_socket_recv(struct tcp_socket *tcp_socket, uint8_t **buf, size_t *buflen);
errval_t tcp_socket_close(struct tcp_socket *tcp_socket);

inline errval_t tcp_socket_register_recv(struct tcp_socket *tcp_socket,
                                         struct waitset *ws, struct event_closure closure)
{
    return ump_chan_register_recv(&tcp_socket->ump_chan, ws, closure);
}

errval_t tcp_server_create(struct tcp_server *tcp_server, uint16_t port,
                           tcp_accept_handler_t handler, bool is_high_speed_connection);
errval_t tcp_server_teardown(struct tcp_server *tcp_server);

#endif
