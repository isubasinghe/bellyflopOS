#include <netutil/net_sockets.h>
#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/nameserver.h>
#include <netutil/etharp.h>

nameservice_chan_t name_service_chan;
bool is_name_service_chan_initialized = false;

static errval_t set_sockets_nameserver_chan(void)
{
    if (is_name_service_chan_initialized) {
        return SYS_ERR_OK;
    }
    errval_t err;
    err = nameservice_lookup("net-socket-servers", &name_service_chan);
    RETURN_IF_ERR(err);
    is_name_service_chan_initialized = true;
    return SYS_ERR_OK;
}

errval_t net_socket_arp_request(ip_addr_t addr, delayus_t timeout)
{
    errval_t err;
    err = set_sockets_nameserver_chan();
    RETURN_IF_ERR(err);
    ArpRequest arp_request = ARP_REQUEST__INIT;
    arp_request.ip_addr = addr;
    arp_request.timeout = timeout;
    REQUEST_WRAP(req_wrap, arp_request, ARP_REQUEST, &arp_request);
    RpcResponseWrap *res_wrap = NULL;
    err = nameservice_rpc_proto(name_service_chan, RPC_METHOD__ARP_REQUEST, &req_wrap,
                                NULL_CAP, &res_wrap, NULL);
    RETURN_IF_ERR(err);
    RESPONSE_WRAP_DESTROY(res_wrap);
    return err;
}


errval_t net_sockets_print_arp_table(void)
{
    errval_t err;
    err = set_sockets_nameserver_chan();
    RETURN_IF_ERR(err);
    RpcResponseWrap *res_wrap = NULL;
    err = nameservice_rpc_proto(name_service_chan, RPC_METHOD__GET_ARP_TABLE_REQUEST, NULL,
                                NULL_CAP, &res_wrap, NULL);
    RETURN_IF_ERR(err);
    ArpTableResponse* res = res_wrap->arp_table_response;
    assert(res != NULL);
    assert(res->n_ip_addr == res->n_mac_addr);
    struct eth_addr mac;
    if(res->n_ip_addr == 0) {
        printf("Arp table is empty\n");
    }
    for(int i = 0; i < res->n_ip_addr; i++) {
        print_ip(res->ip_addr[i]);
        printf(":\t");
        eth_addr_from_uint64(&mac, res->mac_addr[i]);
        print_eth_addr(&mac);
        printf("\n");
    }
    RESPONSE_WRAP_DESTROY(res_wrap);
    return err;
}

errval_t udp_socket_create(struct udp_socket *udp_socket, uint16_t src_port, bool is_high_speed_connection)
{
    errval_t err;
    err = set_sockets_nameserver_chan();
    RETURN_IF_ERR(err);
    uint8_t *urpc;
    struct capref urpc_frame;
    struct frame_identity urpc_frame_id;
    err = ump_create_frame((void **)&urpc, 4 * BASE_PAGE_SIZE, &urpc_frame_id, &urpc_frame);
    RETURN_IF_ERR(err);


    CreateUdpEndpointRequest req = CREATE_UDP_ENDPOINT_REQUEST__INIT;
    req.port = src_port;
    req.is_high_speed_connection = is_high_speed_connection;

    REQUEST_WRAP(req_wrap, create_udp_endpoint, CREATE_UDP_ENDPOINT, &req);

    RpcResponseWrap *res_wrap = NULL;
    err = nameservice_rpc_proto(name_service_chan, RPC_METHOD__CREATE_UDP_ENDPOINT,
                                &req_wrap, urpc_frame, &res_wrap, NULL);
    RESPONSE_WRAP_DESTROY(res_wrap);
    RETURN_IF_ERR(err);

    ump_chan_init_split(&udp_socket->ump_chan, urpc, urpc_frame_id.bytes,
                        UMP_CHAN_BUF_LAYOUT_SEND_RECV);
    udp_socket->urpc_frame = urpc_frame;

    return SYS_ERR_OK;
}

errval_t tcp_connect(struct tcp_socket *tcp_socket, uint16_t src_port, uint16_t dst_port,
                     ip_addr_t dst_ip, delayus_t timeout, bool is_high_speed_connection)
{
    errval_t err;
    err = set_sockets_nameserver_chan();
    RETURN_IF_ERR(err);
    uint8_t *urpc;
    struct capref urpc_frame;
    struct frame_identity urpc_frame_id;
    err = ump_create_frame((void **)&urpc, 4 * BASE_PAGE_SIZE, &urpc_frame_id, &urpc_frame);
    RETURN_IF_ERR(err);

    CreateTcpConnectionRequest req = CREATE_TCP_CONNECTION_REQUEST__INIT;
    req.src_port = src_port;
    req.dst_port = dst_port;
    req.dst_ip = dst_ip;
    req.timeout = timeout;
    req.is_high_speed_connection = is_high_speed_connection;

    REQUEST_WRAP(req_wrap, create_tcp_connection, CREATE_TCP_CONNECTION, &req);

    // DEBUG_PRINTF("Connecting from port %d %d %d\n", req.dst_port, req.src_port,
    //              req.dst_ip);
    RpcResponseWrap *res_wrap = NULL;
    err = nameservice_rpc_proto(name_service_chan, RPC_METHOD__CREATE_TCP_CONNECTION,
                                &req_wrap, urpc_frame, &res_wrap, NULL);
    RESPONSE_WRAP_DESTROY(res_wrap);
    RETURN_IF_ERR(err);

    ump_chan_init_split(&tcp_socket->ump_chan, urpc, urpc_frame_id.bytes,
                        UMP_CHAN_BUF_LAYOUT_SEND_RECV);
    tcp_socket->is_connected = true;
    tcp_socket->urpc_frame = urpc_frame;

    return SYS_ERR_OK;
}

errval_t tcp_socket_send(struct tcp_socket *tcp_socket, uint8_t *buf, size_t buflen)
{
    if (!tcp_socket->is_connected) {
        return INET_ERR_TCP_CONNECTION_CLOSED;
    }
    if (buflen > 1400) {
        for (size_t i = 0; i < buflen; i += 1400) {
            size_t len = MIN(buflen - i, 1400);
            errval_t err = ump_chan_send(&tcp_socket->ump_chan, buf + i, len, NULL_CAP);
            if (err_is_fail(err)) {
                return err;
            }
        }
        return SYS_ERR_OK;
    }
    return ump_chan_send(&tcp_socket->ump_chan, buf, buflen, NULL_CAP);
}

errval_t tcp_socket_recv(struct tcp_socket *tcp_socket, uint8_t **buf, size_t *buflen)
{
    errval_t err = ump_chan_recv_blocking(&tcp_socket->ump_chan, buf, buflen, NULL);
    if (*buflen == 0) {
        // Send the close message back.
        tcp_socket_close(tcp_socket);
        tcp_socket->is_connected = false;
        return INET_ERR_TCP_CONNECTION_CLOSED;
    }
    return err;
}

errval_t tcp_socket_close(struct tcp_socket *tcp_socket)
{
    return ump_chan_send(&tcp_socket->ump_chan, NULL, 0, NULL_CAP);
}

errval_t udp_socket_ump_send(struct ump_chan *ump_chan, ip_addr_t address, uint16_t port,
                             uint8_t *buf, size_t buflen)
{
    errval_t err;
    struct udp_ump_header header;
    header.address = address;
    header.port = port;
    err = ump_chan_send(ump_chan, (uint8_t *)&header, sizeof(struct udp_ump_header),
                        NULL_CAP);
    RETURN_IF_ERR(err);
    err = ump_chan_send(ump_chan, buf, buflen, NULL_CAP);
    RETURN_IF_ERR(err);
    return SYS_ERR_OK;
}


errval_t udp_socket_ump_start_recv(struct ump_chan *ump_chan, ip_addr_t *address,
                                   uint16_t *port)
{
    errval_t err;
    struct udp_ump_header udp_ump_header;
    size_t header_buflen = sizeof(struct udp_ump_header);
    uint8_t *header_buf = (uint8_t *)&udp_ump_header;
    err = ump_chan_recv_blocking(ump_chan, &header_buf, &header_buflen, NULL);
    RETURN_IF_ERR(err);
    assert(header_buflen == sizeof(struct udp_ump_header));

    *port = udp_ump_header.port;
    *address = udp_ump_header.address;
    return SYS_ERR_OK;
}

errval_t udp_socket_recv(struct udp_socket *udp_socket, ip_addr_t *address,
                         uint16_t *port, uint8_t **buf, size_t *buflen)
{
    errval_t err;
    err = udp_socket_ump_start_recv(&udp_socket->ump_chan, address, port);
    RETURN_IF_ERR(err);

    err = ump_chan_recv_blocking(&udp_socket->ump_chan, buf, buflen, NULL);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

inline errval_t udp_socket_close(struct udp_socket *udp_socket)
{
    return udp_socket_ump_send(&udp_socket->ump_chan, 0, 0, 0, 0);
}

static errval_t tcp_server_handler(void *server_state, RpcMethod method,
                                   RpcRequestWrap *request_wrap, struct capref request_cap,
                                   RpcResponseWrap *response_wrap,
                                   struct capref *response_cap)
{
    errval_t err;
    tcp_accept_handler_t accept_handler = (tcp_accept_handler_t)server_state;
    switch (method) {
    case RPC_METHOD__CONNECT_TCP_CLIENT: {
        struct tcp_socket *tcp_socket = malloc(sizeof(struct tcp_socket));

        uint8_t *urpc;
        struct capref urpc_frame;
        struct frame_identity urpc_frame_id;
        err = ump_create_frame((void **)&urpc, 4 * BASE_PAGE_SIZE, &urpc_frame_id, &urpc_frame);
        RETURN_IF_ERR(err);

        ump_chan_init_split(&tcp_socket->ump_chan, urpc, urpc_frame_id.bytes,
                            UMP_CHAN_BUF_LAYOUT_SEND_RECV);
        tcp_socket->is_connected = true;
        tcp_socket->urpc_frame = urpc_frame;
        accept_handler(tcp_socket);

        *response_cap = urpc_frame;
        break;
    }
    default:
        DEBUG_PRINTF("No supported method %d\n", method);
    }
    return SYS_ERR_OK;
}

errval_t tcp_server_create(struct tcp_server *tcp_server, uint16_t port,
                           tcp_accept_handler_t accept_handler, bool is_high_speed_connection)
{
    errval_t err;
    err = set_sockets_nameserver_chan();
    RETURN_IF_ERR(err);

    size_t name_size = sizeof("tcp-server-port:") + sizeof("65000");
    tcp_server->server_name = malloc(name_size);
    snprintf(tcp_server->server_name, name_size, "tcp-server-port:%d", port);

    // We use the nameservice to avoid raced on the same port.
    err = nameservice_register_proto(tcp_server->server_name, tcp_server_handler,
                                     (void *)accept_handler);
    if (err_is_fail(err)) {
        free(tcp_server->server_name);
        return err;
    }

    CreateTcpServerRequest req = CREATE_TCP_SERVER_REQUEST__INIT;
    req.port = port;
    req.service_name = tcp_server->server_name;
    req.is_high_speed_connection = is_high_speed_connection;

    REQUEST_WRAP(req_wrap, create_tcp_server, CREATE_TCP_SERVER, &req);
    RpcResponseWrap *res_wrap = NULL;
    err = nameservice_rpc_proto(name_service_chan, RPC_METHOD__CREATE_TCP_SERVER,
                                &req_wrap, NULL_CAP, &res_wrap, NULL);
    RESPONSE_WRAP_DESTROY(res_wrap);
    RETURN_IF_ERR(err);

    return SYS_ERR_OK;
}

errval_t tcp_server_teardown(struct tcp_server *tcp_server)
{
    errval_t err;
    err = nameservice_deregister(tcp_server->server_name);
    free(tcp_server->server_name);
    return err;
}
