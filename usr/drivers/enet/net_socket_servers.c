
#include <errors/errno.h>
#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/nameserver.h>
#include "net_socket_servers.h"
#include <aos/deferred.h>
#include <collections/hash_table.h>
#include "udp.h"
#include "tcp.h"
#include "arp.h"

// This is a map from udp src_port to udp_endpoint
collections_hash_table *udp_sockets;

static bool ump_udp_recv_and_forward(struct udp_endpoint *udp_endpoint) {
    errval_t err;
    ip_addr_t address;
    uint16_t port;
    err = udp_socket_ump_start_recv(&udp_endpoint->ump_chan, &address, &port);

    if(address == 0 && port == 0) {
        // Free the UDP port and dont register on this channel anymore.
        collections_hash_delete(udp_sockets, udp_endpoint->src_port);
        free(udp_endpoint);
        return false;
    }


    struct udp_context context;
    err = udp_get_context(port, udp_endpoint->src_port, address, &context);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "udp_get_context failed");
        return false;
    }

    size_t buflen = 1500;
    uint8_t *buf = context.pkt->payload;
    err = ump_chan_recv_blocking(&udp_endpoint->ump_chan, &buf, &buflen, NULL);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "ump_chan_recv_blocking failed");
        return false;
    }

    assert(buf == context.pkt->payload);
    err = udp_send_context(context, buflen); 
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "udp_send_context failed");
        return false;
    }  
    return true;
}


static int ump_udp_high_speed_recv(void *arg) {
    struct udp_endpoint *udp_endpoint = (struct udp_endpoint *)arg;
    while(ump_udp_recv_and_forward(udp_endpoint)) {
        // Do nothing
    }
    return 1;
}

// Send packets over the network.
static void ump_udp_recv_handle(void *args)
{
    errval_t err;
    struct udp_endpoint *udp_endpoint = (struct udp_endpoint *)args;

    if(ump_udp_recv_and_forward(udp_endpoint)) {
        err = ump_chan_register_recv(&udp_endpoint->ump_chan, get_default_waitset(),
                                 MKCLOSURE(&ump_udp_recv_handle, udp_endpoint));
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "ump_chan_register_recv failed");
        } 

    }
}


static bool ump_tcp_recv_and_forward(struct tcp_connection_state *tcp_endpoint) {
    errval_t err;
    if(tcp_endpoint->is_closed || tcp_endpoint->is_reset) {
        // We already informed the user about the close, so we can just ignore this.
        return false;
    }

    struct tcp_context context;
    tcp_get_context(tcp_endpoint, &context);


    size_t buflen = 1500;
    uint8_t *buf = tcp_hdr_get_payload(context.pkt);
    err = ump_chan_recv_blocking(&tcp_endpoint->ump_chan, &buf, &buflen, NULL);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "ump_chan_recv_blocking failed");
        return false;
    }

    if (buflen == 0) {
        // Its time to say goodbye!
        context.pkt->fin = 1;
        context.pkt->ack = 1;
        tcp_endpoint->is_in_fin = true;
    } else {
        context.pkt->psh = 1;
        context.pkt->ack = 1;
    }


    assert(buf == tcp_hdr_get_payload(context.pkt));
    
    do {
        
        err = tcp_send_context(tcp_endpoint, context, buflen);
    } while (err == INET_ERR_TCP_SEND_WINDOW_FULL);
    
    if(err_is_fail(err)) {
        debug_printf("send buf slot is used\n");
        DEBUG_ERR(err, "tcp_send_context failed");
        return false;
    }

    if (tcp_endpoint->is_in_fin) {
        tcp_endpoint->next_seq_num = tcp_endpoint->next_seq_num + 1;
    }

    return true;
}

static int ump_tcp_high_speed_recv(void *arg) {
    struct tcp_connection_state *tcp_endpoint = (struct tcp_connection_state *)arg;
    while(ump_tcp_recv_and_forward(tcp_endpoint)) {
    }
    return 1;
}


static void ump_tcp_recv_handle(void *arg)
{
    errval_t err;
    struct tcp_connection_state *tcp_endpoint = (struct tcp_connection_state *)arg;

    if(ump_tcp_recv_and_forward(tcp_endpoint)) {
        err = ump_chan_register_recv(&tcp_endpoint->ump_chan, get_default_waitset(),
                                 MKCLOSURE(&ump_tcp_recv_handle, tcp_endpoint));
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "ump_chan_register_recv failed");
        } 
    }
}


static errval_t create_ump_server(struct ump_chan *ump_chan, struct capref urpc_frame,
                                  struct event_closure event_handler)
{
    errval_t err;
    struct frame_identity id;
    err = frame_identify(urpc_frame, &id);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_FRAME_IDENTIFY, err);

    void *urpc_buf;
    size_t urpc_bytes = id.bytes;
    err = paging_map_frame_attr(get_current_paging_state(), &urpc_buf, urpc_bytes,
                                urpc_frame, VREGION_FLAGS_READ_WRITE);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_MAP, err);

    ump_chan_init_split(ump_chan, urpc_buf, urpc_bytes, UMP_CHAN_BUF_LAYOUT_RECV_SEND);
    err = ump_chan_register_recv(ump_chan, get_default_waitset(), event_handler);
err:
    return err;
}

static errval_t create_high_speed_ump_server(struct ump_chan *ump_chan, struct capref urpc_frame,
                                             thread_func_t thread_func, void *arg)
{
    errval_t err;
    struct frame_identity id;
    err = frame_identify(urpc_frame, &id);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_FRAME_IDENTIFY, err);

    void *urpc_buf;
    size_t urpc_bytes = id.bytes;
    err = paging_map_frame_attr(get_current_paging_state(), &urpc_buf, urpc_bytes,
                                urpc_frame, VREGION_FLAGS_READ_WRITE);
    PUSH_GOTO_IF_ERR(err, LIB_ERR_PMAP_MAP, err);

    ump_chan_init_split(ump_chan, urpc_buf, urpc_bytes, UMP_CHAN_BUF_LAYOUT_RECV_SEND);
    thread_create(thread_func, arg);
err:
    return err;
}

static bool is_false(void *args)
{
    bool value = *(bool *)args;
    return !value;
}

static bool is_arp_avail(void *arg)
{
    uint64_t val = (uint64_t)arg;
    ip_addr_t ip_addr = (ip_addr_t)val;
    return arp_lookup_mac(ip_addr) != NULL;
}

static errval_t arp_request_or_timeout(ip_addr_t ip_addr, delayus_t timeout)
{
    if (arp_lookup_mac(ip_addr) != NULL) {
        return SYS_ERR_OK;
    }
    arp_request(ip_addr);
    uint64_t val = ip_addr;
    errval_t err = wait_for_or_timeout(timeout, &is_arp_avail, (void *)val);
    RETURN_IF_ERR(err);

    if (arp_lookup_mac(ip_addr) == NULL) {
        return INET_ERR_ARP_TIMEOUT;
    }
    return SYS_ERR_OK;
}

static errval_t server_handler(void *server_state, RpcMethod method,
                               RpcRequestWrap *request_wrap, struct capref request_cap,
                               RpcResponseWrap *response_wrap, struct capref *response_cap)
{
    errval_t err;

    switch (method) {
    case RPC_METHOD__GET_ARP_TABLE_REQUEST: {
        ip_addr_t* ips;
        size_t* macs;
        size_t count;
        err = get_arp_table(&ips, &macs, &count);
        RETURN_IF_ERR(err);

        ArpTableResponse* response = malloc(sizeof(ArpTableResponse));
        arp_table_response__init(response);
        response->ip_addr = ips;
        response->mac_addr = macs;
        response->n_ip_addr = count;
        response->n_mac_addr = count;
        response_wrap->arp_table_response = response;
        response_wrap->data_case = RPC_RESPONSE_WRAP__DATA_ARP_TABLE_RESPONSE;
        break;
    }
    case RPC_METHOD__CREATE_UDP_ENDPOINT: {
        assert(!capref_is_null(request_cap));
        uint16_t port = request_wrap->create_udp_endpoint->port;
        bool is_high_speed = request_wrap->create_udp_endpoint->is_high_speed_connection;
        void *res = collections_hash_find(udp_sockets, port);
        if (res != NULL) {
            return INET_ERR_UDP_PORT_BOUND_ALREADY;
        }

        struct udp_endpoint *udp_endpoint = malloc(sizeof(struct udp_endpoint));
        udp_endpoint->src_port = port;
        if(is_high_speed) {
            create_high_speed_ump_server(&udp_endpoint->ump_chan, request_cap,
                                         ump_udp_high_speed_recv, udp_endpoint);
        } else {
            create_ump_server(&udp_endpoint->ump_chan, request_cap,
                              MKCLOSURE(&ump_udp_recv_handle, udp_endpoint));
        }
        
        
        collections_hash_insert(udp_sockets, port, udp_endpoint);
        break;
    }
    case RPC_METHOD__CREATE_TCP_CONNECTION: {
        uint16_t dst_port = request_wrap->create_tcp_connection->dst_port;
        uint16_t src_port = request_wrap->create_tcp_connection->src_port;
        ip_addr_t dst_ip = request_wrap->create_tcp_connection->dst_ip;
        uint64_t timeout = request_wrap->create_tcp_connection->timeout;
        bool is_high_speed = request_wrap->create_tcp_connection->is_high_speed_connection;
        systime_t before_arp = systime_now();
        err = arp_request_or_timeout(dst_ip, timeout);
        // Subtract the time for the arp request from the timeout.
        uint64_t diff = systime_to_us(systime_now() - before_arp);
        timeout -= diff > 0 ? diff : 0;
        RETURN_IF_ERR(err);

        struct tcp_connection_state *tcp_state = NULL;
        err = tcp_start_handshake(&tcp_state, dst_ip, src_port, dst_port);
        assert(tcp_state->is_in_handshake == true);
        RETURN_IF_ERR(err);
        // Work now since we need to wait for the timeout now.
        if(is_high_speed) {
            create_high_speed_ump_server(&tcp_state->ump_chan, request_cap,
                                         ump_tcp_high_speed_recv, tcp_state);
        } else {
            create_ump_server(&tcp_state->ump_chan, request_cap,
                              MKCLOSURE(&ump_tcp_recv_handle, tcp_state));
        }
        
        err = wait_for_or_timeout(timeout, &is_false, &tcp_state->is_in_handshake);
        RETURN_IF_ERR(err);

        if (tcp_state->is_in_handshake) {
            tcp_destroy_connection(tcp_state->src_port, tcp_state->dst_port,
                                   tcp_state->dst_ip);
            return INET_ERR_TCP_HANDSHAKE_TIMEOUT;
        }
        if (tcp_state->is_reset) {
            tcp_destroy_connection(tcp_state->src_port, tcp_state->dst_port,
                                   tcp_state->dst_ip);
            return INET_ERR_TCP_RESET;
        }
        break;
    }
    case RPC_METHOD__ARP_REQUEST: {
        ip_addr_t ip_addr = request_wrap->arp_request->ip_addr;
        uint64_t timeout = request_wrap->arp_request->timeout;
        return arp_request_or_timeout(ip_addr, timeout);
        break;
    }
    case RPC_METHOD__CREATE_TCP_SERVER: {
        uint16_t port = request_wrap->create_tcp_server->port;
        char *service_name = request_wrap->create_tcp_server->service_name;
        bool is_high_speed = request_wrap->create_tcp_server->is_high_speed_connection;

        nameservice_chan_t nameservice_chan;
        err = nameservice_lookup(service_name, &nameservice_chan);
        RETURN_IF_ERR(err);
        tcp_create_server(port, nameservice_chan, is_high_speed);
        break;
    }
    default:
        DEBUG_PRINTF("No supported method %d\n", method);
    }
    return SYS_ERR_OK;
}

errval_t udp_servers_handle_packet(ip_addr_t src, uint16_t src_port, uint16_t dst_port,
                                   uint8_t *buf, size_t buflen)
{
    errval_t err;
    struct udp_endpoint *udp_endpoint = collections_hash_find(udp_sockets, dst_port);
    if (udp_endpoint == NULL) {
        // Drop the packet since nobody listens on this port.
        DEBUG_PRINTF("Dropped packet since nobody listens on port %d.\n", dst_port);
        return SYS_ERR_OK;
    }

    // Check if the user is ready to get the packet.
    // If not we can drop the packet.... its UDP.
    
    if(ump_chan_can_send(&udp_endpoint->ump_chan, buflen + sizeof(struct udp_ump_header))) {
        err = udp_socket_ump_send(&udp_endpoint->ump_chan, src, src_port, buf, buflen);
        RETURN_IF_ERR(err);
    }
    return SYS_ERR_OK;
}

errval_t tcp_servers_tcp_handle_packet(struct tcp_connection_state *connection,
                                       uint8_t *buf, size_t buflen)
{
    errval_t err;
    if(ump_chan_can_send(&connection->ump_chan, buflen + sizeof(struct udp_ump_header))) {
        err = ump_chan_send(&connection->ump_chan, buf, buflen, NULL_CAP);
        RETURN_IF_ERR(err);
        return SYS_ERR_OK;
    } else {
        return INET_ERR_TCP_CLIENT_NOT_READY;
    }
}

errval_t tcp_servers_tcp_handle_close(struct tcp_connection_state *connection)
{
    errval_t err;
    // Tell the user the session is dead.
    err = ump_chan_send(&connection->ump_chan, NULL, 0, NULL_CAP);
    RETURN_IF_ERR(err);
    err = ump_chan_deregister_recv(&connection->ump_chan);
    connection->is_closed = true;
    if(err == LIB_ERR_CHAN_NOT_REGISTERED) {
        // This is ok, there are high speed channels.
        err = SYS_ERR_OK;
    }
    RETURN_IF_ERR(err);
    return err;
}


errval_t tcp_servers_handle_connection_request(struct tcp_connection_state *connection,
                                               nameservice_chan_t chan, bool is_high_speed)
{
    errval_t err;
    assert(connection != NULL);
    ConnectTcpClientRequest req = CONNECT_TCP_CLIENT_REQUEST__INIT;
    req.ip_addr = connection->dst_ip;
    req.port = connection->dst_port;
    REQUEST_WRAP(req_wrap, connect_tcp_client, CONNECT_TCP_CLIENT, &req);
    RpcResponseWrap *res_wrap = NULL;
    struct capref ump_frame;
    err = nameservice_rpc_proto(chan, RPC_METHOD__CONNECT_TCP_CLIENT, &req_wrap, NULL_CAP,
                                &res_wrap, &ump_frame);
    RESPONSE_WRAP_DESTROY(res_wrap);
    assert(!capref_is_null(ump_frame));

    if(is_high_speed) {
        create_high_speed_ump_server(&connection->ump_chan, ump_frame,
                                     ump_tcp_high_speed_recv, connection);
    } else {
        create_ump_server(&connection->ump_chan, ump_frame,
                      MKCLOSURE(&ump_tcp_recv_handle, connection));
    }
    

    return err;
}


errval_t init_netsocket_servers(void)
{
    run_dispatcher_threads(5, get_default_waitset());

    collections_hash_create(&udp_sockets, NULL);

    errval_t err;
    err = nameservice_register_proto("net-socket-servers", server_handler, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "nameservice_register_proto");
        return err;
    }
    return SYS_ERR_OK;
}