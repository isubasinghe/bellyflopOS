#include "tcp.h"
#include "netutil/htons.h"
#include "netutil/checksum.h"
#include <aos/deferred.h>
#include <collections/hash_table.h>
#include <net_socket_servers.h>


uint32_t last_seq_num;
uint32_t last_ack_num;

static struct thread_mutex connection_table_mutex;
collections_hash_table *tcp_connection_table;

collections_hash_table *port_state_map;
collections_hash_table *port_connection_type_map;


void tcp_create_server(uint16_t port, nameservice_chan_t chan, bool is_high_speed_connection)
{
    size_t is_high_speed_connection_arg = is_high_speed_connection;
    thread_mutex_lock_nested(&connection_table_mutex);
    collections_hash_insert(port_state_map, port, (void *)chan);
    collections_hash_insert(port_connection_type_map, port, (void *)is_high_speed_connection_arg);
    thread_mutex_unlock(&connection_table_mutex);
}

static nameservice_chan_t get_port_state(uint16_t port)
{
    thread_mutex_lock_nested(&connection_table_mutex);
    nameservice_chan_t chan = (nameservice_chan_t)collections_hash_find(port_state_map, port);
    thread_mutex_unlock(&connection_table_mutex);
    return chan;
}

static bool is_port_high_speed(uint16_t port)
{
    thread_mutex_lock_nested(&connection_table_mutex);
    size_t is_high_speed_connection_arg = (size_t) (nameservice_chan_t)collections_hash_find(port_connection_type_map, port);
    thread_mutex_unlock(&connection_table_mutex);
    return is_high_speed_connection_arg;
}


static errval_t send_ack(struct tcp_connection_state *connection);

static inline uint64_t get_tcp_con_identifier(uint16_t src_port, uint16_t dst_port,
                                              ip_addr_t dst_ip)
{
    return (((uint64_t)dst_ip) << 32) | (((uint64_t)dst_port) << 16)
           | ((uint64_t)src_port);
}


static errval_t create_new_connection(struct tcp_connection_state **ret,
                                      uint16_t src_port, uint16_t dst_port,
                                      ip_addr_t dst_ip, uint32_t seq_num, uint32_t ack_num)
{
    thread_mutex_lock_nested(&connection_table_mutex);
    if (collections_hash_find(tcp_connection_table,
                              get_tcp_con_identifier(src_port, dst_port, dst_ip))
        != NULL) {
        // debug_printf("Connection already exist ssrc_port: %d dst_port: %d dst_ip: %d\n",
        //          src_port, dst_port, dst_ip);;
        thread_mutex_unlock(&connection_table_mutex);
        return INET_ERR_TCP_STATE_EXISTS_ALREADY;
    }

    // debug_printf("Creating new connection ssrc_port: %d dst_port: %d dst_ip: %d\n",
    //              src_port, dst_port, dst_ip);;

    struct tcp_connection_state *connection = malloc(sizeof(struct tcp_connection_state));

    thread_mutex_init(&connection->mutex);
    connection->is_in_handshake = true;
    connection->is_in_fin = false;
    connection->is_reset = false;
    connection->is_closed = false;
    connection->last_seq_num_sent = seq_num;
    connection->next_seq_num = seq_num;
    connection->max_to_ack = ack_num;
    connection->src_port = src_port;
    connection->dst_port = dst_port;
    connection->dst_ip = dst_ip;
    connection->next_send_slot = 0;
    connection->higest_ack_recv = 0;
    memset(connection->send_buf, 0, sizeof(connection->send_buf));
    connection->rtt_timer = systime_now();
    *ret = connection;

    // DEBUG_PRINTF("Creating new connection ssrc_port: %d dst_port: %d dst_ip: %d\n",
    //              src_port, dst_port, dst_ip);;

    collections_hash_insert(tcp_connection_table,
                            get_tcp_con_identifier(src_port, dst_port, dst_ip),
                            connection);
    // DEBUG_PRINTF("Creating new connection ssrc_port: %d dst_port: %d dst_ip: %d\n",
    //              src_port, dst_port, dst_ip);;
    thread_mutex_unlock(&connection_table_mutex);
    return SYS_ERR_OK;
}

static struct tcp_connection_state *get_connection(uint16_t src_port, uint16_t dst_port,
                                                   ip_addr_t dst_ip)
{
    thread_mutex_lock_nested(&connection_table_mutex);
    struct tcp_connection_state* res = 
        collections_hash_find(tcp_connection_table,
                              get_tcp_con_identifier(src_port, dst_port, dst_ip));
    thread_mutex_unlock(&connection_table_mutex);
    return res;
}

void tcp_destroy_connection(uint16_t src_port, uint16_t dst_port, ip_addr_t dst_ip)
{
    thread_mutex_lock_nested(&connection_table_mutex);
    struct tcp_connection_state *connection = collections_hash_find(
        tcp_connection_table, get_tcp_con_identifier(src_port, dst_port, dst_ip));
    // debug_printf("Destroying connection src_port: %d dst_port: %d dst_ip: %d\n",
    //              src_port, dst_port, dst_ip);
    if (connection != NULL) {
        collections_hash_delete(tcp_connection_table,
                                get_tcp_con_identifier(src_port, dst_port, dst_ip));
        free(connection);
    }
    thread_mutex_unlock(&connection_table_mutex);
}


errval_t tcp_get_context(struct tcp_connection_state *connection, struct tcp_context *ret)
{
    errval_t err;
    err = ip_get_send_context(connection->dst_ip, IP_PROTO_TCP, &ret->__ip_context);
    RETURN_IF_ERR(err);
    ret->pkt = (struct tcp_hdr *)ret->__ip_context.pkt->payload;
    memset(ret->pkt, 0, sizeof(struct tcp_hdr));
    ret->pkt->src_port = htons(connection->src_port);
    ret->pkt->dst_port = htons(connection->dst_port);
    ret->pkt->data_offset = 20 / 4;
    ret->pkt->window_size = htons(64240);
    return SYS_ERR_OK;
}

errval_t tcp_send_context(struct tcp_connection_state *connection,
                          struct tcp_context context, size_t length)
{
    errval_t err = SYS_ERR_OK;
    thread_mutex_lock_nested(&connection->mutex);
    // make sure there is a send buf free-
     if (length != 0) {
        // This is not an ack so pack it in the send buf window if possible.
        struct send_buf_slot *send_buf_slot
            = &connection->send_buf[connection->next_send_slot];
        if (send_buf_slot->is_used) {
            err =  INET_ERR_TCP_SEND_WINDOW_FULL;
            GOTO_IF_ERR(err, out);
        }
    }



    
    uint16_t total_length = length + sizeof(struct tcp_hdr);
    last_seq_num = context.pkt->seq_num;

    context.pkt->seq_num = htonl(connection->next_seq_num);
    context.pkt->ack_num = htonl(connection->max_to_ack);

    context.pkt->chksum = 0;
    context.pkt->chksum = udp_checksum(context.pkt, total_length,
                                       context.__ip_context.pkt);

    connection->last_seq_num_sent = connection->next_seq_num;
    connection->next_seq_num += length;


    if (length != 0) {
        // This is not an ack so pack it in the send buf window if possible.
        struct send_buf_slot *send_buf_slot
            = &connection->send_buf[connection->next_send_slot];
        if (send_buf_slot->is_used) {
            // We checked this earlier.
            assert(false);
            err = INET_ERR_TCP_SEND_WINDOW_FULL;
            GOTO_IF_ERR(err, out);
        }
        send_buf_slot->is_used = true;
        memcpy(send_buf_slot->data, context.pkt, total_length);
        send_buf_slot->length = total_length;
        send_buf_slot->expected_ack = connection->next_seq_num;
        connection->next_send_slot = (connection->next_send_slot + 1) % SEND_BUF_SLOTS;
    }


    err = ip_send_context(context.__ip_context, total_length);
    GOTO_IF_ERR(err, out);

out:
    thread_mutex_unlock(&connection->mutex);
    return err;
}

errval_t tcp_start_handshake(struct tcp_connection_state **ret, ip_addr_t dst_ip,
                             uint16_t src_port, uint16_t dst_port)
{
    // DEBUG_PRINTF("Sending handshake to  %d.\n", dst_ip);
    
    uint32_t seq_num = ntohl(42);
    uint32_t ack_num = 0;

    struct tcp_connection_state *connection;
    errval_t err;
    err = create_new_connection(&connection,
                                src_port, dst_port, dst_ip, seq_num, 0);
    RETURN_IF_ERR(err);
    thread_mutex_lock_nested(&connection->mutex);
    connection->is_in_handshake = true;

    struct tcp_context context;
    err = tcp_get_context(connection, &context);
    GOTO_IF_ERR(err, out);
    context.pkt->syn = 1;
    context.pkt->seq_num = htonl(seq_num);
    context.pkt->ack_num = htonl(ack_num);

    connection->next_seq_num = seq_num + 1;
    connection->last_seq_num_sent = seq_num;

    err = tcp_send_context(connection, context, 0);
    GOTO_IF_ERR(err, out);
    connection->next_seq_num = connection->next_seq_num + 1;
    *ret = connection;

out:
    thread_mutex_unlock(&connection->mutex);
    return err;
}


static errval_t handle_handshake_syn(struct tcp_hdr *tcp_hdr, ip_addr_t src_ip)
{
    assert(tcp_hdr->syn == 1);
    errval_t err = SYS_ERR_OK;

    uint16_t src_port = ntohs(tcp_hdr->src_port);
    uint16_t dst_port = ntohs(tcp_hdr->dst_port);
    struct tcp_connection_state *connection = NULL;
    if (tcp_hdr->ack == 1) {
        connection = get_connection(dst_port, src_port, src_ip);
        if (connection == NULL) {
            // We never agreed on a connection with this peer.
            return SYS_ERR_OK;
        }
        thread_mutex_lock_nested(&connection->mutex);
        connection->rtt_timer = systime_now() - connection->rtt_timer;
        connection->is_in_handshake = false;
        connection->higest_ack_recv = ntohl(tcp_hdr->ack_num);
        connection->max_to_ack = ntohl(tcp_hdr->seq_num) + 1;
        err = send_ack(connection);
        GOTO_IF_ERR(err, out);
    } else if (tcp_hdr->ack == 0) {
        // Check if we have a server running on this port.
        nameservice_chan_t port_state = get_port_state(dst_port);
        if (port_state == NULL) {
            return SYS_ERR_OK;
        }
        bool is_high_speed = is_port_high_speed(dst_port);

        uint32_t seq_num = ntohl(42);
        uint32_t ack_num = ntohl(tcp_hdr->seq_num) + 1;
        err = create_new_connection(&connection,
                                    dst_port, src_port, src_ip, seq_num,
                                    ack_num);
        // debug_err(__FILE__, __func__, __LINE__, err, "msg1");
        RETURN_IF_ERR(err);
        thread_mutex_lock_nested(&connection->mutex);
        struct tcp_context context;
        err = tcp_get_context(connection, &context);
        // debug_err(__FILE__, __func__, __LINE__, err, "tcp_get_context");
        GOTO_IF_ERR(err, out);
        context.pkt->syn = 1;
        context.pkt->ack = 1;

        err = tcp_send_context(connection, context, 0);
        // debug_err(__FILE__, __func__, __LINE__, err, "send context");
        GOTO_IF_ERR(err, out);
        connection->next_seq_num = connection->next_seq_num + 1;
        err = tcp_servers_handle_connection_request(connection, port_state, is_high_speed);
        // debug_err(__FILE__, __func__, __LINE__, err, "new connection");
        GOTO_IF_ERR(err, out);
    }

out:
    thread_mutex_unlock(&connection->mutex);
    return err;
}

__unused static errval_t send_ack_fin(struct tcp_connection_state *connection)
{
    thread_mutex_lock_nested(&connection->mutex);
    errval_t err;
    struct tcp_context context;
    err = tcp_get_context(connection, &context);
    GOTO_IF_ERR(err, out);;
    context.pkt->ack = 1;
    context.pkt->fin = 1;
    err = tcp_send_context(connection, context, 0);
    GOTO_IF_ERR(err, out);
out:
    thread_mutex_unlock(&connection->mutex);
    return err;
}

static errval_t handle_fin(struct tcp_hdr *tcp_hdr, ip_addr_t src_ip)
{
    errval_t err = SYS_ERR_OK;
    uint16_t src_port = ntohs(tcp_hdr->src_port);
    uint16_t dst_port = ntohs(tcp_hdr->dst_port);
    uint32_t seq_num = ntohl(tcp_hdr->seq_num);
    uint32_t ack_num = ntohl(tcp_hdr->ack_num);
    struct tcp_connection_state *connection = get_connection(dst_port, src_port, src_ip);
    if (connection == NULL) {
        // We never agreed on a connection with this peer.
        return SYS_ERR_OK;
    }
    // Lock the table otherwise the time might come and deadlock us.
    thread_mutex_lock_nested(&connection_table_mutex);
    thread_mutex_lock_nested(&connection->mutex);
    // debug_printf("Handeling fin. connection->next_seq_num %d,  max_to_ack %d, "
    //              "ack_num %d, seq_num %d\n",
    //              connection->next_seq_num, connection->max_to_ack, ack_num, seq_num);
    if (connection->next_seq_num == ack_num && connection->max_to_ack == seq_num) {
        // TODO: This is a bit of a hack:
        
        connection->max_to_ack = connection->max_to_ack + 1;
        connection->is_closed = true;
        err = tcp_servers_tcp_handle_close(connection);
        // debug_err(__FILE__, __func__, __LINE__, err, "tcp_servers_tcp_handle_close");
        GOTO_IF_ERR(err, out);
        tcp_destroy_connection(dst_port, src_port, src_ip);

        err = send_ack_fin(connection);
        // debug_err(__FILE__, __func__, __LINE__, err, "send_ack_fin");
        GOTO_IF_ERR(err, out);
        
    } else {
        // We are not ready yet since we haven't got all the promised data.
    }
    
out:
    thread_mutex_unlock(&connection->mutex);
    thread_mutex_unlock(&connection_table_mutex);
    return err;
}

static errval_t send_ack(struct tcp_connection_state *connection)
{
    thread_mutex_lock_nested(&connection->mutex);
    errval_t err;
    struct tcp_context context;
    err = tcp_get_context(connection, &context);
    GOTO_IF_ERR(err, out);
    assert(context.pkt != NULL);
    context.pkt->ack = 1;
    err = tcp_send_context(connection, context, 0);
    GOTO_IF_ERR(err, out);
out:
    thread_mutex_unlock(&connection->mutex);
    return err;
}

int start_acking = 0;

static errval_t handle_connection_packet(struct tcp_hdr *tcp_hdr, ip_addr_t src_ip,
                                         size_t packet_length)
{
    errval_t err = SYS_ERR_OK;
    size_t header_length = tcp_hdr->data_offset * 4;
    size_t payload_length = packet_length - header_length;
    uint16_t src_port = ntohs(tcp_hdr->src_port);
    uint16_t dst_port = ntohs(tcp_hdr->dst_port);
    uint32_t seq_num = ntohl(tcp_hdr->seq_num);
    uint32_t ack_num = ntohl(tcp_hdr->ack_num);
    struct tcp_connection_state *connection = get_connection(dst_port, src_port, src_ip);
    
    if (connection == NULL) {
        // We never agreed on a connection with this peer.
        return SYS_ERR_OK;
    }
    thread_mutex_lock_nested(&connection->mutex);


    if (tcp_hdr->rst) {
        // Reset the connection.
        connection->is_in_handshake = false;
        connection->is_reset = true;
        err = SYS_ERR_OK;
        goto out;
    }

    if (connection->is_in_handshake) {
        // End the handshake.
        connection->rtt_timer = systime_now() - connection->rtt_timer;
        connection->is_in_handshake = false;
        assert(payload_length == 0);
    }

    connection->higest_ack_recv = ack_num;

    while (connection->send_buf[connection->not_acked_slot].is_used
           && connection->send_buf[connection->not_acked_slot].expected_ack <= ack_num) {
        connection->send_buf[connection->not_acked_slot].is_used = false;
        connection->not_acked_slot = (connection->not_acked_slot + 1) % SEND_BUF_SLOTS;
    }


    if (payload_length > 0) {
        // We only want to ack a packet if its the next one we expect.
        // This allows us to not care about reordering of packets and makes the
        // implementation much simpler.
        if (connection->max_to_ack == seq_num) {
            uint8_t *data_ptr = tcp_hdr_get_payload(tcp_hdr);
            err = tcp_servers_tcp_handle_packet(connection, data_ptr, payload_length);
            if (err == INET_ERR_TCP_CLIENT_NOT_READY) {
                // Dont ack the packet. This is going to fast for the client.
                // DEBUG_PRINTF("TCP packet dropped: Client not ready.\n");
                err = SYS_ERR_OK;
                goto out;
            } 
            connection->max_to_ack = seq_num + payload_length;
            err = send_ack(connection);
            GOTO_IF_ERR(err, out);
        } else if (connection->max_to_ack > seq_num) {
            // We have already acked this packet.
            // Ack it again to make sure the client knows we have received it.
            err = send_ack(connection);
            GOTO_IF_ERR(err, out);
        } else {
            // DEBUG_PRINTF("Did not pass seq_num check. max_to_ack %d, seq_num %d\n",
            //              connection->max_to_ack, seq_num);
        }
    }

out:
    thread_mutex_unlock(&connection->mutex);
    return err;
}

errval_t tcp_handle_packet(struct tcp_hdr *tcp_hdr, ip_addr_t src_ip, size_t packet_length)
{
    // debug_printf("tcp_handle_packet\n");
    errval_t err = SYS_ERR_OK;
    if (tcp_hdr->syn == 1) {
        err = handle_handshake_syn(tcp_hdr, src_ip);
    } else if (tcp_hdr->fin == 1 && tcp_hdr->ack == 1) {
        err = handle_fin(tcp_hdr, src_ip);
    } else {
        err = handle_connection_packet(tcp_hdr, src_ip, packet_length);
    }
    last_ack_num = htonl(tcp_hdr->ack_num);

    return err;
}

size_t tcp_send_buf_free_bytes(uint16_t src_port, uint16_t dst_port)
{
    return 0;
}


static void tcp_check_acks(void *arg)
{
    thread_mutex_lock_nested(&connection_table_mutex);
    if (collections_hash_traverse_start(tcp_connection_table) != 1) {
        // Something else is still traversing the hash table.
        // Lets come back later.
        thread_mutex_unlock(&connection_table_mutex);
        return;
    }


    struct tcp_connection_state *connection = NULL;
    uint64_t identifier;
    while ((connection = collections_hash_traverse_next(tcp_connection_table, &identifier))
           != NULL) {
        // assert(connection->guard);
        thread_mutex_lock_nested(&connection->mutex);
        struct send_buf_slot *send_buf = connection->send_buf;
        for (uint64_t i = connection->not_acked_slot; send_buf[i].is_used;
             i = (i + 1) % SEND_BUF_SLOTS) {
            systime_t now = systime_now();
            if (send_buf[i].time_sent
                    + connection->rtt_timer * TCP_RETRANSMISSION_RTT_MULTIPLIER
                < now) {
                // DEBUG_PRINTF("Retransmitting\n");
                send_buf[i].time_sent = now;
                struct ip_context ip_context;
                errval_t err;
                err = ip_get_send_context(connection->dst_ip, IP_PROTO_TCP, &ip_context);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "Error when retransmitting tcp");
                    thread_mutex_unlock(&connection->mutex);
                    goto out;
                }

                memcpy(ip_context.pkt->payload, send_buf[i].data, send_buf[i].length);

                err = ip_send_context(ip_context, send_buf[i].length);
                if (err_is_fail(err)) {
                    DEBUG_ERR(err, "Error when retransmitting tcp");
                    thread_mutex_unlock(&connection->mutex);
                    goto out;
                }
            }
        }
        thread_mutex_unlock(&connection->mutex);
    }

out:
    collections_hash_traverse_end(tcp_connection_table);
    thread_mutex_unlock(&connection_table_mutex);
}

struct periodic_event check_acks_event;


static int tcp_thread(void *args)
{
    periodic_event_create(&check_acks_event, get_default_waitset(), (delayus_t)100000,
                          MKCLOSURE(&tcp_check_acks, NULL));
    while (true) {
        event_dispatch(get_default_waitset());
    }
    return 0;
}


errval_t tcp_init(void)
{
    thread_mutex_init(&connection_table_mutex);
    collections_hash_create(&tcp_connection_table, NULL);
    collections_hash_create(&port_state_map, NULL);
    collections_hash_create(&port_connection_type_map, NULL);
    thread_create(tcp_thread, NULL);
    return SYS_ERR_OK;
}