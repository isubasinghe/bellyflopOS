/**
 * \file
 * \brief Hello world application
 */

/*
 * Copyright (c) 2016 ETH Zurich.
 * All rights reserved.
 *
 * This file is distributed under the terms in the attached LICENSE file.
 * If you do not find this file, copies can be found by writing to:
 * ETH Zurich D-INFK, CAB F.78, Universitaetstr. 6, CH-8092 Zurich,
 * Attn: Systems Group.
 */

#include <stdio.h>
#include <aos/aos.h>
#include <aos/macros.h>
#include <aos/nameserver.h>
#include <netutil/ip.h>
#include <netutil/net_sockets.h>
#include <aos/bellyflop.h>

#define RED "\x1b[31m"
#define GREEN "\x1b[32m"
#define YELLOW "\x1b[33m"
#define BLUE "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN "\x1b[36m"
#define WHITE "\x1b[37m"
#define COLOR_RESET "\x1b[0m"

#include <aos/deferred.h>
#include <netutil/ip.h>

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//                             UDP ECHO CLIENT                               //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// static void tcp_client_echo_server(void)
// {
//     errval_t err;
//     struct tcp_socket tcp_socket;
//     err = tcp_connect(&tcp_socket, 1234, 4344, 167772674, 4000000);
//     if (err_is_fail(err)) {
//         DEBUG_ERR(err, "This should NOT fail");
//         return;
//     }
//     DEBUG_PRINTF("Connected to server\n");

//     uint8_t buf[BASE_PAGE_SIZE];
//     uint8_t *buf_ptr = buf;
//     while (true) {
//         size_t buflen = BASE_PAGE_SIZE;
//         err = tcp_socket_recv(&tcp_socket, &buf_ptr, &buflen);

//         buf[buflen] = '\0';
//         DEBUG_PRINTF("Got %s\n", buf);

//         if (strncmp((char *)buf_ptr, "close", 5) == 0) {
//             err = tcp_socket_close(&tcp_socket);
//             break;
//         }
//         assert(buflen <= BASE_PAGE_SIZE);
//         err = tcp_socket_send(&tcp_socket, buf_ptr, buflen);
//     }
// }

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//                             TCP ECHO SERVER                               //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////


static void tcp_recv_handler(void *arg)
{
    errval_t err;
    struct tcp_socket *tcp_socket = (struct tcp_socket *)arg;

    static uint8_t buf[BASE_PAGE_SIZE];
    uint8_t *buf_ptr = buf;
    size_t buflen = BASE_PAGE_SIZE;

    err = tcp_socket_recv(tcp_socket, &buf_ptr, &buflen);
    assert(buflen <= BASE_PAGE_SIZE);
    if (strncmp((char *)buf_ptr, "close", 5) == 0) {
        err = tcp_socket_close(tcp_socket);
        return;
    }
    if (strncmp((char *)buf_ptr, "bellyflop", 5) == 0) {
        err = tcp_socket_send(tcp_socket, (uint8_t *)belly_flop_get_small(), strlen(belly_flop_get_small()));

    } else if (strncmp((char *)buf_ptr, "big bellyflop", 5) == 0) {
        err = tcp_socket_send(tcp_socket, (uint8_t *)belly_flop_get_big(), strlen(belly_flop_get_big()));

    } else {
        err = tcp_socket_send(tcp_socket, buf_ptr, buflen);
    }
    tcp_socket_register_recv(tcp_socket, get_default_waitset(),
                             MKCLOSURE(tcp_recv_handler, arg));
}

static void handle_tcp_client(struct tcp_socket *tcp_socket)
{
    errval_t err;
    static const char *tcp_welcome_string = "Welcome to AOS Echo Server.\n";
    err = tcp_socket_send(tcp_socket, (uint8_t *)tcp_welcome_string, strlen(tcp_welcome_string));
    
    err = tcp_socket_register_recv(tcp_socket, get_default_waitset(),
                                   MKCLOSURE(tcp_recv_handler, tcp_socket));
}

static void tcp_server_echo_server(uint16_t port)
{
    errval_t err;
    struct tcp_server tcp_server;
    err = tcp_server_create(&tcp_server, port, &handle_tcp_client, false);
    printf("Created TCP echo server on port %d\n", port);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//                             UDP ECHO SERVER                               //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

 
static void udp_echo_server(uint16_t port)
{
    errval_t err;
    struct udp_socket udp_socket;
    err = udp_socket_create(&udp_socket, port, false);
    printf("Created UDP echo server on port %d\n", port);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }

    // err = upd_socket_arp_request(&udp_socket, str_to_ip_addr("10.0.2.2"), 1000000);
    // if(err_is_fail(err)) {
    //     DEBUG_ERR(err, "ARP request failed");
    //     return;
    // }

    uint8_t buf[BASE_PAGE_SIZE];
    uint8_t *buf_ptr = buf;
    while (true) {
        ip_addr_t src;
        uint16_t src_port;
        size_t buflen = BASE_PAGE_SIZE;
        err = udp_socket_recv(&udp_socket, &src, &src_port, &buf_ptr, &buflen);
        assert(buflen <= BASE_PAGE_SIZE);
        if (strncmp((char *)buf_ptr, "bellyflop", 5) == 0) {
            size_t len = strlen(belly_flop_get_small());
            uint8_t * data = (uint8_t *) belly_flop_get_small();
            for (size_t i = 0; i < len; i+= 1400) {
                err = udp_socket_send(&udp_socket, src, src_port, data + i, MIN(1400, len - i));
            }
            
        } else if (strncmp((char *)buf_ptr, "big bellyflop", 5) == 0) {
            size_t len = strlen(belly_flop_get_big());
            uint8_t * data = (uint8_t *) belly_flop_get_big();
            for (size_t i = 0; i < len; i+= 1400) {
                err = udp_socket_send(&udp_socket, src, src_port, data + i, MIN(1400, len - i));
            }
            
        } else {
            err = udp_socket_send(&udp_socket, src, src_port, buf_ptr, buflen);
        }
        
    }
}




int main(int argc, char *argv[])
{
    run_dispatcher_threads(3, get_default_waitset());
   
    if(argc < 3) {
        goto exit;
    }
    uint16_t port = atoi(argv[2]);
    if(strcmp(argv[1], "tcp") == 0) {
        tcp_server_echo_server(port);
    } else if(strcmp(argv[1], "udp") == 0) {
        udp_echo_server(port);
    } else {
        goto exit;
    }
        
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }
    return EXIT_SUCCESS;

exit:
    printf("Usage: %s <udp|tcp> <port>\n", argv[0]);
    return 1;

}
