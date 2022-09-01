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
#include <aos/terminal.h>
#include <stdio.h>

// ///////////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////////
// //                             UDP ECHO CLIENT                               //
// ///////////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////////

// // static void tcp_client_echo_server(void)
// // {
// //     errval_t err;
// //     struct tcp_socket tcp_socket;
// //     err = tcp_connect(&tcp_socket, 1234, 4344, 167772674, 4000000);
// //     if (err_is_fail(err)) {
// //         DEBUG_ERR(err, "This should NOT fail");
// //         return;
// //     }
// //     DEBUG_PRINTF("Connected to server\n");

// //     uint8_t buf[BASE_PAGE_SIZE];
// //     uint8_t *buf_ptr = buf;
// //     while (true) {
// //         size_t buflen = BASE_PAGE_SIZE;
// //         err = tcp_socket_recv(&tcp_socket, &buf_ptr, &buflen);

// //         buf[buflen] = '\0';
// //         DEBUG_PRINTF("Got %s\n", buf);

// //         if (strncmp((char *)buf_ptr, "close", 5) == 0) {
// //             err = tcp_socket_close(&tcp_socket);
// //             break;
// //         }
// //         assert(buflen <= BASE_PAGE_SIZE);
// //         err = tcp_socket_send(&tcp_socket, buf_ptr, buflen);
// //     }
// // }

// ///////////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////////
// //                             TCP ECHO SERVER                               //
// ///////////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////////


// static void tcp_recv_handler(void *arg)
// {
//     errval_t err;
//     struct tcp_socket *tcp_socket = (struct tcp_socket *)arg;

//     static uint8_t buf[BASE_PAGE_SIZE];
//     uint8_t *buf_ptr = buf;
//     size_t buflen = BASE_PAGE_SIZE;

//     err = tcp_socket_recv(tcp_socket, &buf_ptr, &buflen);
//     if (strncmp((char *)buf_ptr, "close", 5) == 0) {
//         err = tcp_socket_close(tcp_socket);
//         return;
//     }
//     if (strncmp((char *)buf_ptr, "bellyflop", 5) == 0) {
//         err = tcp_socket_send(tcp_socket, (uint8_t *)belly_flop_get_small(), strlen(belly_flop_get_small()));
//         goto end;
//     }
//     assert(buflen <= BASE_PAGE_SIZE);
//     err = tcp_socket_send(tcp_socket, buf_ptr, buflen);
// end:
//     tcp_socket_register_recv(tcp_socket, get_default_waitset(),
//                              MKCLOSURE(tcp_recv_handler, arg));
// }

// static void handle_tcp_client(struct tcp_socket *tcp_socket)
// {
//     errval_t err;
//     static const char *tcp_welcome_string = "Welcome to AOS Echo Server.\n";
//     err = tcp_socket_send(tcp_socket, (uint8_t *)tcp_welcome_string, strlen(tcp_welcome_string));
    
//     err = tcp_socket_register_recv(tcp_socket, get_default_waitset(),
//                                    MKCLOSURE(tcp_recv_handler, tcp_socket));
// }

// static void tcp_server_echo_server(uint16_t port)
// {
//     errval_t err;
//     struct tcp_server tcp_server;
//     err = tcp_server_create(&tcp_server, port, &handle_tcp_client);
//     debug_printf("Created TCP echo server on port %d\n", port);
//     if (err_is_fail(err)) {
//         DEBUG_ERR(err, "This should NOT fail");
//         return;
//     }
//     DEBUG_PRINTF("TCP Echo service up.\n");
// }

// ///////////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////////
// //                             UDP ECHO SERVER                               //
// ///////////////////////////////////////////////////////////////////////////////
// ///////////////////////////////////////////////////////////////////////////////

ip_addr_t remote_ip_udp = 0;
uint16_t remote_port_udp;
struct aos_terminal* term;

static void exit_session(struct udp_socket* sock) {
    udp_socket_close(sock);
    exit(0);
}

static int read_terminal_and_forward(void* arg) {
    struct udp_socket* udp_socket = arg;
   // aos_terminal_register(term, true);
   
    while (true)
    {
        char* res = aos_terminal_readline(term);
        if(res == NULL) {
            return 0;
        }
        if(remote_ip_udp == 0) {
            printf("Nobody connected yet.\n");
        } else {
            size_t len = strlen(res);
            res[len] = '\n';
            udp_socket_send(udp_socket, remote_ip_udp, remote_port_udp, (uint8_t*) res, len + 1);
            res[len] = '\0';
        }
        if(strcmp(res, "exit") == 0) {
            free(res);
            printf("Exiting!\n");
            exit_session(udp_socket);
        }
        free(res);
    }

    return 0;
}
 
static void udp_nc(uint16_t port, ip_addr_t ip_addr)
{
    // Sadly thats what we need to do to read from the terminal.
    printf("Welcome to nc!\n");
    term = aos_terminal_init();
    while(!aos_terminal_lock(term)) {}

    errval_t err;
    struct udp_socket udp_socket;
    err = udp_socket_create(&udp_socket, port, false);
    
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "Error when creating udp server.\n");
        exit(0);
        return;
    }
    if(ip_addr != 0) {
        err = net_socket_arp_request(ip_addr, 1000000);
        if(err_is_fail(err)) {
            DEBUG_ERR(err, "ARP request failed");
            exit_session(&udp_socket);
        }
        remote_ip_udp = ip_addr;
        printf("Created UDP client nc session on port %d\n", port);
        
    } else {
        printf("Created UDP nc listen session on port %d\n", port);
    }

    thread_create(read_terminal_and_forward,(void*) &udp_socket);
    
    
    uint8_t buf[BASE_PAGE_SIZE];
    uint8_t *buf_ptr = buf;
    while (true) {
        size_t buflen = BASE_PAGE_SIZE;
        err = udp_socket_recv(&udp_socket, &remote_ip_udp, &remote_port_udp, &buf_ptr, &buflen);
        buf[buflen] = '\0';
        assert(buflen <= BASE_PAGE_SIZE);
        printf("%s\n", buf);
        //printf("\b");
        if(strcmp((char*)buf, "exit\n") == 0) {
            printf("Exiting!\n");
            exit_session(&udp_socket);
        }
    }
}

static void exit_session_tcp(struct tcp_socket* sock) {
    tcp_socket_close(sock);
    exit(0);
}

static int read_terminal_and_forward_tcp(void* arg) {
    struct tcp_socket* tcp_socket = arg;
   // aos_terminal_register(term, true);
   
    while (true)
    {
        char* res = aos_terminal_readline(term);
        if(res == NULL) {
            return 0;
        }

        size_t len = strlen(res);
        res[len] = '\n';
        tcp_socket_send(tcp_socket, (uint8_t*) res, len + 1);
        res[len] = '\0';
        
        if(strcmp(res, "exit") == 0) {
            free(res);
            printf("Exiting.\n");
            exit_session_tcp(tcp_socket);
        }
        free(res);
    }

    return 0;
}


static void nc_tcp(uint16_t local_port, uint16_t remote_port, ip_addr_t ip) {

    // Sadly thats what we need to do to read from the terminal.
    printf("Welcome to nc!\n");
    term = aos_terminal_init();
    while(!aos_terminal_lock(term)) {}

    struct tcp_socket tcp_socket;
    errval_t err = tcp_connect(&tcp_socket, local_port, remote_port, ip, 4 * 1000 * 1000, false);
    if(err_is_fail(err)) {
        printf("Connection request timed out.\n");
        exit(0);
        return;
    }
    printf("Session established!\n");

    thread_create(read_terminal_and_forward_tcp,(void*) &tcp_socket);
    // Lets shape the diamond, in order to get the $> without a newline 
    // to work, printf should not buffer till it sees a newline.
    setbuf(stdout, NULL);
    uint8_t buf[BASE_PAGE_SIZE];
    uint8_t *buf_ptr = buf;
    while (true) {
        size_t buflen = BASE_PAGE_SIZE;
        err = tcp_socket_recv(&tcp_socket, &buf_ptr, &buflen);
        if(err_is_fail(err)) {
            // DEBUG_ERR(err, "Error when receiving data");
            exit_session_tcp(&tcp_socket);
        }
        buf[buflen] = '\0';
        assert(buflen <= BASE_PAGE_SIZE);
        printf("%s", buf);
        if(strcmp((char*)buf, "exit\n") == 0) {
            printf("Exiting!\n");
            exit_session_tcp(&tcp_socket);
        }
    }

}

// run 3 nc tcp-client 6666 6666 10.0.2.1
// run 3 nc udp-client 7777 7777 10.0.2.1
// run 3 nc udp-server 7777
int main(int argc, char *argv[])
{
    // Parsing the netcat command line arguments
    if (argc < 3 || argc > 5 || strcmp(argv[1], "--help") == 0) {
        goto exit;
    }
    if((argv[2][0] < '0' || argv[2][0] > '9') && argv[2][0] != '-') {
        printf("Invalid src port\n");
        goto exit;
    }
    uint16_t local_port = atoi(argv[2]);
    if(strcmp(argv[1], "udp-server") == 0 && argc == 3) {
        udp_nc(local_port, 0);
    } else if(strcmp(argv[1], "udp-client") == 0 && argc == 5) {
        ip_addr_t ip_addr = str_to_ip_addr(argv[4]);
        if(ip_addr == 0) {
            printf("Invalid IP address\n");
            goto exit;
        }
        
        if((argv[2][0] < '0' || argv[2][0] > '9') && argv[2][0] != '-') {
            printf("Invalid remote port\n");
            goto exit;
        }
        remote_port_udp = atoi(argv[3]);
        udp_nc(local_port, ip_addr);
    } else if(strcmp(argv[1], "tcp-client") == 0 && argc == 5) {
        ip_addr_t ip_addr = str_to_ip_addr(argv[4]);
        if(ip_addr == 0) {
            printf("Invalid IP address\n");
            goto exit;
        }
        
        if((argv[2][0] < '0' || argv[2][0] > '9') && argv[2][0] != '-') {
            printf("Invalid remote port\n");
            goto exit;
        }
        uint16_t remote_port = atoi(argv[3]);
        nc_tcp(local_port, remote_port, ip_addr);
    } else if (strcmp(argv[1], "tcp-server") == 0 && argc == 4) {
        printf("Not implemented yet\n");
        // ip_addr_t ip_addr = str_to_ip_addr(argv[3]);
        // tcp_nc_server(port, ip_addr);
    } else {
        goto exit;
    }


        
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }
    return EXIT_SUCCESS;

exit:
    printf("Usage: %s <tcp-client|udp-client> <local_port> <remote_port> <ip>\n", argv[0]);
    printf("Usage: %s <tcp-server|udp-server> <local_port> \n", argv[0]);
    return 1;

}
