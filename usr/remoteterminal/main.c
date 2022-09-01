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

#include <aos/deferred.h>
#include <netutil/ip.h>


///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//                             TCP TERM SERVER                               //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

static void handle_tcp_term_client(struct tcp_socket *tcp_socket)
{
    errval_t err;
    
    nameservice_chan_t chan;
    err = nameservice_lookup("terminal", &chan);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "nameservice_lookup failed");
        return;
    }

    RpcRequestWrap req_wrap = RPC_REQUEST_WRAP__INIT;
    RpcResponseWrap *res_wrap;
    err = nameservice_rpc_proto(chan, RPC_METHOD__TERM_SWITCH_TO_UMP, &req_wrap,
                                tcp_socket->urpc_frame, &res_wrap, NULL);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "unable to write");
    }
}

static void tcp_term_server(uint16_t port)
{
    errval_t err;
    struct tcp_server tcp_server;
    err = tcp_server_create(&tcp_server, port, &handle_tcp_term_client, false);
    printf("Created TCP term server on port %d\n", port);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }
}


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }
    uint16_t port = atoi(argv[1]);
    run_dispatcher_threads(3, get_default_waitset());       
    tcp_term_server(port);
    struct waitset *default_ws = get_default_waitset();
    while (true) {
        ASSERT_ERR_OK(event_dispatch(default_ws));
    }
    return EXIT_SUCCESS;

}
