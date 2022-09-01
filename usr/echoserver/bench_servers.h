///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//                             TCP BENCH CLIENT                              //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

__unused static void tcp_bench_client_recv(void)
{
    errval_t err;
    struct tcp_socket tcp_socket;
    debug_printf("Connecting to server\n");
    size_t packet_count = 100000;
    uint16_t port = 40031;
    err = tcp_connect(&tcp_socket, port, port, 167772674, 4000000);
    if (err_is_fail(err)) {
        debug_printf("Could not connect to server\n");
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }
    debug_printf("Connected to server\n");


    while(true){
        debug_printf("TDP Bench service up.\n");
        uint64_t bytes_received = 0;
        uint8_t buf[BASE_PAGE_SIZE];
        uint8_t *buf_ptr = buf;
        while (true) {
            size_t buflen = BASE_PAGE_SIZE;
            err = tcp_socket_recv(&tcp_socket, &buf_ptr, &buflen);
            bytes_received+=buflen;
            //debug_printf("Received %lu bytes\n", bytes_received);
            if(bytes_received >= 1400 * packet_count) {
                break;
            }
            
        }
        err = tcp_socket_send(&tcp_socket, (uint8_t*) "End", 3);
        debug_printf("Got %d bytes.", bytes_received);
    }

}

__unused static void tcp_bench_client_send(void)
{
    errval_t err;
    struct tcp_socket tcp_socket;
    debug_printf("Connecting to server\n");
    size_t packet_count = 100000;
    uint16_t port = 40038;
    err = tcp_connect(&tcp_socket, port, port, 167772674, 4000000);
    if (err_is_fail(err)) {
        debug_printf("Could not connect to server\n");
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }
    debug_printf("Connected to server\n");


    while(true){
        debug_printf("TDP Bench service up.\n");
        uint64_t bytes_received = 0;
        uint8_t buf[BASE_PAGE_SIZE];
        while (packet_count--) {
            err = tcp_socket_send(&tcp_socket, buf, 1400);           
        }
        err = tcp_socket_send(&tcp_socket, (uint8_t*) "End", 3);
        debug_printf("Got %d bytes.", bytes_received);
    }

}



///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
//                             UDP BENCH SERVER                              //
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

#define BENCH_PORT 50000

__unused static void udp_bench_recv(void)
{
    errval_t err;
    struct udp_socket udp_socket;
    err = udp_socket_create(&udp_socket, BENCH_PORT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }

    err = upd_socket_arp_request(&udp_socket, str_to_ip_addr("10.0.2.2"), 1000000);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "ARP request failed");
        return;
    }
    while(true){
        printf("UDP Bench service up.\n");
        uint64_t packets_received = 0;
        uint8_t buf[BASE_PAGE_SIZE];
        uint8_t *buf_ptr = buf;
        ip_addr_t src;
        uint16_t src_port;
        while (true) {
            
            
            size_t buflen = BASE_PAGE_SIZE;
            err = udp_socket_recv(&udp_socket, &src, &src_port, &buf_ptr, &buflen);
            if(buflen == 7) {
                break;
            }
            packets_received++;
            
        }
        err = udp_socket_send(&udp_socket, src, src_port,(uint8_t*) "End", 3);
        printf("Got %d packets.", packets_received);
    }
}


__unused static void udp_bench_send(void)
{
    errval_t err;
    struct udp_socket udp_socket;
    err = udp_socket_create(&udp_socket, BENCH_PORT);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "This should NOT fail");
        return;
    }

    err = upd_socket_arp_request(&udp_socket, str_to_ip_addr("10.0.2.2"), 1000000);
    if(err_is_fail(err)) {
        DEBUG_ERR(err, "ARP request failed");
        return;
    }

    printf("UDP Bench service up.\n");
    uint8_t buf[BASE_PAGE_SIZE];
    uint8_t *buf_ptr = buf;
    ip_addr_t src;
    uint16_t src_port;

    while (true) {

        size_t buflen = BASE_PAGE_SIZE;
        err = udp_socket_recv(&udp_socket, &src, &src_port, &buf_ptr, &buflen);

        size_t packet_count = 100;
        size_t count = packet_count;
        while(count--){
            err = udp_socket_send(&udp_socket, src, src_port,buf, 1400);
            if(count % 1000 == 0){
                debug_printf(".");
            }
        }
        count = 100;
        while(count--)
            err = udp_socket_send(&udp_socket, src, src_port,(uint8_t*) "End", 3);
        debug_printf("Send %d packets.\n", packet_count);
    }
}