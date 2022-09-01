import socket
import time
import select


remote_ip = "10.0.2.1"
local_ip = "10.0.2.2"

bench_port = 1234
local_port = 1234



def get_udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    sock.bind((local_ip, local_port))
    return sock

def get_tcp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((local_ip, local_port))
    sock.listen(1)
    return sock

def get_tcp_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((remote_ip, bench_port))
    return sock

def send_udp_packet(sock, data):
    sock.sendto(data, (remote_ip, bench_port))

def send_tcp_packet(sock, data):
    sock.sendall(data)


payload = bytearray(1400)

def benchmark_socket_send(sock, send_function, udp,  count = 100000):
    start = time.time()
    for i in range(count):
        send_function(sock, payload)
    if udp:
        time.sleep(0.1)
        for i in range(3):
            send_function(sock, bytearray(7))
    print("waiting")
    msg = sock.recv(1024)
    
    end = time.time()
    print(msg)
    return end - start

def benchmark_socket_recv(sock, send_function):
    # lets tell it to start.
    # send_function(sock, bytearray(7))
    msg = sock.recv(1500)
    start = time.time()
    count = 0
    while True:
        msg = sock.recv(1500)
        count = count +1
        if len(msg) == 3 or 'End' in str(msg):
            break
    end = time.time()
    print(f"got {count} packets")
    return end - start


def benchmark_socket_latency(sock, send_function, count = 100):
    print("Starting latency test")
    msg = "Hello World"
    enc = msg.encode()
    times = []
    for i in range(count):
        start = time.time()
        send_function(sock, enc)
        res = sock.recv(1500)
        end = time.time()
        times.append(end - start)
    print(times)

def benchmark_tcp_send():
    sock = get_tcp_socket()
    connection, client_address = sock.accept()
    print("connected")
    print(benchmark_socket_send(connection, send_tcp_packet, False, 100000))

def benchmark_tcp_recv():
    sock = get_tcp_socket()
    connection, client_address = sock.accept()
    print("connected")
    print(benchmark_socket_recv(connection, send_tcp_packet))


#sock = get_tcp_client()
sock = get_udp_socket()
benchmark_socket_latency(sock, send_udp_packet)

# print("Benchmarking UDP socket send")
# sock = get_udp_socket()
# print(benchmark_socket_send(sock, send_udp_packet, True))


# print("Benchmarking UDP socket send")
# sock = get_udp_socket()
# print(benchmark_socket_recv(sock, send_udp_packet))

# print("Benchmarking TCP socket send")
# benchmark_tcp_send()

# print("Benchmarking TCP socket send")
# benchmark_tcp_recv()
