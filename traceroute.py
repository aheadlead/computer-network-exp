#!/usr/bin/env python3
# coding=utf-8
import sys
import socket
import struct
import select
import time

def traceroute(IP, ttl):
    PORT = 33434
    MAX_HOPS = 64

    if ttl <= MAX_HOPS:
        print_buffer = [''] * 7
        print_buffer[0] = str(ttl)

        for cycle in range(3):
            send_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM,
                                      proto=socket.getprotobyname('udp'))
            recv_sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW,
                                      proto=socket.getprotobyname('icmp'))

            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

            start_time = time.time()
            send_sock.sendto(('\x00'*24).encode('utf-8'), (IP, PORT + ttl))
            if select.select([recv_sock], [], [], 1.0)[0]:
                raw_packet, addr = recv_sock.recvfrom(1024)
                stop_time = time.time()
                print_buffer[4+cycle] = '%.2f' % (1000*(stop_time - start_time))
                print_buffer[1] = addr[0] + '\t'

                ip_header_length = (raw_packet[0] & 0x0F)*4
                icmp_packet_header = raw_packet[ip_header_length:ip_header_length+4]
                Type, Code  = struct.Struct('!bb2x').unpack(icmp_packet_header)

                print_buffer[2] = str(Type)
                print_buffer[3] = str(Code)
            else:
                print_buffer[4+cycle] = '*'
                print_buffer[1] = '?'+' '*14

            send_sock.close()
            recv_sock.close()

        return '\t'.join(print_buffer) + '\n'

