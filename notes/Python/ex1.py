#!/usr/bin/env python3

import os
import sys


def main():
    os.system('clear')
    port = input('\nEnter a valid port: ')

    if port == '':
        print('\nYou did not enter anything.\n')
        sys.exit(1)

    try:
        val = int(port)
    except ValueError:
        print('\nThat is not a number.\n')
        sys.exit(1)

    if not 1 <= val <= 65535:
        print('\nThat is an invalid port.\n')
        sys.exit(1)

    print('\nThat is a valid port.\n')


if __name__ == '__main__':
    main()