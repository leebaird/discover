#!/usr/bin/env python3

import argparse
import os


def main():
    parser = argparse.ArgumentParser(description='Filter lines from a file, dedupe, and sort.')
    parser.add_argument('file', help='input file path')
    parser.add_argument('--match', default='@', help='substring required in line')
    parser.add_argument('--exclude', default='apples', help='substring that excludes a line')
    args = parser.parse_args()

    os.system('clear')

    with open(args.file, 'r') as f:
        filedata = f.read().split('\n')

    out = []
    for line in filedata:
        if args.match in line and args.exclude not in line:
            out.append(line.lower())

    for line in sorted(set(out)):
        print(line)


if __name__ == '__main__':
    main()