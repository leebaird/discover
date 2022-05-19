#!/usr/bin/env python3

__author__ = "Bharath"
__description__ = """A script to extract sub-domains that Virus Total
                   has found for a given domain name. Modified by Jay Townsend aka L1ghtn1ng"""

import argparse
import sys

try:
    from requests import get, exceptions
except ImportError:
    raise ImportError('requests library missing. pip3 install requests.')


parser = argparse.ArgumentParser(description='Scrapes https://crt.sh for subdomains from SSL certificate transparency.')
parser.add_argument('-d', '--domain', required=True, help='Domain to lookup.')
parser.add_argument('-l', '--limit', default='40', help='How many to output, max allowed is 40 and the default.')
args = parser.parse_args()


def check_virustotal():
    url = "https://www.virustotal.com/ui/domains/{0}/subdomains?limit={1}".format(args.domain, args.limit)
    print("URL being queried: {}".format(url))
    try:
        get(url)
    except exceptions.RequestException as e:
        print(e)
        sys.exit(1)
    response = get(url)
    return response.json()


def print_results(search_results):
    for index, item in enumerate(search_results['data']):
        print(item['id'])


if __name__ == '__main__':
    try:
        search_results = check_virustotal()
        print_results(search_results)
    except KeyboardInterrupt:
        print('CTRL + C detected, quiting.')
