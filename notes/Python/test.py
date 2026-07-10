#!/usr/bin/env python3

import argparse
import webbrowser
from time import sleep


def main():
    parser = argparse.ArgumentParser(description='Open recon URLs in browser tabs.')
    parser.add_argument('--domain', required=True, help='target domain')
    parser.add_argument('--company', required=True, help='target company name')
    parser.add_argument('--delay', type=float, default=2, help='seconds between tabs')
    args = parser.parse_args()

    urls_domain = [
        'https://api.hackertarget.com/dnslookup/?q=',
        'https://api.hackertarget.com/reversedns/?q=',
        'https://api.hackertarget.com/pagelinks/?q=',
        'https://seositecheckup.com/seo-audit/',
        'http://viewdns.info/reversewhois/?q=',
        'http://viewdns.info/dnsreport/?domain=',
        'http://www.spyonweb.com/'
    ]

    urls_company = [
        'https://censys.io/ipv4?q=',
        'https://www.shodan.io/search?query='
    ]

    for url in urls_domain:
        webbrowser.open_new_tab(url + args.domain)
        sleep(args.delay)

    for url in urls_company:
        webbrowser.open_new_tab(url + args.company)
        sleep(args.delay)


if __name__ == '__main__':
    main()