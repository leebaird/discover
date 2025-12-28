#!/usr/bin/env python3

import sys
import webbrowser
from time import sleep


def main():
    company = 'Google'
    domain = 'google.com'

    # Add only URL's that take the domain URL
    urls_domain = [
        'https://api.hackertarget.com/dnslookup/?q=',
        'https://api.hackertarget.com/reversedns/?q=',
        'https://api.hackertarget.com/pagelinks/?q=',
        'https://seositecheckup.com/seo-audit/',
        'http://viewdns.info/reversewhois/?q=',
        'http://viewdns.info/dnsreport/?domain=',
        'http://www.spyonweb.com/'
    ]

    # Add only URL's that take the company name
    urls_company = [
        'https://censys.io/ipv4?q=',
        'https://www.shodan.io/search?query='
    ]

    for url in urls_domain:
        webbrowser.open_new_tab(url + domain)
        sleep(2)

    for comp in urls_company:
        webbrowser.open_new_tab(comp + company)
        sleep(2)


if __name__ == '__main__':
    main()
    sys.exit(0)
