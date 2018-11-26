#!/usr/bin/env python

import sys
import time
import webbrowser

# Variables
company="Target"
domain="target.com"

webbrowser.open_new('https://censys.io/ipv4?q='+company)
time.sleep(1)
webbrowser.open_new_tab('https://www.shodan.io/search?query='+company)
time.sleep(1)
webbrowser.open_new_tab('http://api.hackertarget.com/dnslookup/?q='+domain)
time.sleep(1)
webbrowser.open_new_tab('https://api.hackertarget.com/reversedns/?q='+domain)
time.sleep(1)
webbrowser.open_new_tab('https://api.hackertarget.com/pagelinks/?q='+domain)
time.sleep(1)
webbrowser.open_new_tab('https://seositecheckup.com/seo-audit/'+domain)
time.sleep(1)
webbrowser.open_new_tab('http://viewdns.info/reversewhois/?q='+domain)
time.sleep(1)
webbrowser.open_new_tab('http://viewdns.info/dnsreport/?domain='+domain)
time.sleep(1)
webbrowser.open_new_tab('http://www.spyonweb.com/'+domain)

sys.exit(0)

