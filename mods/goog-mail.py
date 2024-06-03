#!/usr/bin/python3

import re
import sys
import urllib.request
import urllib.parse


def strip_tags(text):
    finished = False
    while not finished:
        finished = True
        start = text.find(b"<")
        if start >= 0:
            stop = text[start:].find(b">")
            if stop >= 0:
                text = text[:start] + text[start+stop+1:]
                finished = False
    return text


if len(sys.argv) != 2:
    print("\nExtracts emails from Google results.")
    print("\nUsage: ./goog-mail.py <domain>")
    sys.exit(1)

domain_name = sys.argv[1]
d = {}
page_counter = 0

try:
    while page_counter < 50:
        results = 'https://groups.google.com/groups?q=' + urllib.parse.quote(domain_name) + '&hl=en&lr=&ie=UTF-8&start=' + str(page_counter) + '&sa=N'
        request = urllib.request.Request(results)
        request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
        opener = urllib.request.build_opener()
        text = opener.open(request).read()
        emails = re.findall(rb"[\w\.\-]+@" + re.escape(domain_name.encode()), strip_tags(text))
        for email in emails:
            d[email.lower()] = 1
        page_counter += 10
except IOError as e:
    print(e)

page_counter_web = 0

try:
    while page_counter_web < 50:
        results_web = 'https://www.google.com/search?q=%40' + urllib.parse.quote(domain_name) + '&hl=en&lr=&ie=UTF-8&start=' + str(page_counter_web) + '&sa=N'
        request_web = urllib.request.Request(results_web)
        request_web.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
        opener_web = urllib.request.build_opener()
        text = opener_web.open(request_web).read()
        emails_web = re.findall(rb"[\w\.\-]+@" + re.escape(domain_name.encode()), strip_tags(text))
        for email_web in emails_web:
            d[email_web.lower()] = 1
        page_counter_web += 10
except IOError as e:
    print(e)

for uniq_email in d.keys():
    print(uniq_email.decode('utf-8'))
