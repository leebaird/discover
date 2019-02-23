#!/usr/bin/env python

import re
import requests
import sys

from lxml import html

domain = sys.argv[1]
filetype = sys.argv[2]
start = 0
results = []
totalFiles = 0

def googleDork():
    global domain
    global filetype
    global start
    global results
    global totalFiles

    headers = {
        "Host": "www.google.com",
        "User-agent": "Internet Explorer 6.0 ",
        "Referrer": "www.g13net.com"
    }

    url = 'https://google.com/search?num=500&q=site:{0}+filetype:{1}&num=100&start={2}'.format(domain, filetype, start)
    page = requests.get(url, headers)
    tree = html.fromstring(page.content)

    results = tree.xpath('//*[@class="r"]/a/@href')

    totalFiles += len(results)

    for link in results:
        m = re.match('^\/url\?q=(.*)\&sa', link)
        if m:
            print(m.groups()[0])
        else:
            print('Could not parse: {0}'.format(link))

    if results != []:
        start += 100

def main():
    global results
    global totalFiles
    global filetype

    googleDork()

    if results == []:
        sys.exit()

    while results != []:
        googleDork()

main()

