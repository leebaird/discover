#!/usr/bin/env python

import re
import sys
import requests
from lxml import html

domain = sys.argv[1]
filetype = sys.argv[2]
start = 0
results = []

def googleDork():
    global domain
    global filetype
    global start
    global results

    url = 'https://google.com/search?num=500&q=site:{0}+filetype:{1}&num=100&start={2}'.format(domain, filetype, start)
    page = requests.get(url)
    tree = html.fromstring(page.content)

    results = tree.xpath('//*[@class="r"]/a/@href')

    for link in results:
        m = re.match('^\/url\?q=(.*)\&sa', link)
        if m:
            print(m.groups()[0])
        else:
            print('Could not parse the following link: ' + link)

    if results != []:
        start += 100

def main():
    global results

    googleDork()

    if results == []:
        print("No results were found.")
        sys.exit()

    while results != []:
        googleDork()

main()