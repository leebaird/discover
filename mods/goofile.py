#!/usr/bin/env python

import re
import sys
import requests
from lxml import html

domain = sys.argv[1]
filetype = sys.argv[2]
start = 0
results = []
totalFiles = 0

linkTemplate = '<li><a href="{0}" target="_blank">{0}</a></li>'

def googleDork():
    global domain
    global filetype
    global start
    global results
    global totalFiles
    global linkTemplate

    url = 'https://google.com/search?num=500&q=site:{0}+filetype:{1}&num=100&start={2}'.format(domain, filetype, start)
    page = requests.get(url)
    tree = html.fromstring(page.content)

    results = tree.xpath('//*[@class="r"]/a/@href')

    totalFiles += len(results)

    for link in results:
        m = re.match('^\/url\?q=(.*)\&sa', link)
        if m:
            print(linkTemplate.format(m.groups()[0]))
        else:
            print('<li>Could not parse: {0}</li>'.format(link))

    if results != []:
        start += 100

def main():
    global results
    global totalFiles
    global filetype

    print('<ul>')

    googleDork()

    if results == []:
        print("<li>No results were found.</li>")
        sys.exit()

    while results != []:
        googleDork()

    print('</ul>')
    print('<p>Total number of {0} files: {1}</p>'.format(filetype.upper(), totalFiles))

main()