#!/usr/bin/python3

import re
import requests
import sys

from lxml import html

domain = sys.argv[1]
filetype = sys.argv[2]
start = 0
results = []
totalFiles = 0


def google_dork():
    global domain
    global filetype
    global start
    global results
    global totalFiles

    regex = re.compile(r'(?P<urls>http\S{3}\w+\S+)(?P<junk>&prev=search)', re.MULTILINE.IGNORECASE,)
    headers = {
        "Host": "www.google.com",
        "User-agent": 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
        "Referrer": "google.com"
    }

    url = f'https://www.google.com/search?hl=en&q=site%3A{domain}%20filetype%3A{filetype}&num=100&start={start}'
    page = requests.get(url, headers=headers)
    tree = html.fromstring(page.content)
    results = tree.xpath('//*[@class="r"]/a/@href')

    totalFiles += len(results)

    for link in results:
        match = re.search(regex, link)
        if match:
            print(match.group('urls'))
        else:
            print(f'{link}')

    if results != []:
        start += 100


def main():
    global results
    global totalFiles
    global filetype

    google_dork()

    if results == []:
        sys.exit()

    while results != []:
        google_dork()


if __name__ == '__main__':
    main()
