#!/usr/bin/env python
# This script works under py3 as well
import sys
import requests
from lxml import html
from texttable import Texttable

url = 'https://crt.sh/?q={0}&dir=v&sort=4&group=none'.format(sys.argv[1])
page = requests.get(url)
tree = html.fromstring(page.content)

# Gather data from HTML table rows via XPATH
logTimes = tree.xpath('//table/tr/td[2]/text()')
notBefore = tree.xpath('//table/tr/td[3]/text()')
notAfter = tree.xpath('//table/tr/td[4]/text()')
issuerName = tree.xpath('//table/tr/td[5]/a/text()')

# Setup the rows; define headers for the table in the first row
rows = [
    ['Log Times', 'Not Before', 'Not After', 'Issuer Name']
]

# Loop over parsed data; format into rows[] list
for i in range(len(logTimes)):
    rows.append([
        logTimes[i],
        notBefore[i],
        notAfter[i],
        issuerName[i]
    ])

table = Texttable()
table.add_rows(rows)

print(table.draw())

