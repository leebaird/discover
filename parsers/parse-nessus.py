#!/usr/bin/env python
#
# Author  -- Alexander Sferrella
# Created -- 13 September, 2017
# Edited  -- 20 September, 2017

from sys import argv
from csv import QUOTE_ALL as QUOTE_ALL
import utfdictcsv
import xml.etree.ElementTree as ET

# CSV and Nessus headers
csvHeaders = ['CVSS Score', 'IP', 'FQDN', 'OS', 'Port', 'Vulnerability', 'Description', 'Proof', 'Solution', 'See Also', 'CVE']
nessusFields = ['cvss_base_score', 'host-ip', 'host-fqdn', 'operating-system', 'port', 'plugin_name', 'description', 'plugin_output', 'solution', 'see_also', 'cve']

# Create output CSV file
def createCSV():
    outFile = open('nessus.csv', 'wb')
    csvWriter = utfdictcsv.DictUnicodeWriter(outFile, csvHeaders, quoting=QUOTE_ALL)
    csvWriter.writeheader()
    return csvWriter

# Clean values from nessus report
def getValue(rawValue):
    cleanValue = rawValue.replace('\n', ' ').strip(' ')
    if len(cleanValue) > 32000:
        cleanValue = cleanValue[:32000] + ' [Text Cut Due To Length]'
    return cleanValue

# Helper function
def getKey(rawKey):
    return csvHeaders[nessusFields.index(rawKey)]

# Handle a single report item
def handleReport(report):
    findings = []
    reportHost = dict.fromkeys(csvHeaders, '')
    for item in report:
        if item.tag == 'HostProperties':
            for tag in (tag for tag in item if tag.attrib['name'] in nessusFields):
                reportHost[getKey(tag.attrib['name'])] = getValue(tag.text)
        if item.tag == 'ReportItem':
            reportRow = dict(reportHost)
            reportRow['Port'] = item.attrib['port']
            for tag in (tag for tag in item if tag.tag in nessusFields):
                reportRow[getKey(tag.tag)] = getValue(tag.text)
            findings.append(reportRow)
    return findings

# Main
if __name__ == '__main__':
    if len(argv) <= 1:
        print('\nUsage: ./parse-nessus.py input.nessus')
        print('Any fields longer than 32,000 characters will be truncated.\n'.format(argv[0]))
        exit()
    reportRows = []
    for nessusScan in argv[1:]:
        xmlRoot = ET.parse(nessusScan).getroot()
        for report in xmlRoot.findall('./Report/ReportHost'):
            findings = handleReport(report)
            reportRows.extend(findings)
    createCSV().writerows(reportRows)
