#!/usr/bin/env python3
#
# Author  -- Alexander Sferrella
# Created -- 13 September, 2017
# Ported to python3 by Jay Townsend 2021-10-11

import argparse
from csv import QUOTE_ALL
import utfdictcsv
import xml.etree.ElementTree as ET

# CSV and Nessus headers
csvHeaders = ['CVSS Score', 'IP Address', 'FQDN', 'OS', 'Port', 'Vulnerability', 'Description', 'Proof', 'Solution', 'See Also', 'CVE']
nessusFields = ['cvss_base_score', 'host-ip', 'host-fqdn', 'operating-system', 'port', 'plugin_name', 'description', 'plugin_output', 'solution', 'see_also', 'cve']


def createCSV():
    outFile = open('nessus.csv', 'wb')
    csvWriter = utfdictcsv.DictUnicodeWriter(outFile, csvHeaders, quoting=QUOTE_ALL)
    csvWriter.writeheader()
    return csvWriter


def getValue(rawValue):
    # Clean values from Nessus report
    cleanValue = rawValue.replace('\n', ' ').strip(' ')
    if len(cleanValue) > 32000:
        cleanValue = cleanValue[:32000] + ' [Trimmed due to length]'
    return cleanValue


def getKey(rawKey):
    # Helper function for handleReport()
    return csvHeaders[nessusFields.index(rawKey)]


def handleReport(report):
    # Handle a single report item
    findings = []
    reportHost = dict.fromkeys(csvHeaders, '')
    for item in report:
        if item.tag == 'HostProperties':
            for tag in (tag for tag in item if tag.attrib['name'] in nessusFields):
                reportHost[getKey(tag.attrib['name'])] = getValue(tag.text)
        if item.tag == 'ReportItem':
            reportRow = dict(reportHost)
            reportRow['Port'] = item.attrib['port']
            reportRow['Vulnerability'] = item.attrib['pluginName']
            for tag in (tag for tag in item if tag.tag in nessusFields):
                reportRow[getKey(tag.tag)] = getValue(tag.text)
            # Clean up - Mike G
            if reportRow['CVSS Score'] != "":
                findings.append(reportRow)
    return findings


def handleArgs():
    # Get files
    aparser = argparse.ArgumentParser(description='Converts Nessus scan findings from XML to a CSV file.', usage="\n./parse-nessus.py input.nessus\nAny fields longer than 32,000 characters will be truncated.")
    aparser.add_argument('nessus_xml_files', type=str, nargs='+', help="nessus xml file to parse")
    args = aparser.parse_args()
    return args.nessus_xml_files


if __name__ == '__main__':
    reportRows = []
    for nessusScan in handleArgs():
        try:
            scanFile = ET.parse(nessusScan)
        except IOError:
            print("Could not find file \"" + nessusScan + "\"")
            exit()
        xmlRoot = scanFile.getroot()
        for report in xmlRoot.findall('./Report/ReportHost'):
            findings = handleReport(report)
            reportRows.extend(findings)
    createCSV().writerows(reportRows)
