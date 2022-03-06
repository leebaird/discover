#!/usr/bin/python3
# Created by Jay Townsend
import argparse
from base64 import b64decode
from typing import List, AnyStr
from bs4 import BeautifulSoup
import csv
import os


def main():
    parser = argparse.ArgumentParser(description='A script to parse Burp Suite XML base64 encoded files to CSV')
    parser.add_argument('-f', '--filename', help='XML file to parse', required=True)
    parser.add_argument('-o', '--outfile', help='Filename of the parsed XML to save as a CSV file', required=True)

    args = parser.parse_args()

    xml_file_to_parse: AnyStr = args.filename
    save_location: AnyStr = args.outfile
    dir_path: AnyStr = os.path.dirname(os.path.realpath(__file__)) + '/'
    file_path: AnyStr = dir_path + xml_file_to_parse
    soup = BeautifulSoup(open(file_path, 'r'), features='lxml')
    issues = soup.find_all('issues')
    issue_data: List = []

    for entries in issues:
        vuln_name = entries.find('name').text.replace('<![CDATA[', '').replace(']]>', '')
        host = entries.find('host')
        ip = host['ip']
        host = host.text
        location = entries.find('location').text.replace('<![CDATA[', '').replace(']]>', '')
        severity = entries.find('severity').text
        confidence = entries.find('confidence').text

        issue_background = entries.find('issuebackground').text.replace("<p>", "").replace("</p>", "").replace(
            '<![CDATA[', '').replace(']]>', '').replace('\n', '')
        remediation_background = entries.find('remediationbackground')
        vulnerability_classification = entries.find('vulnerabilityclassifications')
        data_request = entries.find('requestresponse').text
        request = b64decode(data_request.replace('<![CDATA[', '').replace(']]>', '')).decode()
        response = b64decode(
            entries.find('requestresponse').find('response').text.replace('<![CDATA[', '').replace(']]>', '')).decode()
        issue_detail = entries.find('issuedetail')

        results = (vuln_name, host, ip, location, severity, confidence, issue_background, remediation_background,
                   vulnerability_classification, issue_detail, request, response)
        issue_data.append(results)

        with open(save_location, 'w+') as outfile:
            if issue_data is not None:
                writer = csv.writer(outfile)
                writer.writerow(
                    ['Vulnerability', 'Host', 'IP', 'Location', 'Severity', 'Confidence', 'Issue Background',
                     'Remediation Background', 'Vulnerability Classification', 'Issue Details', 'request', 'response'])
                writer.writerows(issue_data)


if __name__ == '__main__':
    main()
