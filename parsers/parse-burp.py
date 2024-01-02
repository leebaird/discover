#!/usr/bin/python3
# Created by Jay Townsend

import argparse
import binascii
import csv
import os
from base64 import b64decode
from bs4 import BeautifulSoup
from typing import List, AnyStr, Optional


def main():
    parser = argparse.ArgumentParser(description='A script to parse Burp Suite XML base64 encoded files to CSV')
    parser.add_argument('-f', '--filename', help='XML file to parse', required=True)
    parser.add_argument('-o', '--outfile', help='Filename of the parsed XML to save as a CSV file', required=True)
    args = parser.parse_args()

    xml_file_to_parse: AnyStr = args.filename
    save_location: AnyStr = args.outfile
    file_path: AnyStr = xml_file_to_parse

    try:
        with open(file_path, 'r') as file:
            soup = BeautifulSoup(file, features='lxml')
    except IOError:
        print(f"Could not open file: {file_path}")
        return
    except Exception as ex:
        print(f"Could not parse XML: {ex}")
        return

    issues = soup.find_all('issues')
    issue_data: List = []
    for entries in issues:
        vuln_name = find_and_extract_text(entries, 'name')
        host, ip = find_host_and_ip(entries, 'host')
        location = find_and_extract_text(entries, 'location')
        severity = find_and_extract_text(entries, 'severity')
        confidence = find_and_extract_text(entries, 'confidence')
        issue_background = find_and_extract_text(entries, 'issuebackground')
        remediation_background = find_and_extract_text(entries, 'remediationbackground')
        vulnerability_classification = find_and_extract_text(entries, 'vulnerabilityclassifications')
        request, response = extract_request_response(entries)
        issue_detail = find_and_extract_text(entries, 'issuedetail')

        results = (vulnerability_classification, vuln_name, severity, confidence, host, ip, location, issue_detail, issue_background, 
                   remediation_background, request, response)
        issue_data.append(results)

    try:
        with open(save_location, 'w+') as outfile:
            if issue_data:
                writer = csv.writer(outfile)
                writer.writerow(
                    ['Classification', 'Vulnerability', 'Severity', 'Confidence', 'URL', 'IP', 'Location', 'Description', 'Background',
                     'Remediation', 'Request', 'Response'])
                writer.writerows(issue_data)
    except IOError:
        print(f"Could not write to file: {save_location}")


def find_and_extract_text(entry, tag):
    element = entry.find(tag)
    return element.text.replace('<![CDATA[', '').replace(']]>', '') if element is not None else ''


def find_host_and_ip(entry, tag):
    host_element = entry.find(tag)
    if host_element is None:
        return '', ''
    ip = host_element.get('ip', '')
    host = host_element.text
    return host, ip


def extract_request_response(entry):
    request_response = entry.find('requestresponse')
    if request_response is None:
        return '', ''

    try:
        request = b64decode(find_and_extract_text(request_response, 'request')).decode()
    except binascii.Error:
        request = ''

    try:
        response = b64decode(find_and_extract_text(request_response, 'response')).decode()
    except binascii.Error:
        response = ''

    return request, response


if __name__ == '__main__':
    main()
