#!/usr/bin/python3
# Created by Jay Townsend and Lee Baird

import argparse
import binascii
import csv
import os
import re
from base64 import b64decode
from bs4 import BeautifulSoup
from typing import AnyStr, List, Optional


def main():
    parser = argparse.ArgumentParser(description='Parse Burp Suite Pro XML base64 encoded files to CSV.')
    parser.add_argument('-f', '--filename', help='XML file to parse', required=True)
    parser.add_argument('-o', '--outfile', help='CSV file', required=True)
    args = parser.parse_args()

    xml_file_to_parse: AnyStr = args.filename
    save_location: AnyStr = args.outfile
    file_path: AnyStr = xml_file_to_parse

    try:
        with open(file_path, 'r') as file:
            soup = BeautifulSoup(file, 'xml')
    except IOError:
        print(f"Could not open file: {file_path}")
        return
    except Exception as ex:
        print(f"Could not parse XML: {ex}")
        return

    issues = soup.find_all('issues')
    issue_data: List = []
    for entries in issues:
        vulnerabilityClassifications = find_and_extract_text(entries, 'vulnerabilityClassifications')
        name = find_and_extract_text(entries, 'name')
        severity = find_and_extract_text(entries, 'severity')
        confidence = find_and_extract_text(entries, 'confidence')
        host, ip = find_host_and_ip(entries, 'host')
        location = find_and_extract_text(entries, 'location')
        issueDetail = find_and_extract_text(entries, 'issueDetail')
        issueBackground = find_and_extract_text(entries, 'issueBackground')
        remediationBackground = find_and_extract_text(entries, 'remediationBackground')
        request, response = extract_request_response(entries)
        references = find_and_extract_text(entries, 'references')

        results = (vulnerabilityClassifications, name, severity, confidence, host, ip, location, issueDetail, issueBackground,
                   remediationBackground, request, response, references)
        issue_data.append(results)

    try:
        with open(save_location, 'w+', newline='', encoding='utf-8') as outfile:
            if issue_data:
                writer = csv.writer(outfile, quoting=csv.QUOTE_MINIMAL, escapechar='\\')
                writer.writerow(['Classification', 'Vulnerability', 'Severity', 'Confidence', 'URL', 'IP', 'Location', 'Description', 'Background', 'Remediation', 'Request', 'Response', 'See Also'])
                writer.writerows(issue_data)
    except IOError:
        print(f"Could not write to file: {save_location}")


def find_and_extract_text(entry, tag):
    element = entry.find(tag)
    if element is not None:
        html_content = ''.join(element.find_all(string=True, recursive=True))
        if tag == 'issueDetail':
            return parse_issue_detail(html_content)
        if tag == 'vulnerabilityClassifications':
            return parse_vulnerability_classifications(html_content)
        elif tag == 'references':
            return extract_urls(html_content)
        else:
            if html_content and not os.path.exists(html_content):
                text_only = ''.join(BeautifulSoup(html_content, 'html.parser').stripped_strings)
                return text_only
            else:
                return html_content
    else:
        return ''


def parse_issue_detail(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')

    # Initialize a string to hold the formatted text
    formatted_text = ""

    # Process each part of the HTML content
    for content in soup.contents:
        if content.name is None:
            # Handle direct string content
            stripped_content = content.strip()
            if stripped_content:
                # Add a newline before specific sentences
                if stripped_content.startswith("Burp relies on the Java") or stripped_content.startswith("The server presented the following"):
                    formatted_text += "\n" + stripped_content + "\n"
                else:
                    formatted_text += stripped_content + "\n"
        elif content.name == 'ul':
            # Process list items
            for li in content.find_all('li'):
                formatted_text += "- " + li.get_text(strip=True) + "\n"
        elif content.name == 'table':
            # Process table rows
            for row in content.find_all('tr'):
                cells = [cell.get_text(strip=True) for cell in row.find_all('td')]
                formatted_text += " ".join(cells).strip() + "\n"
        elif content.name == 'h4':
            # Include <h4> tag content
            h4_text = content.get_text(strip=True)
            formatted_text += h4_text + "\n"

    # Clean up the final formatted text
    formatted_text = "\n".join(filter(None, formatted_text.split("\n")))  # Remove empty lines
    return formatted_text


def parse_vulnerability_classifications(html_content):
    if not html_content.strip():
        return "No content"
    li_texts = re.findall(r'<li>(.*?)<\/li>', html_content, re.DOTALL)
    formatted_text_lines = [re.sub(r'<[^>]+>', '', li_text).strip() for li_text in li_texts]
    formatted_text = '\n'.join(formatted_text_lines)
    return formatted_text


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


def extract_urls(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    urls = [a['href'] for a in soup.find_all('a', href=True)]
    return '\n'.join(urls)


if __name__ == '__main__':
    main()
