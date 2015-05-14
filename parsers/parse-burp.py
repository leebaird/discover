#!/usr/bin/env python
#
# by John Kim
# Thanks to Securicon, LLC. for sponsoring development
#
#-*- coding:utf-8 -*-

from BaseHTTPServer import BaseHTTPRequestHandler
from httplib import HTTPResponse
from StringIO import StringIO
import binascii
import csv
import datetime
import sys
import time

################################################################

# Non-standard libraries
try:
    from lxml import etree
except ImportError:
    print "Missing lxml library. Please install using PIP. https://pypi.python.org/pypi/lxml/3.4.2"
    exit()

try:
    import html2text
except ImportError:
    print "Missing html2text library. Please install using PIP. https://pypi.python.org/pypi/html2text/2015.2.18"
    exit()

# Custom libraries
try:
    import utfdictcsv
except ImportError:
    print "Missing dict to csv converter custom library. utfdictcsv.py should be in the same path as this script."
    exit()

################################################################

CUSTOM_HEADERS = {'host': 'URL',
                  'path': 'PATH',
                  'name': 'Vulnerability',
                  'issueBackground': 'Description',
                  'issueDetail': 'Proof',
                  'requestHeaders': 'Requests',
                  'responseHeaders': 'Response',
                  'remediationBackground': 'Solution'}

REPORT_HEADERS = ['host',
                  'path',
                  'name',
                  'issueBackground',
                  'issueDetail',
                  'requestHeaders',
                  'responseHeaders',
                  'remediationBackground']

COLUMN_HEADERS = ['host', 'path', 'issueDetail', 'name', 'issueBackground', 'remediationBackground']

################################################################

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

################################################################

class FakeSocket():
    def __init__(self, response_str):
        self._file = StringIO(response_str)

    def makefile(self, *args, **kwargs):
        return self._file


def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def report_writer(report_dic):
    with open("burp.csv", "wb") as outFile:
        csvWriter = utfdictcsv.DictUnicodeWriter(outFile, REPORT_HEADERS, quoting=csv.QUOTE_ALL)
        csvWriter.writerow(CUSTOM_HEADERS)
        csvWriter.writerows(report_dic)
    print "Successfully parsed."

################################################################

def issue_row(raw_row):
    issue_row = {}
    for column in COLUMN_HEADERS:
        column_data_raw = raw_row.findtext(column)
        if column_data_raw:
            if column in ['issueDetail', 'issueBackground', 'remediationBackground']:
                issue_row[column] = htmltext(column_data_raw)
            else:
                issue_row[column] = column_data_raw

            if len(issue_row[column]) > 32000:
                issue_row[column] = "".join(issue_row[column][:32000], " [Text Cut Due To Length]")

    request = raw_row.findtext('./requestresponse/request')
    if request:
        parsed_request = HTTPRequest(binascii.a2b_base64(request))
        formatted_request_a = "command : {}\nuri : {}\nrequest_version : {}".format(parsed_request.command, parsed_request.path, parsed_request.request_version)
        formatted_request_b = "\n".join("{}: {}".format(header, parsed_request.headers[header]) for header in parsed_request.headers.keys())
        issue_row['requestHeaders'] = "{}\n{}".format(formatted_request_a, formatted_request_b)

    response = raw_row.findtext('./requestresponse/response')
    if response:
        parsed_response = HTTPResponse(FakeSocket(binascii.a2b_base64(response)))
        parsed_response.begin()
        formatted_response = "\n".join(["{} : {}".format(header_item[0], header_item[1]) for header_item in parsed_response.getheaders()])
        issue_row['responseHeaders'] = formatted_response

    return issue_row


def burp_parser(burp_xml_file):
    parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
    d = etree.parse(burp_xml_file, parser)
    r = d.xpath('//issues/issue')
    report_writer([issue_row(issue) for issue in r])

################################################################

if __name__ == "__main__":

    if len(sys.argv) > 1:
        burp_files = sys.argv[1:]

        for xml_file in burp_files:
            try:
                burp_parser(xml_file)
            except:
                print "[!] Error processing file.\n"
    else:
        print "\nUsage: ./parse-burp.py Base64_input.xml"
        print "Any field longer than 32,000 characters will be truncated.\n".format(sys.argv[0])
        exit()
