#!/usr/bin/env python
#
# by John Kim
# Thanks to Securicon, LLC. for sponsoring development
#
#-*- coding:utf-8 -*-

import argparse
import csv
import re

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
    print "Missing dict to csv converter custom library. utfdictcsv.py should be in the same path as this file."
    exit()

################################################################

CUSTOM_HEADERS = {'CVSS_score': 'CVSS Score',
                  'ip_address': 'IP Address',
                  'fqdn': 'FQDN',
                  'os': 'OS',
                  'port_status': 'Port',
                  'vuln_name': 'Vulnerability',
                  'vuln_description': 'Description',
                  'solution': 'Solution',
                  'links': 'Links',
                  'cve': 'CVE'}

REPORT_HEADERS = ['CVSS_score',
                  'ip_address',
                  'fqdn',
                  'os',
                  'port_status',
                  'vuln_name',
                  'vuln_description',
                  'solution',
                  'links',
                  'cve']

################################################################

def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def report_writer(report_dic, output_filename):
    with open(output_filename, "wb") as outFile:
        csvWriter = utfdictcsv.DictUnicodeWriter(outFile, REPORT_HEADERS, quoting=csv.QUOTE_ALL)
        csvWriter.writerow(CUSTOM_HEADERS)
        csvWriter.writerows(report_dic)
    print "Successfully parsed."

################################################################

def issue_r(raw_row, vuln):
    ret_rows = []
    issue_row = {}

    # IP ADDRESS
    issue_row['ip_address']  = raw_row.findtext('IP')

    # FQDN
    issue_row['fqdn'] =raw_row.findtext('DNS')

    # OS NAME
    issue_row['os'] = raw_row.findtext('OPERATING_SYSTEM')

    # Scan details
    for vuln_details in raw_row.iterfind('VULN_INFO_LIST/VULN_INFO'):
        _temp = issue_row

        # Port
        _gid = vuln_details.find('QID').attrib['id']
        _port = vuln_details.findtext('PORT')
        _temp['port_status'] = _port

        search = "//GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS[@id='{}']".format(_gid)
        vuln_item = vuln.find(search)
        if vuln_item is not None:

            # Vuln name
            _temp['vuln_name'] = vuln_item.findtext('TITLE')

            #Solution Strips Heading Workaround(s)
            _temp['solution'] = re.sub('Workaround(s)?:.+\n', '', htmltext(vuln_item.findtext('SOLUTION')))

            # Vuln_description
            _temp['vuln_description'] = "\n".join([htmltext(vuln_item.findtext('THREAT')), htmltext(vuln_item.findtext('IMPACT'))])

            # CVSS
            _temp['CVSS_score'] = vuln_item.findtext('CVSS_SCORE/CVSS_BASE')

            # CVE and LINKS
            _temp_cve_details = vuln_item.iterfind('CVE_ID_LIST/CVE_ID')
            if _temp_cve_details:
                _cl = {cve_detail.findtext('ID'): cve_detail.findtext('URL') for cve_detail in _temp_cve_details}
                _temp['cve'] = "\n".join(_cl.keys())
                _temp['links'] = "\n".join(_cl.values())

            ret_rows.append(_temp.copy())
    return ret_rows


def qualys_parser(qualys_xml_file):
    parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
    d = etree.parse(qualys_xml_file, parser)
    r = d.xpath('//ASSET_DATA_REPORT/HOST_LIST/HOST')
    master_list = []

    for issue in r:
        master_list += issue_r(issue, d)

    report_writer(master_list, args.outfile)

################################################################

if __name__ == "__main__":

    # Parse args
    aparser = argparse.ArgumentParser(description='Converts Qualys XML results to .csv file.')
    aparser.add_argument('--out',
                        dest='outfile',
                        default='qualys.csv',
                        help="WARNING: By default, output will overwrite current path to the file named 'qualys.csv'")

    aparser.add_argument('qualys_xml_file',
                        type=str,
                        help='Qualys xml file.')

    args = aparser.parse_args()

    try:
        qualys_parser(args.qualys_xml_file)
    except IOError:
        print "[!] Error processing file: {}".format(args.qualys_xml_file)
        exit()
