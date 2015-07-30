#!/usr/bin/env python
#-*- coding:utf-8 -*-

__version__ = "0.1.0"

import csv
import argparse
import StringIO

# Non-standard libraries
try:
    from lxml import etree
except ImportError:
    print "Missing lxml library. Please install using PIP. https://pypi.python.org/pypi/lxml/3.4.2"
    exit()

try:
    import html2text
except:
    print "Missing html2text library by Aaron Shwartz. Please install using PIP. https://pypi.python.org/pypi/html2text/2015.2.18"
    exit()

# custom libraries
try:
    import utfdictcsv
except ImportError:
    print "Missing dict to csv converter custom lib. utfdictcsv.py should be in the same path as this file."
    exit()


CUSTOM_HEADERS_SECURITY_AUDIT = {'ip_address': 'IP Address',
                                 'fqdn': 'FQDN',
                                 'os': 'OS',
                                 'cvss': 'CVSS',
                                 'vuln_name': 'Vulnerability Name',
                                 'vuln_description': 'Description',
                                 'solution': 'Solution',
                                 'cve': 'CVE'}

REPORT_HEADERS_SECURITY_AUDIT = ['ip_address',
                                 'fqdn',
                                 'os',
                                 'cvss',
                                 'vuln_name',
                                 'vuln_description',
                                 'solution',
                                 'cve']


def fix_text(txt):
    lines = StringIO.StringIO(txt).readlines()
    _temp_stage_1 = " ".join([line.strip() for line in lines if line.strip()])
    return ' '.join(_temp_stage_1.split())


def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def report_writer(report_dic, output_filename):
    with open(output_filename, "wb") as outFile:
        csvWriter = utfdictcsv.DictUnicodeWriter(outFile, REPORT_HEADERS_SECURITY_AUDIT, quoting=csv.QUOTE_ALL)
        csvWriter.writerow(CUSTOM_HEADERS_SECURITY_AUDIT)
        csvWriter.writerows(report_dic)
    print "Successfully parsed!"


def nipper_parser(nipper_xml_file):
    ret_rows = []
    issue_row = {}

    parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
    root = etree.parse(nipper_xml_file, parser)

    # IPs
    server_info = root.xpath("//document/report/part[@ref='CONFIGURATION']/section[@ref='CONFIGURATION.']"
                             "/section[@ref='CONFIGURATION.ADDRESSES']/section/table/tablebody/tablerow")
    _ip_list = [ tablerow[2].findtext('item') for tablerow in server_info if tablerow[2].findtext('item')]
    issue_row['ip_address'] = "\n".join(_ip_list)

    # NAME, OS
    server_info = root.xpath("//document/report/part[@ref='SECURITYAUDIT']/section[@ref='SECURITY.INTRODUCTION']"
                             "/table/tablebody/tablerow")
    if server_info:
        _device_name = server_info[0][1].findtext('item')
        _device_os = server_info[0][2].findtext('item')
        issue_row['fqdn'] = _device_name
        issue_row['os'] = _device_os

    # VULNS vulnerabilities
    server_info = root.xpath("//document/report/part[@ref='VULNAUDIT']/section")

    for vuln_item in server_info:
        if "VULNAUDIT.CVE" in vuln_item.attrib['ref']:
            _temp = issue_row.copy()

            # VULN CVE
            _cve = vuln_item.attrib['title']
            _temp['cve'] = _cve
            _temp['vuln_name'] = _cve

            # CVSS
            _cvss = vuln_item.findtext("infobox/infodata[@label='CVSSv2 Score']")
            _temp['cvss'] = _cvss

            _vuln_solution_links = []
            for section in vuln_item:
                if section.attrib['title'] == "Summary":

                    # VULN Summary
                    _temp['vuln_description'] = section.findtext('text')

                elif section.attrib['title'] in ['Vendor Security Advisory', 'Reference', 'References']:
                    listitem = section.findtext('list/listitem')
                    # for listitem in listitems:
                    # print listitem
                    _vul_link_key = listitem
                    listitem = section.findtext('list/listitem/weblink')
                    # for listitem in listitems:
                    # print listitem
                    _vul_links = listitem
                    _vuln_solution_links.append("{}: {}".format(_vul_link_key, _vul_links))
                    # print _vul_link_key, _vul_links
            # SOLUTION LINKS
            _temp['solution'] = "\n".join(_vuln_solution_links)
            # print vuln_solutions
            ret_rows.append(_temp.copy())


    # Security Audit
    server_info = root.xpath("//document/report/part[@ref='SECURITYAUDIT']/section")

    for vuln_item in server_info:
        if vuln_item.attrib['ref'] not in ["SECURITY.INTRODUCTION", "SECURITY.CONCLUSIONS", "SECURITY.RECOMMENDATIONS", "SECURITY.MITIGATIONS"]:
            _temp = issue_row.copy()
            # print _temp
            # Vulnerability
            _vuln = vuln_item.attrib['title']
            _temp['vuln_name'] = _vuln

            # _vuln_solution_links = []
            for section in vuln_item.xpath('section[@ref="FINDING"]'):
                # VULN DESCRIPTION
                _vuln_description = htmltext(etree.tostring(section))
                _temp['vuln_description'] = fix_text(_vuln_description)

            for section in vuln_item.xpath('section[@ref="RECOMMENDATION"]'):
                # VULN Recommendation
                _vuln_solution = htmltext(etree.tostring(section))

                _temp['solution'] = fix_text(_vuln_solution)

            # CVE
            _temp['cve'] = "\n".join([_cve_items.text for _cve_items in
                                     vuln_item.xpath('section[@ref="IMPACT"]/table/tablebody/tablerow/tablecell/item')
                                     if _cve_items.text is not None if "cve" in _cve_items.text.lower()])
            ret_rows.append(_temp.copy())
    return ret_rows


if __name__ == "__main__":

    # Parse Args
    aparser = argparse.ArgumentParser(description='Converts Nipper Security and Vulnerability Audit section XML results '
                                                  'into two .csv files.')
    aparser.add_argument('--out',
                        dest='outfile',
                        default='nipper.csv',
                        help="WARNING: By default, output will overwrite current path to the file named 'nipper.csv'")

    aparser.add_argument('nipper_xml_file',
                        type=str,
                        help='nipper xml file.')

    args = aparser.parse_args()

    # try:
    # nipper_parser(args.nipper_xml_file)
    report_writer(nipper_parser(args.nipper_xml_file),"nipper_vulns.csv")
    # except IOError:
    #     print "ERROR processing file: {}.".format(args.nipper_xml_file)
    #     exit()