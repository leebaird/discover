#!/usr/bin/env python3
#
# by John Kim
# Thanks to Securicon, LLC. for sponsoring development
# Ported to python3 by Jay Townsend 2021-10-11
# -*- coding:utf-8 -*-

__version__ = "0.2.0"

import csv
import argparse
import io

################################################################

# Non-standard libraries
try:
    from lxml import etree
except ImportError:
    print("Missing lxml library. Please install using PIP3 or install using your distro python3 package if available. https://pypi.python.org/pypi/lxml/")
    exit()

try:
    import html2text
except ImportError:
    print("Missing html2text library by Aaron Shwartz. Please install using PIP3 or install using your distro python3 package if available. https://pypi.python.org/pypi/html2text/")
    exit()

# custom libraries
try:
    import utfdictcsv
except ImportError:
    print("Missing dict to csv converter custom lib. utfdictcsv.py should be in the same path as this file.")
    exit()


CUSTOM_HEADERS_SECURITY_AUDIT = {'ip_address': 'IP Address',
                                 'fqdn': 'FQDN',
                                 'os': 'OS',
                                 'cvss': 'CVSS',
                                 'audit_name': 'Audit Name',
                                 'audit_description': 'Description',
                                 'solution': 'Solution',
                                 'cve': 'CVE'}

REPORT_HEADERS_SECURITY_AUDIT = ['ip_address',
                                 'fqdn',
                                 'os',
                                 'cvss',
                                 'audit_name',
                                 'audit_description',
                                 'solution',
                                 'cve']


def fix_text(txt):
    lines = io.StringIO(txt).readlines()
    _temp_stage_1 = " ".join([line.strip() for line in lines if line.strip()])
    return ' '.join(_temp_stage_1.split())


def htmltext(blob):
    h = html2text.HTML2Text()
    h.ignore_links = False
    return h.handle(blob)


def trim_for_excel(text):
    if len(text) > 32000:
        return "".join([text[:32000], " [Text Cut Due To Length]"])
    else:
        return text


def nipper_parser(nipper_xml_file, output_filename):

    with open(output_filename, "wb") as outFile:
        csvWriter = utfdictcsv.DictUnicodeWriter(outFile, REPORT_HEADERS_SECURITY_AUDIT, quoting=csv.QUOTE_ALL, extrasaction='ignore')
        csvWriter.writerow(CUSTOM_HEADERS_SECURITY_AUDIT)

        # ret_rows = []
        master_endpoint_table = {}
        parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
        root = etree.parse(nipper_xml_file, parser)

        # NAME, OS, ip pulled from Security audit and configuration section
        server_info_list = root.xpath("//document/report/part[@ref='SECURITYAUDIT']/section[@ref='SECURITY.INTRODUCTION']"
                                 "/table/tablebody/tablerow")

        for server_info in server_info_list:

            _device_name = server_info[1].findtext('item')
            _device_os = server_info[2].findtext('item')
            _device_description = trim_for_excel(server_info[0].findtext('item'))

            # IPs
            ip_info = root.xpath("//document/report/part[@ref='CONFIGURATION']/section[@ref='CONFIGURATION.']")
            _ip_list = []
            for ip_config in ip_info:

                # per device collect all available IP's
                if _device_name.lower() in ip_config.attrib['title'].lower():
                    _temp = ip_config.xpath("section[@ref='CONFIGURATION.ADDRESSES']/section/table[starts-with(@ref, 'ADDRESSES.IPV4.INTERFACES')]/tablebody/tablerow")
                    for _row in _temp:
                        cells = _row.xpath('tablecell')

                        # 3rd cell is ip address/subnet
                        iface_network = cells[2].findtext('item')
                        if len(iface_network) > 0:
                            _ip_list.append(iface_network)

            _device_ips = ",\n".join(_ip_list)
            master_endpoint_table[_device_name] = {'os': _device_os, 'device_description': _device_description, 'fqdn':_device_name, 'ip_address': _device_ips}

        # Vulnerability Audit
        vuln_scan_info = root.xpath("//document/report/part[@ref='VULNAUDIT']/section")

        for vuln_item in vuln_scan_info:
            if "VULNAUDIT.CVE" in vuln_item.attrib['ref']:

                # get devices that have vuln per vuln
                for server_name in master_endpoint_table:
                    #
                    _affected_devices = vuln_item.findtext("section[@title='Affected Device']/text")
                    if _affected_devices is None:
                        # check vuln audit section via alternative method of storing device name in a sub table.
                        _affected_devices_list = vuln_item.find("section[@title='Affected Devices']/list")
                        _affected_devices = "".join([device.text for device in _affected_devices_list])

                    if server_name.lower() in _affected_devices.lower():
                        _temp = master_endpoint_table[server_name].copy()

                        # VULN CVE
                        _cve = vuln_item.attrib['title']
                        _temp['cve'] = _cve
                        _temp['audit_name'] = _cve

                        # CVSS
                        _cvss = vuln_item.findtext("infobox/infodata[@label='CVSSv2 Score']")
                        _temp['cvss'] = _cvss

                        _vuln_solution_links = []
                        for section in vuln_item:
                            if section.attrib['title'] == "Summary":

                                # VULN Summary
                                _temp['audit_description'] = trim_for_excel(section.findtext('text'))

                            elif section.attrib['title'] in ['Vendor Security Advisory', 'Reference', 'References']:
                                listitem = section.findtext('list/listitem')
                                _vul_link_key = listitem
                                listitem = section.findtext('list/listitem/weblink')
                                _vul_links = listitem
                                _vuln_solution_links.append("{}: {}".format(_vul_link_key, _vul_links))

                        # SOLUTION LINKS
                        _temp['solution'] = trim_for_excel("\n".join(_vuln_solution_links))
                        csvWriter.writerow(_temp)

        # Security Audit
        security_audit = root.xpath("//document/report/part[@ref='SECURITYAUDIT']/section")

        for audit_item in security_audit:
            if audit_item.attrib['ref'] not in ["SECURITY.INTRODUCTION",
                                               "SECURITY.CONCLUSIONS",
                                               "SECURITY.RECOMMENDATIONS",
                                               "SECURITY.MITIGATIONS"]:

                for audit_server_list in audit_item.xpath('issuedetails/devices/device'):
                    server_name = audit_server_list.attrib['name']
                    _temp = master_endpoint_table[server_name].copy()
                    _temp['audit_name'] = audit_item.attrib['title']

                    for section in audit_item.xpath('section[@ref="FINDING"]'):
                        # VULN DESCRIPTION
                        _temp['audit_description'] = trim_for_excel(fix_text(htmltext(etree.tostring(section))))

                    for section in audit_item.xpath('section[@ref="RECOMMENDATION"]'):
                        # VULN Recommendation
                        _temp['solution'] = trim_for_excel(fix_text(htmltext(etree.tostring(section))))

                        # CVE
                        _temp['cve'] = "\n".join([_cve_items.text for _cve_items in
                                                 audit_item.xpath('section[@ref="IMPACT"]/table/tablebody/tablerow/tablecell/item')
                                                 if _cve_items.text is not None if "cve" in _cve_items.text.lower()])
                    csvWriter.writerow(_temp)


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

    try:
        nipper_parser(args.nipper_xml_file, args.outfile)
        print("Successfully parsed!")

    except IOError:
        print("ERROR processing file: {}.".format(args.nipper_xml_file))
        exit()
