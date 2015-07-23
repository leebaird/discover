#!/usr/bin/env python
#
# by John Kim
# Thanks to Securicon, LLC. for sponsoring development
#
#-*- coding:utf-8 -*-

import argparse
import csv
import StringIO
################################################################

# Non-standard libraries
try:
    from lxml import etree
except ImportError:
    print "Missing lxml library. Please install using PIP. https://pypi.python.org/pypi/lxml/3.4.2"
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
                  'proof': 'Proof',
                  'solution': 'Solution',
                  'ref_url': 'See Also',
                  'cve': 'CVE',}

REPORT_HEADERS = ['CVSS_score',
                  'ip_address',
                  'fqdn',
                  'os',
                  'port_status',
                  'vuln_name',
                  'vuln_description',
                  'proof',
                  'solution',
                  'ref_url',
                  'cve',]

################################################################

def report_writer(report_dic, output_filename):
    with open(output_filename, "wb") as outFile:
        csvWriter = utfdictcsv.DictUnicodeWriter(outFile, REPORT_HEADERS, quoting=csv.QUOTE_ALL)
        csvWriter.writerow(CUSTOM_HEADERS)
        csvWriter.writerows(report_dic)
    print "Successfully parsed."

################################################################

def fix_text(txt):
    lines = StringIO.StringIO(txt).readlines()
    _temp_stage_1 = " ".join([line.strip() for line in lines if line.strip()])
    return ' '.join(_temp_stage_1.split())

def issue_r(raw_row, vuln):
    ret_rows = []
    issue_row = {}

    # IP ADDRESS
    if raw_row.attrib['address'] is not None:
        issue_row['ip_address'] = raw_row.attrib['address']

    # FQDN
    column_data_raw = raw_row.findtext('names/name')
    if column_data_raw is not None:
        issue_row['fqdn'] = column_data_raw

    # OS NAME
    column_data_raw = raw_row.find('fingerprints/os')
    if column_data_raw is not None:
        issue_row['os'] = column_data_raw.attrib['product']

    # Scan details : ENDPOINTS
    column_data_raw = raw_row.find('endpoints')
    for dd in column_data_raw.iterfind('endpoint'):

        _temp = issue_row

        # Port
        if dd.attrib['port'] is not None:
            _temp['port_status'] = dd.attrib['port']

        # Vulns
        column_data_raw = dd.find('services/service/tests')
        if len(column_data_raw) > 0:
            for ee in column_data_raw.iterfind('test'):
                if ee is not None:

                    # Proof
                    proof_items = []
                    proofs = ee.find('Paragraph')
                    if proofs.text:
                        proof_items.append(proofs.text)
                    for child in proofs.iter():
                        if child.text:
                            proof_items.append(child.text)
                        if child.tag == 'URLLink':
                            proof_items.append(child.attrib['LinkURL'])
                    _temp['proof'] = "\n".join(proof_items)

                    # CVE
                    # _temp_cve = ee.attrib['id']
                    # if "cve" in _temp_cve.lower():
                    #     m = re.search("(CVE.*$)", _temp_cve.upper())
                    #     _temp['cve'] = m.group(1)
                    # else:
                    #     _temp['cve'] = None

                    search = "//VulnerabilityDefinitions/vulnerability[@id='{}']".format(ee.attrib['id'])
                    # print search
                    vuln_item = vuln.find(search)
                    if vuln_item is None:
                        search = "//VulnerabilityDefinitions/vulnerability[@id='{}']".format(ee.attrib['id'].upper())
                        # print search
                        vuln_item = vuln.find(search)

                    # Vuln name
                    _temp['vuln_name'] = vuln_item.attrib['title']
                    _temp['CVSS_score'] = vuln_item.attrib['cvssScore']

                    # Vuln description
                    _temp_vuln_description = vuln_item.findtext('description/ContainerBlockElement/Paragraph')
                    if _temp_vuln_description is None:
                        _temp_vuln_description = vuln_item.findtext('description/ContainerBlockElement')
                    _temp['vuln_description'] = fix_text(_temp_vuln_description)

                    # Solution
                    solution = []
                    solut_col = vuln_item.find('solution/ContainerBlockElement/UnorderedList')
                    if solut_col is None:
                        solut_col = vuln_item.find('solution/ContainerBlockElement/Paragraph')

                    if solut_col is not None:
                        for solve_item in solut_col.iter():
                            if solve_item.text and solve_item.text.strip() != '':
                                solution.append(solve_item.text.strip())
                            if solve_item.tag == 'URLLink':
                                solution.append(solve_item.attrib['LinkURL'])

                        _temp['solution'] = "\n".join(solution)

                    # Reference URL
                    _temp['ref_url'] = vuln_item.findtext("references/reference[@source='URL']")

                    # CVE
                    _temp['cve'] = vuln_item.findtext("references/reference[@source='CVE']")

                    ret_rows.append(_temp.copy())

    # Scan details : TESTS
    column_data_raw = raw_row.find('tests')
    for ee in column_data_raw.iterfind('test'):

        _temp = issue_row
        if ee is not None:

            # Proof
            proof_items = []
            proofs = ee.find('Paragraph')
            if proofs.text:
                proof_items.append(proofs.text)
            for child in proofs.iter():
                if child.text:
                    proof_items.append(child.text)
                if child.tag == 'URLLink':
                    proof_items.append(child.attrib['LinkURL'])
            _temp['proof'] = "\n".join(proof_items)

            search = "//VulnerabilityDefinitions/vulnerability[@id='{}']".format(ee.attrib['id'])
            # print search
            vuln_item = vuln.find(search)
            if vuln_item is None:
                search = "//VulnerabilityDefinitions/vulnerability[@id='{}']".format(ee.attrib['id'].upper())
                # print search
                vuln_item = vuln.find(search)

            # Vuln name
            _temp['vuln_name'] = vuln_item.attrib['title']
            _temp['CVSS_score'] = vuln_item.attrib['cvssScore']

            # Vuln description
            _temp_vuln_description = vuln_item.findtext('description/ContainerBlockElement/Paragraph')
            if _temp_vuln_description is None:
                _temp_vuln_description = vuln_item.findtext('description/ContainerBlockElement')
            _temp['vuln_description'] = fix_text(_temp_vuln_description)

            # Solution
            solution = []
            solut_col = vuln_item.find('solution/ContainerBlockElement/UnorderedList')
            if solut_col is None:
                solut_col = vuln_item.find('solution/ContainerBlockElement/Paragraph')

            if solut_col is not None:
                for solve_item in solut_col.iter():
                    if solve_item.text and solve_item.text.strip() != '':
                        solution.append(solve_item.text.strip())
                    if solve_item.tag == 'URLLink':
                        solution.append(solve_item.attrib['LinkURL'])

                _temp['solution'] = "\n".join(solution)

            # Reference URL
            _temp['ref_url'] = vuln_item.findtext("references/reference[@source='URL']")

            # CVE
            _temp['cve'] = vuln_item.findtext("references/reference[@source='CVE']")

            ret_rows.append(_temp.copy())


    return ret_rows


def nexpose_parser(nexpose_xml_file):
    parser = etree.XMLParser(remove_blank_text=True, no_network=True, recover=True)
    d = etree.parse(nexpose_xml_file, parser)
    r = d.xpath('//nodes/node')
    master_list = []

    for issue in r:
        master_list += issue_r(issue, d)

    report_writer(master_list, args.outfile)

################################################################

if __name__ == "__main__":

    # Parse args
    aparser = argparse.ArgumentParser(description='Converts Nexpose XML results to .csv file. '
                                                  'Only vunerabilities are converted. '
                                                  'Rows with only ports are NOT included in the .csv file.')
    aparser.add_argument('--out',
                        dest='outfile',
                        default='nexpose.csv',
                        help="WARNING: By default, output will overwrite current path to the file named 'nexpose.csv'")

    aparser.add_argument('nexpose_xml_file',
                        type=str,
                        help='Nexpose version 1 or 2 xml file to be converted to csv file')

    args = aparser.parse_args()

    try:
        nexpose_parser(args.nexpose_xml_file)
    except IOError:
        print "[!] Error processing file: {}".format(args.nexpose_xml_file)
        exit()
