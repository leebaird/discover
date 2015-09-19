#!/usr/bin/env python
#
# by John Kim
# Thanks to Securicon, LLC. for sponsoring development
#
# Converts the Nessus plugin database into a CSV file with the following columns:
#    Vulnerability, CVSS Base Score, Description, Solution, Published, Modified
#
# To genrate database:
# Kali Linux
#    /opt/nessus/sbin/nessusd -X
#    mv /opt/nessus/lib/nessus/plugins/plugins.xml /root/
#
# OS X
#    sudo /Library/Nessus/run/sbin/Nessusd -X
#    sudo mv /Library/Nessus/run/lib/nessus/plugins/plugins.xml ./

import codecs
import cStringIO
import csv
import sys
import xml.etree.ElementTree as ET

class UnicodeWriter:
    """
    A CSV writer which will write rows to CSV file "f",
    which is encoded in the given encoding.
    """

    def __init__(self, f, dialect=csv.excel, encoding="utf-8", **kwds):
        # Redirect output to a queue
        self.queue = cStringIO.StringIO()
        self.writer = csv.writer(self.queue, dialect=dialect, **kwds)
        self.stream = f
        self.encoder = codecs.getincrementalencoder(encoding)()

    def writerow(self, row):
        self.writer.writerow([s.encode("utf-8") for s in row])
        # Fetch UTF-8 output from the queue
        data = self.queue.getvalue()
        data = data.decode("utf-8")
        # ... and reencode it into the target encoding
        data = self.encoder.encode(data)
        # Write to the target stream
        self.stream.write(data)
        # Empty queue
        self.queue.truncate(0)

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)

################################################################

def write_results(results_table, out_filename):
    print "\nWriting CSV data..."
    try:
        with open(out_filename, 'wb') as csvfile:
            sum_write = UnicodeWriter(csvfile)
            sum_write.writerows(results_table)

    except IOError as e:
        print "Error writing CSV file. Check for permissions and/or path.\n"
        print(e)
        exit()

################################################################

def max_field_len_excel(ggchild, row_number):
    field = ggchild[1].text
    if len(field) > 32767:
        fname = "row.{}.{}.txt".format(row_number, ggchild[0].text)
        try:
            with open(fname, "wb") as trunk_file:
                trunk_file.write(field[32000:])
        except IOError:
            print "Error writing remainder of the column data to file. Check for permissions and/or path."
            exit()

        print "Row {}, '{}' was truncated. The remainder can be found here: {}".format(row_number, ggchild[0].text, fname)
        return field[:32000]+"[TRUNCATED file:{}]".format(fname)
    else:
        return field

################################################################

def get_sum_from_xml(filename):
    print "\nParsing XML data. This takes about 90 sec...\n"
    results_table = [["Vulnerability", "CVSS Base Score", "Description", "Remediation", "Published", "Updated", "See Also"]]

    try:
        tree = ET.parse(filename)
        root = tree.getroot()
    except IOError:
        print "Error reading/parsing XML file. Likely XML file is mangled in some way. Check the XML file."
        exit()

    row_tracker = 1
    for child in root:
        row_tracker += 1
        row = ["", "", "", "", "", "", ""]
        for gchild in child:

            if gchild.tag == "script_name":
                row[0] = gchild.text

            if gchild.tag == "attributes":
                for ggchild in gchild:
                    if ggchild[0].text == "cvss_base_score":
                        row[1] = ggchild[1].text

                    elif ggchild[0].text == "description":
                        row[2] = max_field_len_excel(ggchild, row_tracker)

                    elif ggchild[0].text == "solution":
                        row[3] = max_field_len_excel(ggchild, row_tracker)

                    elif ggchild[0].text == "plugin_publication_date":
                        row[4] = max_field_len_excel(ggchild, row_tracker)

                    elif ggchild[0].text == "plugin_modification_date":
                        row[5] = max_field_len_excel(ggchild, row_tracker)

                    elif ggchild[0].text == "see_also":
                        row[6] = max_field_len_excel(ggchild, row_tracker)

        results_table.append(row)

    return results_table

################################################################

if __name__ == "__main__":
    if len(sys.argv) == 3:
        results = get_sum_from_xml(sys.argv[1])
        write_results(results, sys.argv[2])
        print "\nConverted {} rows to CSV format.\n\n".format(len(results))
    else:
        print "\nUsage: ./parse-nessus-feed.py input.xml output.csv"
        print "Any field longer than 32,000 characters will be truncated.\n".format(sys.argv[0])
        exit()
