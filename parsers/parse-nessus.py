#!/usr/bin/env python
#
# Original code from - https://github.com/Clete2/NessusReport, modded by Lee Baird
# John Kim - additional modification completed to support UTF-8, support cli help, renaming output files
# Thanks to Securicon, LLC. for sponsoring development

import csv
import datetime
import re
import sys
import time
import utfdictcsv
import xml.etree.ElementTree as ET

################################################################

class NessusParser:
    def loadXML(self, filename):
        self.xml = ET.parse(filename)
        self.rootElement = self.xml.getroot()

    def getHosts(self):
        return self.rootElement.findall("./Report/ReportHost")

################################################################

    def getHostProperties(self, host):
        properties = {}
        hostProperties = host.findall("./HostProperties")[0]

        _temp_ip = hostProperties.findall("./tag[@name='host-ip']")
        if len(_temp_ip) > 0:
            properties['host-ip'] = _temp_ip[0].text
        else:
            properties['host-ip'] = host.attrib['name']

        hostnames = hostProperties.findall("./tag[@name='netbios-name']")
        if(len(hostnames) >= 1):
            properties['netbios-name'] = hostnames[0].text
        else:
            hostnames = hostProperties.findall("./tag[@name='host-fqdn']")
            if(len(hostnames) >= 1):
                properties['netbios-name'] = hostnames[0].text

        os = hostProperties.findall("./tag[@name='operating-system']")
        if(len(os) >= 1):
            properties['operating-system'] = os[0].text
        else:
            os = hostProperties.findall("./tag[@name='os']")
            if(len(os) >= 1):
                properties['operating-system'] = os[0].text

        return properties
################################################################

    def getReportItems(self, host):
        return host.findall("./ReportItem")

    def getReportItemProperties(self, reportItem):
        properties = reportItem.attrib

        if(properties.has_key('severity')):
            del(properties['severity'])

        if(properties.has_key('pluginFamily')):
            del(properties['pluginFamily'])

        return properties

################################################################

    def getReportItemDetails(self, reportItem):
        details = {}

        details['description'] = reportItem.findall("./description")[0].text

        pluginElements = reportItem.findall("./plugin_output")
        if(len(pluginElements) >= 1):
            details['plugin_output'] = pluginElements[0].text

        solutionElements = reportItem.findall("./solution")
        if(len(solutionElements) >= 1):
            details['solution'] = solutionElements[0].text

        seealsoElements = reportItem.findall("./see_also")
        if(len(seealsoElements) >= 1):
            details['see_also'] = seealsoElements[0].text

        cveElements = reportItem.findall("./cve")
        if(len(cveElements) >= 1):
            details['cve'] = cveElements[0].text

        cvssElements = reportItem.findall("./cvss_base_score")
        if(len(cvssElements) >= 1):
            details['cvss_base_score'] = cvssElements[0].text

        return details

################################################################

def transformIfAvailable(inputDict, inputKey, outputDict, outputKey):
    if(inputDict.has_key(inputKey)):
        inputDict[inputKey] = inputDict[inputKey].replace("\n"," ")

        # Excel has a hard limit of 32,767 characters per cell. Let's make it an even 32K.
        if(len(inputDict[inputKey]) > 32000):
            inputDict[inputKey] = inputDict[inputKey][:32000] +" [Text Cut Due To Length]"

        outputDict[outputKey] = inputDict[inputKey]

################################################################

if __name__ == "__main__":

    if len(sys.argv) > 1:
        header = ['CVSS Score','IP','FQDN','OS','Port','Vulnerability','Description','Proof','Solution','See Also','CVE']
        with open("nessus.csv", "wb") as outFile:
            csvWriter = utfdictcsv.DictUnicodeWriter(outFile, header, quoting=csv.QUOTE_ALL)
            csvWriter.writeheader()

            nessusParser = NessusParser()

            for fileName in sys.argv[1:]:
                # try:
                    nessusParser.loadXML(fileName)
                    hostReports = []

                    hosts = nessusParser.getHosts()

                    for host in hosts:
                        # Get properties for this host
                        hostProperties = nessusParser.getHostProperties(host)

                        # Get all findings for this host
                        reportItems = nessusParser.getReportItems(host)

                        for reportItem in reportItems:
                            reportItemDict = {}

                            # Get the metadata and details for this report item
                            reportItemProperties = nessusParser.getReportItemProperties(reportItem)
                            reportItemDetails = nessusParser.getReportItemDetails(reportItem)

                            # Create dictionary for line
                            transformIfAvailable(reportItemDetails, "cvss_base_score", reportItemDict, header[0])
                            transformIfAvailable(hostProperties, "host-ip", reportItemDict, header[1])
                            transformIfAvailable(hostProperties, "netbios-name", reportItemDict, header[2])
                            transformIfAvailable(hostProperties, "operating-system", reportItemDict, header[3])
                            transformIfAvailable(reportItemProperties, "port", reportItemDict, header[4])
                            transformIfAvailable(reportItemProperties, "pluginName", reportItemDict, header[5])
                            transformIfAvailable(reportItemDetails, "description", reportItemDict, header[6])
                            transformIfAvailable(reportItemDetails, "plugin_output", reportItemDict, header[7])
                            transformIfAvailable(reportItemDetails, "solution", reportItemDict, header[8])
                            transformIfAvailable(reportItemDetails, "see_also", reportItemDict, header[9])
                            transformIfAvailable(reportItemDetails, "cve", reportItemDict, header[10])

                            hostReports.append(reportItemDict)
                    csvWriter.writerows(hostReports)
                # except:
                #     print "[!] Error processing {}".format(fileName)
                #     pass
        outFile.close()
    else:
        print "\nUsage: ./parse-nessus.py input.nessus"
        print "Any field longer than 32,000 characters will be truncated.\n".format(sys.argv[0])
        exit()
