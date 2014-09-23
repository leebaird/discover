# Original code from - https://github.com/Clete2/NessusReport

import csv
import glob
import re
import xml.etree.ElementTree as ET
############################################################################################################

class NessusParser:
    def loadXML(self, filename):
        self.xml = ET.parse(filename)
        self.rootElement = self.xml.getroot()
    
    def getHosts(self):
        return self.rootElement.findall("./Report/ReportHost")
############################################################################################################
    
    def getHostProperties(self, host):
        properties = {}        
    
        hostProperties = host.findall("./HostProperties")[0]

        hostnames = hostProperties.findall("./tag[@name='netbios-name']")
        if(len(hostnames) >= 1):
            properties['netbios-name'] = hostnames[0].text
        properties['host-ip'] = hostProperties.findall("./tag[@name='host-ip']")[0].text

        hostnames = hostProperties.findall("./tag[@name='operating-system']")
        if(len(hostnames) >= 1):
            properties['operating-system'] = hostnames[0].text
        properties['host-ip'] = hostProperties.findall("./tag[@name='host-ip']")[0].text

        return properties
############################################################################################################
   
    def getReportItems(self, host):
        return host.findall("./ReportItem")
        
    def getReportItemProperties(self, reportItem):
        properties = reportItem.attrib

        if(properties.has_key('severity')):
            del(properties['severity'])
            
        if(properties.has_key('pluginFamily')):
            del(properties['pluginFamily'])
        
        return properties
############################################################################################################
        
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
############################################################################################################

def transformIfAvailable(inputDict, inputKey, outputDict, outputKey):
    if(inputDict.has_key(inputKey)):
        inputDict[inputKey] = inputDict[inputKey].replace("\n"," ")
        
        # Excel has a hard limit of 32,767 characters per cell. Let's make it an even 32K.
        if(len(inputDict[inputKey]) > 32000):
            inputDict[inputKey] = inputDict[inputKey][:32000] +" [Text Cut Due To Length]"
            
        outputDict[outputKey] = inputDict[inputKey]
            
header = ['CVSS Score','IP','FQDN','OS','Port','Vulnerability','Description','Proof','Solution','See Also','CVE']

outFile = open("nessus.csv", "wb")
csvWriter = csv.DictWriter(outFile, header, quoting=csv.QUOTE_ALL)
csvWriter.writeheader()
############################################################################################################

nessusParser = NessusParser()

#for fileName in glob.glob("*.nessus"):
#    nessusParser.loadXML(fileName)

    nessusParser.loadXML(/tmp/nessus.nessus)

    hosts = nessusParser.getHosts()

    hostReports = []

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
        
outFile.close()

