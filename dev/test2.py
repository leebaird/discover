# Author: Saviour Emmanuel
# Modified by Lee Baird for Nessus

from xml.dom import minidom

class Nessus_XMLParser(object):                                # Lee
    def __init__(self,file_path):
        self._xml_object = object()
        self._xml_path = file_path
        self._output_path = str()
        self._csv_string = str()
        self._open_xml()

    def _open_xml(self):
        '''Open XML file on class construction'''
        self._xml_object = minidom.parse(self._xml_path)

    def setCSVPath(self,output_path):
        '''Set path to dump CSV file'''
        if not output_path.lower().endswith(".csv"):
            output_path = output_path + ".csv"
        self._output_path = output_path
############################################################################################################

    def _iter_hosts(self):
        '''Fetch the <host> tags from the xml file'''
        hosts_nodes = self._xml_object.getElementsByTagName("host")

        for host_node in hosts_nodes:
            yield(host_node)
############################################################################################################

    def _get_FQDN(self,info):
        '''get the FQDN aka domain/hostname'''
        fqdn = str()
        info_detail = info.getElementsByTagName("hostname")
        for hostname in info_detail:
            if(info_detail.getAttribute("netbios-name")):       # Lee
                fqdn = address.getAttribute("netbios-name")     # Lee
                break

        return(fqdn)
############################################################################################################

    def _parse_XML_details(self):
        '''Initiate parsing of Nessus XML file and create CSV string object'''                                # Lee

        csv_header = "CVSS Score,IP,FQDN,OS,Port,Vulnerability,Description,Proof,Solution,See Also,CVE\n"     # Lee
        csv_format = '{0},"{1}","{2}","{3}","{4}","{5}","{6}","{7}","{8}","{9}","{10}","{11}"\n'              # Lee

        self._csv_string += csv_header

        for info in self._iter_hosts():
            ip =  self._get_IP_Address(info)
            fqdn = self._get_FQDN(info)
            os = self._get_OS(info)

            for port,protocol,service,product,version in self._get_iter_Port_Information(info):
                self._csv_string += csv_format.format(cvss-score,ip,fqdn,os,port,vulnerability,description,proof,solution,see-also,cve)     # Lee
############################################################################################################

    def dumpCSV(self):
        '''Write CSV output file to disk'''
        self._parse_XML_details()

        csv_output = open(self._output_path,"w")
        csv_output.write(self._csv_string)
        csv_output.close()

# Usage below:
if(__name__ == "__main__"):

    nessus_xml = Nessus_XMLParser("nessus.nessus")     # Lee
    nessus_xml.setCSVPath("report2.csv")               # Lee
    nessus_xml.dumpCSV()                               # Lee

