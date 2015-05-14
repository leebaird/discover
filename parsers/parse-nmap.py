#!/usr/bin/env python
#
# by Saviour Emmanuel

from xml.dom import minidom

class NMAP_XMLParser(object):
    def __init__(self,file_path):
        self._xml_object = object()
        self._xml_path = file_path
        self._output_path = str()
        self._csv_string = str()
        self._open_xml()

    def _open_xml(self):
        '''Open the XML file on class construction'''
        self._xml_object = minidom.parse(self._xml_path)

    def setCSVPath(self,output_path):
        '''Set the path to dump the CSV file'''
        if not output_path.lower().endswith(".csv"):
            output_path = output_path + ".csv"
        self._output_path = output_path

    def _iter_hosts(self):
        '''Fetch the <host> tags from the XML file'''
        hosts_nodes = self._xml_object.getElementsByTagName("host")
        for host_node in hosts_nodes:
            yield(host_node)

    def _get_IP_Address(self,info):
        '''Fetch the IP address from the XML object'''
        ip_address = str()
        info_detail = info.getElementsByTagName("address")
        for address in info_detail:
            if(address.getAttribute("addrtype") == "ipv4"):
                ip_address = address.getAttribute("addr")
                break

        return(ip_address)

    def _get_FQDN(self,info):
        '''Get the FQDN aka domain/hostname'''
        fqdn = str()
        info_detail = info.getElementsByTagName("hostname")
        for hostname in info_detail:
            if(hostname.getAttribute("name")):              # thanks to Kevin
                fqdn = hostname.getAttribute("name")        # for the bug fix
                break

        return(fqdn)

    def _get_OS(self,info):
        '''Determine the OS by the greatest percentage in accuracy'''
        os = str()
        os_hash = dict()
        percentage = list()

        info_detail = info.getElementsByTagName("osmatch")

        for os_detail in info_detail:
            guessed_os = os_detail.getAttribute("name")
            accuracy = os_detail.getAttribute("accuracy")
            if(guessed_os and accuracy):
                os_hash[float(accuracy)] = guessed_os

        percentages = os_hash.keys()
        if(percentages):
            max_percent = max(percentages)
            os = os_hash[max_percent]

        return(os)

    def _get_iter_Port_Information(self,info):
        '''Fetch port and service information'''
        info_detail = info.getElementsByTagName("port")
        for port_details in info_detail:
            protocol = port_details.getAttribute("protocol")
            port_number = port_details.getAttribute("portid")

            port_service = port_details.getElementsByTagName("state")
            for port_services in port_service:
                port_state = port_services.getAttribute("state")

                if(port_state == "open"):

                    service_info = port_details.getElementsByTagName("service")
                    for service_details in service_info:
                        service = service_details.getAttribute("name")
                        product = service_details.getAttribute("product")
                        version = service_details.getAttribute("version")

                        yield(port_number,protocol,service,product,version)

    def _parse_XML_details(self):
        '''Initiate parsing of nmap XML file and create CSV string object'''
        csv_header = "IP Address,FQDN,OS,Port,Protocol,Service,Name,Version\n"
        csv_format = '{0},"{1}","{2}",{3},{4},"{5}","{6}","{7}"\n'

        self._csv_string += csv_header

        for info in self._iter_hosts():
            ip =  self._get_IP_Address(info)
            fqdn = self._get_FQDN(info)
            os = self._get_OS(info)

            for port,protocol,service,product,version in self._get_iter_Port_Information(info):
                self._csv_string += csv_format.format(ip,fqdn,os,port,protocol,service,product,version)

    def dumpCSV(self):
        '''Write CSV output file to disk'''
        self._parse_XML_details()

        csv_output = open(self._output_path,"w")
        csv_output.write(self._csv_string)
        csv_output.close()

if __name__ == "__main__":
    nmap_xml = NMAP_XMLParser("nmap.xml")          # Input file
    nmap_xml.setCSVPath("nmap.csv")                # Output file
    nmap_xml.dumpCSV()
