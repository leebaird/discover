import xml.etree.ElementTree as ET

#tree = ET.parse('nessus.nessus')
#root = tree.getroot()

xml = ET.parse('nessus.nessus')
rootElement = xml.getroot()

#rootElement = tree.getroot()
#rootElement.findall("./Report/ReportHost")

