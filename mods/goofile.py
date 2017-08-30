#!/usr/bin/env python

# Goofile v1.5a
# by Thomas (G13) Richards
# www.g13net.com
# Project Page: code.google.com/p/goofile
# TheHarvester used for inspiration
# A many thanks to the Edge-Security team!           
# Modified by Lee Baird

import getopt
import httplib
import re
import string
import sys

global result
result =[]

def usage():
     print "\nusage: goofile <options>"
     print "   -d: domain"
     print "   -f: filetype\n"
     print "example: goofile.py -d target.com -f txt\n\n" 
     sys.exit()

def run(domain,file):
	h = httplib.HTTP('www.google.com')
	h.putrequest('GET',"/search?num=500&q=site:"+domain+"+filetype:"+file)
	h.putheader('Host', 'www.google.com')
	h.putheader('User-agent', 'Internet Explorer 6.0 ')
	h.putheader('Referrer', 'www.g13net.com')
	h.endheaders()

	returncode, returnmsg, headers = h.getreply()
	data=h.getfile().read()
	data=re.sub('<b>','',data)
        for e in ('>','=','<','\\','(',')','"','http',':','//'):
		data = string.replace(data,e,' ')
	r1 = re.compile('[-_.a-zA-Z0-9.-_]*'+'\.'+file)	
	res = r1.findall(data) 
	return res 

def search(argv):
	global limit
	limit = 100

	if len(sys.argv) < 2: 
		usage() 
	try :
	      opts, args = getopt.getopt(argv,"d:f:")

	except getopt.GetoptError:
          	usage()
		sys.exit()

	for opt,arg in opts :
    	   	if opt == '-f' :
			file=arg
		elif opt == '-d':
			domain=arg

	cant = 0

	while cant < limit:
		res = run(domain,file)
		for x in res:
			if result.count(x) == 0:
        			result.append(x)
		cant+=100

	if result==[]:
		print "No results were found."
	else:
		for x in result:
			print x

if __name__ == "__main__":
        try: search(sys.argv[1:])
	except KeyboardInterrupt:
		print "Search interrupted by user."
	except:
		sys.exit()

