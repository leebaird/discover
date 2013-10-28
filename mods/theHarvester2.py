#!/usr/bin/env python

import time
import string
import httplib, sys
from socket import *
import re
import getopt

# Modified by Matt Banick (Bourne_SC)
# Ver 1.6.15

global word
global w
global result
global names
global resulthost
global nexty
global files
resulthost =[]
result = []
names = []
files = []

def usage():

 print "Usage: theHarvester2.py options \n"
 print "   -d: Domain to search or company name"
 print "   -b: Data source (all,123people,ask,bing,google,linkedin,login,yahoo)"
 print "   -s: Start in result number X (default 0)"
 print "   -v: Verify host name via dns resolution"
 print "   -l: Limit the number of results to work with(bing goes from 50 to 50 results,"
 print "            google 100 to 100, and pgp does'nt use this option)"
 print "\nExample: theHarvester2.py -d microsoft.com -l 500 -b google"
 print ""
 print "Note: Yahoo will ban your IP temporarily if you use this or any scraping program too much or too often."
 print ""

def ppl123(w, i):
	
	nexty = "0"
	h = httplib.HTTP('www.google.com')
	h.putrequest('GET', "/search?num=100&start=" + str(i) + "&hl=en&q=" + w + "+site%3A123people.com")
	h.putheader('Host', 'www.google.com')
	h.endheaders()
	returncode, returnmsg, headers = h.getreply()
	data = h.getfile().read()
	renext = re.compile('>Next<')
	nextres=renext.findall(data)

	if nextres !=[]:
		nexty="1"
	else:
		nexty="0"
	data = re.sub('<b>', '', data)
	data = re.sub('<em>', '', data)
	for e in ('>', ':', '=', '<', '\\', ';','3A'):
		data = string.replace(data, e, ' ')
		
	
	ems = r"[a-zA-Z0-9.-_]+@[a-zA-Z0-9.-]*%s\s"
	nas = r"www\.123people\.com/s/[a-zA-Z0-9.-_]*\+[a-zA-Z0-9.-_]*\+?[a-zA-Z0-9.-_]*\""
	em = re.compile(ems % w)
	na = re.compile(nas)
	
	names = na.findall(data)
	emails = em.findall(data)		
	
	return names,emails,nexty

def run(w, i, eng):
	nexty="0"
	if eng == "ask":
		h = httplib.HTTP('www.ask.com')
		h.putrequest('GET', "/web?q=%40" + w + "&pu=100&page="+ str(i))
		h.putheader('Host', 'www.ask.com')
		h.putheader('Accept-Language: en-us,en')
	elif eng == "bing":
		h = httplib.HTTP('www.bing.com')
		h.putrequest('GET', "/search?q=%40" + w + "&go=&count=50&FORM=QBHL&qs=n&first="+ str(i))
		h.putheader('Host', 'www.bing.com')
		h.putheader('Cookie: mkt=en-US;ui=en-US;SRCHHPGUSR=NEWWND=0&ADLT=DEMOTE&NRSLT=50')
		h.putheader('Accept-Language: en-us,en')
	elif eng == "linkedin":
		h = httplib.HTTP('www.google.com')
		h.putrequest('GET', "/search?num=100&start=" + str(i) + "&hl=en&meta=&q=site%3Alinkedin.com%20" + w)
		h.putheader('Host', 'www.google.com')
	elif eng == "google":
		h = httplib.HTTP('www.google.com')
		h.putrequest('GET', "/search?num=100&start=" + str(i) + "&hl=en&meta=&q=%40\"" + w + "\"")
		h.putheader('Host', 'www.google.com')
	elif eng == "pgp":
		h = httplib.HTTP('pgp.rediris.es:11371')
		h.putrequest('GET', "/pks/lookup?search=" + w + "&op=index")
		h.putheader('Host', 'pgp.rediris')
	elif eng == "yahoo":
		h = httplib.HTTP('www.search.yahoo.com')
		h.putrequest('GET', "/search?n=100&b=" + str(i) + "&ei=UTF-8&va_vt=any&vo_vt=any&ve_vt=any&vp_vt=any&vd=all&vst=0&vf=all&vm=p&fl=0&fr=404_web&p=" + w + "&vs=")
		h.putheader('Host', 'www.search.yahoo.com')
	elif eng == "login":
		h = httplib.HTTP('www.google.com')
		h.putrequest('GET', "/search?num=100&start=" + str(i) + "&hl=en&meta=&q=email+OR+user+OR+username+password+site%3A" + w + "")
		h.putheader('Host', 'www.google.com')
	h.putheader('User-agent', '(Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6')	
	h.endheaders()
	returncode, returnmsg, headers = h.getreply()
	data = h.getfile().read()
	if eng == "ask":
		renext = re.compile('>Next')
		nextres=renext.findall(data)
		if nextres !=[]:
			nexty="1"
		else:
			nexty="0"
		data = re.sub('<b>', '', data)
		data = re.sub('<em>', '', data)
		for e in ('>', ':', '=', '<', '/', '\\', ';','3A', '3D'):
			data = string.replace(data, e, ' ')
	elif eng == "bing":
		renext = re.compile('>Next<')
		nextres=renext.findall(data)
		if nextres !=[]:
			nexty="1"
		else:
			nexty="0"
 		data = string.replace(data, '<strong>', '')
 		data = string.replace(data, '</strong>', '')
		for e in ('>', ':', '=', '<', '/', '\\', ';','&'):
			data = string.replace(data, e, ' ')
	elif eng == "google":
		renext = re.compile('>Next<')
		nextres=renext.findall(data)
		if nextres !=[]:
			nexty="1"
		else:
			nexty="0"
		data = re.sub('<b>', '', data)
		data = re.sub('<em>', '', data)
		for e in ('>', ':', '=', '<', '/', '\\', ';','3A', '3D'):
			data = string.replace(data, e, ' ')
	elif eng == "login":
		renext = re.compile('>Next<')
		nextres=renext.findall(data)
		if nextres !=[]:
			nexty="1"
		else:
			nexty="0"
		data = re.sub('<b>', '', data)
		data = re.sub('<em>', '', data)
		for e in ('>', ':', '=', '<', '/', '\\', ';','3A', '3D'):
			data = string.replace(data, e, ' ')
	elif eng == "linkedin":
		renext = re.compile('>Next<')
		nextres=renext.findall(data)
		if nextres !=[]:
			nexty="1"
		else:
			nexty="0"
		re1 = re.compile('>[a-zA-Z ,._-]* - Directory | LinkedIn</a>')
		res = re1.findall(data)
		resul = []
		host = [] #this is needed.  We need to return 3 items, else python quits out.
		for x in res:
				y = string.replace(x, 'LinkedIn', '') #was replacing ' | LinkedIn</a> but it was not weeding out the entries that were simply 'LinkedIn</a'
				y = string.replace(y, '</a', '') #added
				y = string.replace(y, '- Directory', '') #this was 'y = string.replace(x, '- Directory', '') which I think was a typo, as y would now be equal to original x without the changes made concerning 'LinkedIn' and '</a' entries.
				y = string.replace(y, '>', '')
				y = string.replace(y, '</a>', '')
				y.strip(' \n\t\r')
				if len(y) == 1: #this block weeds out strings of length 1 that are only a whitespace
					if ord(y) == 32:
						continue
				if len(y) != 0: #checks for zero length strings, which probably wont happen
					resul.append(y)
		return resul,nexty,host #as stated above, only returning resul,nexty makes python quit.
	elif eng == "yahoo":
		renext = re.compile('>Next')
		nextres=renext.findall(data)
		if nextres !=[]:
			nexty="1"
		else:
			nexty="0"
		data = re.sub('<b>', '', data)
		data = re.sub('<em>', '', data)
		for e in ('>', ':', '=', '<', '/', '\\', ';','3A'):
			data = string.replace(data, e, ' ')
	else:
		data = string.replace(data, '&lt;', ' ')
		data = string.replace(data, '&gt;', ' ')
	r1e = r"[a-zA-Z0-9.-_]+@[a-zA-Z0-9.-]*%s\s"
	r3e = r"[a-zA-Z0-9.-_]*\.%s"
	r1 = re.compile(r1e % w)
	if eng == "pgp":
		r3 = re.compile('(?<=">)[a-zA-Z0-9.-_]+\s[a-zA-Z0-9.-_]+\s')
		res3=r3.findall(data)
		res = r1.findall(data)
		return res,nexty,res3
	else:
		r3 = re.compile(r3e % w)
		res3=r3.findall(data)
		res = r1.findall(data)
		return res,nexty,res3

def test(argv):
	global limit, engines, engine
	limit = 100
	start = 0
	cant = 0
	verify = 0
	if len(sys.argv) < 4:
		usage()
		sys.exit()
	try :
		opts, args = getopt.getopt(argv, "vl:d:b:s:")
	except getopt.GetoptError:
		usage()
		sys.exit()
	for opt, arg in opts :
		if opt == '-l' :
			limit = int(arg)
		elif opt == '-d':
			word = arg
		elif opt == '-s':
			cant=int(arg)
		elif opt == '-v':
			verify= '1'
		elif opt == '-b':
			
			engine = arg
			if engine not in ("123people", "ask", "bing", "google", "linkedin", "login", "pgp", "all", "yahoo"):
				usage()
				print "Invalid search engine, try with: bing, google, linkedin, pgp, 123people, login, yahoo, all"
				sys.exit()
		elif opt == '-o':
			files.append(open(arg, 'w'))
			for a in args:
				files.append(open(a, 'w'))
		
	if engine == "linkedin":
		word = word.replace(' ', '%20')
		
	if engine == "pgp":	
		res,nexty,fi = run(word, 0, engine)
		if res != []:
			res.sort(key=str.lower)
			print "\nEmails:"
			print "============"
			for x in res:
				print x
			if fi == []:
				sys.exit()
			fi.sort(key=str.lower)
			print "\nNames:"
			print "============"
			for x in fi:
				xr = x.lstrip('[')
				print xr
		sys.exit()
	if engine == "all":
		en = 'pgp'
		res,nexty,fi = run(word, 0, en)
		if res != []:
			for x in res:
				result.append(x)
			for x in fi:
				names.append(x.rstrip())
	
	if engine == 'all': 
		engines = ['123people', 'ask', 'login', 'linkedin', 'google', 'bing', 'yahoo']
	else:
		engines = [engine]
	for e in engines:
		while cant < limit:
			if e == "linkedin":
				lword = word.replace('.com', '').replace('.org', '').replace('.gov', '').replace('.net', '')
				res,nexty,host = run(lword.replace(' ', '%20'), cant, e)
				for x in res:
					if names.count(x) == 0:
						names.append(x)
			elif e == '123people':
				n,em,nexty = ppl123(word, cant)
				for x in em:
					if result.count(x) == 0:
						result.append(x)
				for x in n:
					if names.count(x) == 0:
						x = string.replace(x, "www.123people.com/s/", "")
						x = string.replace(x, "+", " ")
						x = string.replace(x, "\"", "")
						names.append(x)
			else:
				res,nexty,host = run(word, cant, e)
				for x in res:
					if result.count(x) == 0:
						result.append(x)
				for x in host:
					if resulthost.count(x) == 0:
						resulthost.append(x)
			if e == 'ask':
				if nexty == "1":
					cant += 100
				else:
					cant = limit + 1			
			elif e == 'bing':
				cant += 50
			elif e == 'yahoo':
				cant += 100
			else:
				if nexty == "1":
					cant += 100
				else:
					cant = limit + 1 
		cant = 0

	if resulthost == []:
		if result == []:
			if names == []:
				sys.exit()
				
	if resulthost != []:
		print "\nHosts:"	
		print "===================="
		resulthost.sort(key=str.lower)
		for x in resulthost:
			host= x.replace('3A','')
			if verify == '1':
				try:
					g=gethostbyname(host)
					print host + " ===> " + g
				except:
					pass
			else:
				print host
	
	if names != []:
		print "\nNames: "
		print "===================="
		names.sort(key=str.lower)
		for x in names:
			print x
		
	if result != []:
		print "\nEmails:"
		print "===================="
		result.sort(key=str.lower)
		for x in result:
			x = re.sub('<li class="first">', '', x)
			x = re.sub('</li>', '', x)
			print x
	
if __name__ == "__main__":
        try: test(sys.argv[1:])
	except KeyboardInterrupt:
		print "Search interrupted by user.."

