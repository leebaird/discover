#!/usr/bin/env python

import os

# variables
lineMedium="=================================================================="

colorBlue = "\033[01;34m{0}\033[00m"

##############################################################################################################

os.system("clear")
banner()

print colorBlue.format("RECON")
print
print "1.  Passive"
print "2.  Active"
print "3.  Previous menu"
print
choice = raw_input("Choice: ")

if choice == "1":
     os.system("clear")
     banner()

     print colorBlue.format("Uses ARIN, dnsrecon, goofile, goog-mail, goohost, theHarvester,")
     print colorBlue.format(" Metasploit, URLCrazy, Whois, multiple websites, and recon-ng.")
     print
     print colorBlue.format("[*] Acquire API keys for Bing, Builtwith, Fullcontact, GitHub,")
     print colorBlue.format(" Google, Hashes, and Shodan for maximum results with recon-ng.")
     print
     print lineMedium
     print
     print "Usage"
     print
     print "Company: Target"
     print "Domain:  target.com"
     print
     print lineMedium
     print
     company = raw_input("Company: ")

     # Check for no answer
     if company == "":
          error()

     domain = raw_input("Domain: ")

     # Check for no answer
     if domain == "":
          error()

     print
     print lineMedium
     print

     # Number of tests
     total = 35

     print "ARIN"
     print "     Email                (1/"+str(total)+")"
     print "     Names                (2/"+str(total)+")"
     print "     Networks             (3/"+str(total)+")"
     print
     print "dnsrecon                  (4/"+str(total)+")"
     print
     print "goofile                   (5/"+str(total)+")"
#     os.system("goofile -d "+domain+" -f doc > tmp")
#     os.system("goofile -d "+domain+" -f docx >> tmp")
#     os.system("goofile -d "+domain+" -f pdf >> tmp")
#     os.system("goofile -d "+domain+" -f ppt >> tmp")
#     os.system("goofile -d "+domain+" -f pptx >> tmp")
#     os.system("goofile -d "+domain+" -f txt >> tmp")
#     os.system("goofile -d "+domain+" -f xls >> tmp")
#     os.system("goofile -d "+domain+" -f xlsx >> tmp")

#     f_doc = open("doc.txt","a")
#     f_pdf = open("pdf.txt","a")
#     f_ppt = open("ppt.txt","a")
#     f_txt = open("txt.txt","a")
#     f_xls = open("xls.txt","a")
#
#     f = open("tmp","r")                                # Setup a read connection to file
#     filedata = f.read()                                # Read the file
#     f.close()                                          # Close the connection
#     filedata = filedata.split("\n")                    # Turn into a list

#     for i in filedata:
#          if domain in i:
#               if not "Searching in" in i:
#                    if ".doc" in i:
#                         if not ".pdf, .ppt, .xls" in i:
#                              f_doc.write(i.lower()+"\n")
#                    elif ".pdf" in i:
#                         f_pdf.write(i.lower()+"\n")
#                    elif ".ppt" in i:
#                         f_ppt.write(i.lower()+"\n")
#                    elif ".txt" in i:
#                         f_txt.write(i.lower()+"\n")
#                    elif ".xls" in i:
#                         f_xls.write(i.lower()+"\n")

#     # Files need sorted.
#     f_doc.close()
#     f_pdf.close()
#     f_ppt.close()
#     f_txt.close()
#     f_xls.close()

     print
     print "goog-mail                 (6/"+str(total)+")"
     print
     print "goohost"
     print "     IP                   (7/"+str(total)+")"
     print "     Email                (8/"+str(total)+")"
     print
     print "theHarvester"
     print "     Baidu                (9/"+str(total)+")"
     print "     Bing                 (10/"+str(total)+")"
     print "     crtsh                (11/"+str(total)+")"
     print "     Dogpilesearch        (12/"+str(total)+")"
     print "     Google               (13/"+str(total)+")"
     print "     Google CSE           (14/"+str(total)+")"
     print "     Google+              (15/"+str(total)+")"
     print "     Google Profiles      (16/"+str(total)+")"
     print "     LinkedIn             (17/"+str(total)+")"
     print "     netcraft             (18/"+str(total)+")"
     print "     PGP                  (19/"+str(total)+")"
     print "     threatcrowd          (20/"+str(total)+")"
     print "     Twitter              (21/"+str(total)+")"
     print "     vhost                (22/"+str(total)+")"
     print "     virustotal           (23/"+str(total)+")"
     print "     Yahoo                (24/"+str(total)+")"
     print
     print "Metasploit                (25/"+str(total)+")"
     print
     print "URLCrazy                  (26/"+str(total)+")"
     print
     print "Whois"
     print "     Domain               (27/"+str(total)+")"
     print "     IP                   (28/"+str(total)+")"
     print
     print "crt.sh                    (29/"+str(total)+")"
     print
     print "dnsdumpster.com           (30/"+str(total)+")"
     print
     print "email-format.com          (31/"+str(total)+")"
     print
     print "intodns.com               (32/"+str(total)+")"
     print
     print "robtex.com                (33/"+str(total)+")"
     print
     print "Registered Domains        (34/"+str(total)+")"
     print
     print "recon-ng                  (35/"+str(total)+")"
     goodbye()

     ##############################################################

     runlocally()

     webbrowser.open("https://www.arin.net")
     time.sleep(2)
     webbrowser.open("http://toolbar.netcraft.com/site_report?url=http://www."+domain)
     time.sleep(2)
     webbrowser.open("http://uptime.netcraft.com/up/graph?site=www."+domain)
     time.sleep(2)
     webbrowser.open("http://www.shodanhq.com/search?q="+domain)
     time.sleep(2)
     webbrowser.open("http://www.jigsaw.com/")
     time.sleep(2)
     webbrowser.open("http://pastebin.com/")
     time.sleep(2)
     webbrowser.open("http://www.google.com/#q=filetype%3Axls+OR+filetype%3Axlsx+site%3A"+domain)
     time.sleep(2)
     webbrowser.open("http://www.google.com/#q=filetype%3Appt+OR+filetype%3Apptx+site%3A"+domain)
     time.sleep(2)
     webbrowser.open("http://www.google.com/#q=filetype%3Adoc+OR+filetype%3Adocx+site%3A"+domain)
     time.sleep(2)
     webbrowser.open("http://www.google.com/#q=filetype%3Apdf+site%3A"+domain)
     time.sleep(2)
     webbrowser.open("http://www.google.com/#q=filetype%3Atxt+site%3A"+domain)
     time.sleep(2)
     webbrowser.open("http://www.sec.gov/edgar/searchedgar/companysearch.html")
     time.sleep(2)
     webbrowser.open("http://www.google.com/finance/")
     goodbye()

elif choice == "2":
     os.system("clear")
     banner()

     print "Active"
     goodbye()
elif choice == "3":
     main()
else:
     error()
