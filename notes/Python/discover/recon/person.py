#!/usr/bin/env python

import os

# variables
colorBlue = "\033[01;34m{0}\033[00m"

##############################################################################################################

runlocally()
os.system("clear")
banner()

print colorBlue.format("RECON")
print
firstName = raw_input("First name: ")

if firstName == "":
     error()

lastName = raw_input("Last name:  ")

if lastName == "":
     error()

webbrowser.open("http://www.411.com/name/"+firstName+"-"+lastName+"/")
time.sleep(2)
uripath="http://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn=${"+firstName+"}&mi=&ln=${"+lastName+"}&age=&city=&state="
webbrowser.open(uripath)
time.sleep(2)
webbrowser.open("https://www.linkedin.com/pub/dir/"+firstName+"/"+lastName)
time.sleep(2)
webbrowser.open("http://www.peekyou.com/"+firstName+"%5f"+lastName)
time.sleep(2)
webbrowser.open("http://phonenumbers.addresses.com/people/"+firstName+"+"+lastName)
time.sleep(2)
webbrowser.open("https://pipl.com/search/?q="+firstName+"+"+lastName)
time.sleep(2)
webbrowser.open("http://www.spokeo.com/"+firstName+"-"+lastName)
time.sleep(2)
webbrowser.open("https://twitter.com/search?q=%22"+firstName+"%20"+lastName+"%22")
time.sleep(2)
webbrowser.open("https://www.youtube.com/results?search_query="+firstName+"+"+lastName)

print
print
sys.exit(0)
