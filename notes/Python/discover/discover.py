#!/usr/bin/env python
#
# By Lee Baird
# Feel free to contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
# I'm in the process of totally rewriting this script in Python specifically for Kali.
# I'm brand new to Python, so please bare with me.
#
# Special thanks to the following people:
#
# Ben Wood - regex kung foo
# JK - Python and constant ribbing
# Rob Clowser - Python
#
##############################################################################################################

import os
import subprocess
import sys
import time
import urllib2
import webbrowser

# Global variables
lineLong="========================================================================================================================================================"
lineMedium="=================================================================="
lineShort="========================================"

colorBlue = "\033[01;34m{0}\033[00m"
colorRed = "\033[01;31m{0}\033[00m"
colorYellow = "\033[01;33m{0}\033[00m"

homeDir = os.environ['HOME']

##############################################################################################################

def banner():
     print
     print
     print colorYellow.format("______  ___ ______ ______  _____  _    _ ______  _____")
     print colorYellow.format("|     \  |  |____  |      |     |  \  /  |_____ |____/")
     print colorYellow.format("|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_")
     print
     print colorYellow.format("By Lee Baird")
     print
     print

##############################################################################################################

def cidr():
     print "CIDR"
     goodbye()

##############################################################################################################

def error():
     print
     print colorRed.format(lineMedium)
     print
     print colorRed.format("                *** Invalid choice or entry. *** ")
     print
     print colorRed.format(lineMedium)
     time.sleep(2)
     main()

##############################################################################################################

def goodbye():
     print
     print
     print "Coming soon, goodbye..."
     print
     print
     sys.exit(0)

##############################################################################################################

def lan():
     print "LAN"
     goodbye()

##############################################################################################################

def listener():
     print "Metasploit Listener"
     goodbye()

##############################################################################################################

def lists():
     print "List"
     goodbye()

##############################################################################################################

def main():
     while True:
          choice = menu()
          if choice == "1":
               execfile("recon/domain.py")
          elif choice == "2":
               execfile("recon/person.py")
          elif choice == "3":
               execfile("recon/salesforce.py")
          elif choice == "4":
               generate()
          elif choice == "5":
               cidr()
          elif choice == "6":
               lst()
          elif choice == "7":
               ip()
          elif choice == "8":
               execfile("rerun.py")
          elif choice == "9":
               insecureDOR()
          elif choice == "10":
               execfile("web/multiTabs.py")
          elif choice == "11":
               nikto()
          elif choice == "12":
               execfile("sslcheck.py")
          elif choice == "13":
               execfile("parseXML.py")
          elif choice == "14":
               execfile("generate.py")
          elif choice == "15":
               execfile("listener.py")
          elif choice == "16":
               execfile("../update.sh")
          elif choice == "17":
               print
               print
               sys.exit(0)
          elif choice == "99":
               updates()
          else:
               error()

##############################################################################################################

def menu():
     os.system("clear")
     banner()

     # If folder doesn't exist, create it
     if not os.path.exists(homeDir+"/data"):
          os.makedirs(homeDir+"/data")

     print colorBlue.format("RECON")
     print "1.  Domain"
     print "2.  Person"
     print "3.  Parse salesforce"
     print
     print colorBlue.format("SCANNING")
     print "4.  Generate target list"
     print "5.  CIDR"
     print "6.  List"
     print "7.  IP, range, or URL"
     print "8.  Rerun Nmap scripts and MSF aux."
     print
     print colorBlue.format("WEB")
     print "9.  Insecure direct object reference"
     print "10. Open multiple tabs in Firefox"
     print "11. Nikto"
     print "12. SSL"
     print
     print colorBlue.format("MISC")
     print "13. Parse XML"
     print "14. Generate a malicious payload"
     print "15. Start a Metasploit listener"
     print "16. Update"
     print "17. Exit"
     print
     return raw_input("Choice: ")

##############################################################################################################

def nikto():
     print "Nikto"
     goodbye()

##############################################################################################################

def pingsweep():
     print "Pingsweep"
     goodbye()

##############################################################################################################

def runlocally():
     if not sys.stdout.isatty():
          os.system("clear")
          banner()
          print
          print lineMedium
          print
          print "*** This option must be run locally, in an X-Windows environment. ***"
          print
          print lineMedium
          time.sleep(4)
          main()

##############################################################################################################

def scanname():
     typeofscan()

     name = raw_input("Name of scan: ")

     # Check for no answer
     if name == "":
          error()

     os.makedirs("/"+user+"/"+name)

##############################################################################################################

def single():
     print "Single"
     goodbye()

##############################################################################################################

def sslcheck():
     print "SSLcheck"
     goodbye()

##############################################################################################################

def typeofscan():
     colorBlue.format("Type of scan:")
     print
     print "1. External"
     print "2. Internal"
     print "3. Previous menu"
     print
     choice = raw_input("Choice: ")

     if choice == "1":
          print
          colorYellow.format("[*] Setting source port to 53.")
          sourceport = 53
          print
          print line
          print

     elif choice == "2":
          print
          colorYellow.format("[*] Setting source port to 88.")
          sourceport = 88
          print
          print line
          print
     elif choice == "3":
          main()
     else:
          error()

##############################################################################################################

if __name__ == "__main__":
     main()
