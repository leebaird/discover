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

import getpass
import os
import subprocess
import sys
import time
import urllib2
import webbrowser

# variables
colorblue = '\033[01;34m{0}\033[00m'
colorred = '\033[01;31m{0}\033[00m'
coloryellow = '\033[01;33m{0}\033[00m'
line = '======================================'
user = getpass.getuser()

##############################################################################################################

def banner():
     print
     print '______  ___ ______ ______  _____  _    _ ______  _____'
     print '|     \  |  |____  |      |     |  \  /  |_____ |____/'
     print '|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_Kali'
     print
     print 'By Lee Baird'
     print
     print

##############################################################################################################

def cidr():
     print 'CIDR'
     goodbye()

##############################################################################################################

def error():
     print
     print
     print colorred.format(line)
     print
     print colorred.format(' *** Invalid choice or entry. *** ')
     print
     print colorred.format(line)
     time.sleep(2)
     main()

##############################################################################################################

def goodbye():
     print
     print
     print 'Coming soon...'
     print
     print
     sys.exit(0)

##############################################################################################################

def lan():
     print 'LAN'
     goodbye()

##############################################################################################################

def listener():
     print 'Metasploit Listener'
     goodbye()

##############################################################################################################

def lists():
     print 'List'
     goodbye()

##############################################################################################################

def main():
     while True:
          choice = menu()
          if choice == "1":
               execfile('recon.py')
          elif choice == "2":
               pingsweep()
          elif choice == "3":
               single()
          elif choice == "4":
               lan()
          elif choice == "5":
               lists()
          elif choice == "6":
               cidr()
          elif choice == "7":
               execfile('multitabs.py')
          elif choice == "8":
               nikto()
          elif choice == "9":
               execfile('sslcheck.py')
          elif choice == "10":
               subprocess.call('/opt/scripts/crack-wifi.sh')
          elif choice == "11":
               listener()
          elif choice == "12":
               sys.exit(0)
          elif choice == "99":
               updates()
          else:
               error()

##############################################################################################################

def menu():
     os.system('clear')
     banner()
     print colorblue.format('RECON')
     print '1. Scrape'
     print
     print colorblue.format('DISCOVER')+' - Host discovery, port scanning, service enumeration and OS'
     print 'identification using Nmap, Nmap scripts and Metasploit scanners.'
     print '2. Ping Sweep'
     print '3. Single IP, URL or Range'
     print '4. Local Area Network'
     print '5. List'
     print '6. CIDR Notation'
     print
     print colorblue.format('WEB')
     print '7. Open multiple tabs in Firefox'
     print '8. Nikto'
     print '9. SSL Check'
     print
     print colorblue.format('MISC')
     print '10. Crack WiFi'
     print '11. Start a Metasploit listener'
     print '12. Exit'
     print
     return raw_input('Choice: ')

##############################################################################################################

def nikto():
     print 'Nikto'
     goodbye()

##############################################################################################################

def pingsweep():
     print 'Pingsweep'
     goodbye()

##############################################################################################################

def reinstall_nmap():
     print 'Reinstall nmap.'
     goodbye()

##############################################################################################################

def runlocally():
     if not sys.stdout.isatty():
          print
          print line
          print
          print 'This option must be run locally, in an X-Windows environment.'
          time.sleep(2)
          main()

##############################################################################################################

def scanname():
     typeofscan()

     name = raw_input('Name of scan: ')

     # Check for no answer
     if name == "":
          error()

     os.makedirs('/'+user+'/'+name)

##############################################################################################################

def single():
     print 'Single'
     goodbye()

##############################################################################################################

def sslcheck():
     print 'SSLcheck'
     goodbye()

##############################################################################################################

def typeofscan():
     colorblue.format('Type of scan:')
     print
     print '1. External'
     print '2. Internal'
     print '3. Previous menu'
     print
     choice = raw_input('Choice: ')

     if choice == "1":
          print
          coloryellow.format('[*] Setting source port to 53.')
          sourceport = 53
          print
          print line
          print

     if choice == "2":
          print
          coloryellow.format('[*] Setting source port to 88.')
          sourceport = 88
          print
          print line
          print

     if choice == "3":
          main()
     else:
          error()

##############################################################################################################

def updates():
     print 'Updates'
     goodbye()

##############################################################################################################

if __name__ == '__main__':
     main()
