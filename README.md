Formally BackTrack scripts.  
For use with Kali Linux or BackTrack - custom bash scripts used to automate various pentesting tasks.


RECON
* Domain
* Person

SCANNING
* Generate target list
* CIDR
* List
* Single IP or URL

WEB
* Open multiple tabs in Firefox
* Nikto
* SSL Check

MISC
* Crack WiFi
* Parse salesforce
* Start a Metasploit listener
* Update
* Exit

 
Download
===================
* git clone git://github.com/leebaird/discover.git /opt/scripts/
* All scripts must be ran from this location.


Install
===================
* cd /opt/scripts/
* ./setup.sh


Usage 
===================
* BackTrack      ./discover-bt.sh
* Kali Linux     ./discover.sh


Overview
===================
* Active domain recon - combines Nmap, dnsrecon, Fierce, lbd, WAF00W, traceroute and Whatweb.
* Passive domain recon - combines goofile, goog-mail, goohost, theHarvester, Metasploit, dnsrecon, URLCrazy, Whois and multiple webistes. 
* Individual recon - combines multiple websites.
* Use different methods to create a target list with Angry IP Scanner, arp-scan, netdiscover and nmap pingsweep.
* Scanning - host discovery, port scanning, service enumeration and OS identification using Nmap, NSE and Metasploit auxiliary modules.
* Open multiple tabs in Firefox with a list containing IPs and/or URLs or with directories from a domain's robot.txt file.
* Run multiple instances of Nikto in parallel against a list of IP addresses.
* Check for SSL certificate issues.
* Crack wireless networks.
* Parse the results of a query on salesfore.
* Start a Metasploit listener.
* Update the distro, scripts and various tools.
