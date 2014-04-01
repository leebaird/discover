Formally BackTrack scripts. For use with Kali Linux - custom bash scripts used to automate various pentesting tasks.

### Download
* git clone git://github.com/leebaird/discover.git /opt/scripts/
* All scripts must be ran from this location.


### Setup
* cd /opt/scripts/
* ./setup.sh


### Usage 
* ./discover.sh


### Main Menu
```
RECON
1.  Domain
2.  Person
3.  Parse salesforce

SCANNING
4.  Generate target list
5.  CIDR
6.  List
7.  Single IP or domain

WEB
8.  Open multiple tabs in Iceweasel
9.  Nikto
10. SSL

MISC
11. Crack WiFi
12. Start a Metasploit listener
13. Update
14. Exit
```

### Overview
RECON
* Active domain recon - combines Nmap, dnsrecon, Fierce, lbd, WAF00W, traceroute and Whatweb.
* Passive domain recon - combines goofile, goog-mail, goohost, theHarvester, Metasploit, dnsrecon, URLCrazy, Whois and multiple webistes.
* Individual recon - combines multiple websites.

SCANNING
* Use different methods to create a target list including Angry IP Scanner, arp-scan, netdiscover and nmap pingsweep.
* Scanning - host discovery, port scanning, service enumeration and OS identification using Nmap. Additional enumeration performed with matching Nmap scripts and Metasploit auxiliary modules.


WEB
* Open multiple tabs in Iceweasel with a list containing IPs and/or URLs or with directories from a domain's robot.txt file.
* Run multiple instances of Nikto in parallel.
* Check for SSL/TLS certificate issues.


MISC
* Crack wireless networks.
* Parse the results of a query on salesfore.
* Start a Metasploit listener.
* Update the distro, scripts and various tools.
