Formally BackTrack scripts. Custom bash scripts used to automate various pentesting tasks.


### Download
* git clone git://github.com/leebaird/discover.git /opt/scripts/
* All scripts must be ran from this location.


### Setup
* cd /opt/scripts/
* ./setup.sh


### Usage 
* BackTrack      ./discover-bt.sh
* Kali Linux     ./discover.sh


### Main Menu
```
RECON
1. Domain
2. Person

SCANNING
3. Generate target list
4. CIDR
5. List
6. Single IP or domain

WEB
7. Open multiple tabs in Firefox
8. Nikto
9. SSL

MISC
10. Crack WiFi
11. Parse salesforce
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
* Open multiple tabs in Firefox with a list containing IPs and/or URLs or with directories from a domain's robot.txt file.
* Run multiple instances of Nikto in parallel.
* Check for SSL/TLS certificate issues.


MISC
* Crack wireless networks.
* Parse the results of a query on salesfore.
* Start a Metasploit listener.
* Update the distro, scripts and various tools.
