Formally BackTrack scripts. For use with Kali Linux. Custom bash scripts used to automate various pentesting tasks.

### Download, Setup & Usage
* git clone git://github.com/leebaird/discover.git /opt/scripts/
* All scripts must be ran from this location.
* cd /opt/scripts/
* ./setup.sh
* ./discover.sh


## Main Menu
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

### Domain
```
RECON

1.  Passive
2.  Active
3.  Previous menu

Choice: 
```

* Passive combines goofile, goog-mail, goohost, theHarvester, Metasploit, dnsrecon, URLCrazy, Whois and multiple webistes.
* Active combines Nmap, dnsrecon, Fierce, lbd, WAF00W, traceroute and Whatweb.

### Person
```
RECON

First name:
Last name:
```

* Combines info from multiple websites.

### Parse salesforce
```
Create a free account at salesforce (https://connect.data.com/login).
Perform a search on your target company > select the company name > see all.
Copy the results into a new file.

Enter the location of your list:
```

* Gather names and positions into a clean list.

### Generate target list
```
SCANNING

1.  Angry IP Scanner
2.  Local area network
3.  NetBIOS
4.  netdiscover
5.  Ping sweep
6.  Previous menu
```

* Use different tools to create a target list including Angry IP Scanner, arp-scan, netdiscover and nmap pingsweep.

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
