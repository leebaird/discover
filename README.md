Formally BackTrack scripts. For use with Kali Linux. Custom bash scripts used to automate various pentesting tasks.

### Download, setup & usage
* git clone git://github.com/leebaird/discover.git /opt/scripts/
* All scripts must be ran from this location.
* cd /opt/scripts/
* ./setup.sh
* ./discover.sh

```
RECON
1.  Domain
2.  Person
3.  Parse salesforce

SCANNING
4.  Generate target list
5.  CIDR
6.  List
7.  IP or domain

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
## RECON
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

## SCANNING
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

### CIDR, List, IP or domain
```
Type of scan: 

1.  External
2.  Internal
3.  Previous menu

Choice: 
```

* An external scan will set the nmap source port to 53, while an internal scan will set it to 88.
* Nmap is used to perform host discovery, port scanning, service enumeration and OS identification. 
* Matching nmap scripts are used for additional enumeration.
* Matching Metasploit auxiliary modules are also leveraged.

## WEB
* Open multiple tabs in Iceweasel with a list containing IPs and/or URLs or with directories from a domain's robot.txt file.
* Run multiple instances of Nikto in parallel.
* Check for SSL/TLS certificate issues.

## MISC
* Crack wireless networks.
* Start a Metasploit listener.
* Update the distro, scripts and various tools.
