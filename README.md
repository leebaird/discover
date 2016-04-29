Follow on Twitter @discoverscripts

For use with Kali Linux. Custom bash scripts used to automate various pentesting tasks.

# License

This project is licensed under the ```BSD 3-clause “New” or “Revised” License```. For more information please see the licence file.

### Download, setup & usage
* git clone https://github.com/leebaird/discover /opt/discover/
* All scripts must be ran from this location.
* cd /opt/discover/
* ./update.sh

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
8.  Open multiple tabs in Firefox
9.  Nikto
10. SSL

MISC
11. Crack WiFi
12. Parse XML
13. Generate a malicious payload
14. Start a Metasploit listener
15. Update
16. Exit
```
## RECON
### Domain
```
RECON

1.  Passive
2.  Active
3.  Previous menu
```

* Passive uses ARIN, dnsrecon, goofile, goog-mail, goohost, theHarvester, Metasploit, URLCrazy, Whois, multiple websites, and recon-ng.
* Active uses Nmap, dnsrecon, Fierce, lbd, WAF00W, traceroute, and Whatweb.

* Acquire API keys for Bing, Builtwith, Fullcontact, GitHub, Google, Hashes, and Shodan for maximum results with recon-ng.

```
  recon-ng
  keys add bing_api <value>
  keys add builtwith_api <value>
  keys add fullcontact_api <value>
  keys add github_api <value>
  keys add google_api <value>
  keys add google_cse <value>
  keys add hashes_api <value>
  keys add shodan_api <value>

```

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

1.  Local area network
2.  NetBIOS
3.  netdiscover
4.  Ping sweep
5.  Previous menu
```

* Use different tools to create a target list including Angry IP Scanner, arp-scan, netdiscover and nmap pingsweep.

### CIDR, List, IP or domain
```
Type of scan:

1.  External
2.  Internal
3.  Previous menu
```

* External scan will set the nmap source port to 53 and the max-rrt-timeout to 1500ms.
* Internal scan will set the nmap source port to 88 and the max-rrt-timeout to 500ms.
* Nmap is used to perform host discovery, port scanning, service enumeration and OS identification.
* Matching nmap scripts are used for additional enumeration.
* Matching Metasploit auxiliary modules are also leveraged.

## WEB
### Open multiple tabs in Firefox
```
Open multiple tabs in Firefox with:

1.  List
2.  Directories from a domain's robot.txt.
3.  Previous menu
```

* Use a list containing IPs and/or URLs.
* Use wget to pull a domain's robot.txt file, then open all of the directories.

### Nikto
```
Run multiple instances of Nikto in parallel.

1.  List of IPs.
2.  List of IP:port.
3.  Previous menu
```
### SSL
```
Check for SSL certificate issues.

Enter the location of your list:
```

* Use sslscan and sslyze to check for SSL/TLS certificate issues.


## MISC
### Crack WiFi

* Crack wireless networks.

### Parse XML
```
Parse XML to CSV.

1.  Burp (Base64)
2.  Nessus
3.  Nexpose
4.  Nmap
5.  Qualys
6.  Previous menu
```

### Generate a malicious payload
```
MALICIOUS PAYLOADS

1.  android/meterpreter/reverse_tcp
2.  cmd/windows/reverse_powershell
3.  linux/x64/shell_reverse_tcp
4.  linux/x86/meterpreter/reverse_tcp
5.  osx/x64/shell_reverse_tcp
6.  windows/meterpreter/reverse_tcp
7.  windows/x64/meterpreter/reverse_tcp
8.  Previous menu
```

### Start a Metasploit listener
```
Metasploit LISTENERS

1.  android/meterpreter/reverse_tcp
2.  cmd/windows/reverse_powershell
3.  linux/x64/shell_reverse_tcp
4.  linux/x86/meterpreter/reverse_tcp
5.  osx/x64/shell_reverse_tcp
6.  windows/meterpreter/reverse_tcp
7.  windows/x64/meterpreter/reverse_tcp
8.  Previous menu
```

### Update

* Use to update Kali Linux, Discover scripts, various tools and the locate database.
