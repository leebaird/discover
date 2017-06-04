Follow on Twitter [![Twitter Follow](https://img.shields.io/twitter/follow/shields_io.svg?style=social&label=@discoverscripts)](https://twitter.com/discoverscripts) <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT licsense" width="100" height="20">


For use with Kali Linux. Custom bash scripts used to automate various pentesting tasks.

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
7.  IP, range, or domain
8.  Rerun Nmap scripts and MSF aux

WEB
9.  Insecure direct object reference
10. Open multiple tabs in Firefox
11. Nikto
12. SSL

MISC
13. Crack WiFi
14. Parse XML
15. Generate a malicious payload
16. Start a Metasploit listener
17. Update
18. Exit
```
## RECON
### Domain
```
RECON

1.  Passive
2.  Active
3.  Previous menu
```

* Passive uses ARIN, dnsrecon, goofile, goog-mail, goohost, theHarvester,
     Metasploit, URLCrazy, Whois, multiple websites, and recon-ng.
* Active uses Nmap, dnsrecon, Fierce, lbd, WAF00W, traceroute, and Whatweb.

* Acquire API keys for Bing, Builtwith, Fullcontact, GitHub, Google, Hashes, 
     and Shodan for maximum results with recon-ng.

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

### CIDR, List, IP, Range, or URL
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
* Addition tools: enum4linux, smbclient, and ike-scan.
* Matching Metasploit auxiliary modules are also leveraged.

## WEB
### Insecure direct object reference
````
Using Burp, authenticate to a site, map & Spider, then log out.
Target > Site map > select the URL > right click > Copy URLs in this host.
Paste the results into a new file.

Enter the location of your file: 
````

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
Malicious Payloads

1.   android/meterpreter/reverse_tcp
2.   cmd/windows/reverse_powershell
3.   java/jsp_shell_reverse_tcp
4.   linux/x64/shell_reverse_tcp
5.   linux/x86/meterpreter/reverse_tcp
6.   osx/x64/shell_reverse_tcp
7.   php/meterpreter/reverse_tcp
8.   windows/meterpreter/reverse_tcp
9.   windows/meterpreter/reverse_tcp (ASP)
10.  windows/x64/meterpreter/reverse_tcp
11.  Previous menu
```

### Start a Metasploit listener
```
Metasploit Listeners

1.   android/meterpreter/reverse_tcp
2.   cmd/windows/reverse_powershell
3.   java/jsp_shell_reverse_tcp
4.   linux/x64/shell_reverse_tcp
5.   linux/x86/meterpreter/reverse_tcp
6.   osx/x64/shell_reverse_tcp
7.   php/meterpreter/reverse_tcp
8.   windows/meterpreter/reverse_tcp
9.   windows/x64/meterpreter/reverse_tcp
10.  Previous menu
```

### Update

* Use to update Kali Linux, Discover scripts, various tools and the locate database.

