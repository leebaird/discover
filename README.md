```
Custom bash scripts used to automate various penetration testing tasks including recon, scanning, 
enumeration, and malicious payload creation using Metasploit. For use with Kali Linux.
```

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/leebaird/discover/blob/master/LICENSE)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/tools.html#discover)

* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![Twitter Follow](https://img.shields.io/twitter/follow/ninewires.svg?style=social&label=Follow)](https://twitter.com/ninewires) Jason Ashton @ninewires

### Download, setup, and usage
* git clone https://github.com/leebaird/discover /opt/discover/
* Discover should be ran as root from this location.
* cd /opt/discover/
* sudo ./discover.sh
* Select option 15 to update Kali Linux, Discover scripts, various tools, and the locate database before using the framework.


```
RECON
1.  Domain
2.  Person

SCANNING
3.  Generate target list
4.  CIDR
5.  List
6.  IP, range, or URL
7.  Rerun Nmap scripts and MSF aux

WEB
8.  Insecure direct object reference
9.  Open multiple tabs in Firefox
10. Nikto
11. SSL

MISC
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
3.  Find registered domains
4.  Previous menu
```

Passive uses ARIN, DNSRecon, dnstwist, goog-mail, goohost, theHarvester,
    Metasploit, Whois, multiple websites, and recon-ng.

Active uses DNSRecon, recon-ng, Traceroute, wafw00f, and Whatweb.

[*] You should acquire various API keys for maximum results with theHarvester and add them here:

```
/etc/theHarvester/api-keys.yaml
```

### Person
```
RECON

First name:
Last name:
```

* Combines info from multiple websites.

## SCANNING
### Generate target list
```
SCANNING

1.  ARP scan
2.  Ping sweep
3.  Previous menu
```

* Use different tools to create a target list including Angry IP Scanner, arp-scan, netdiscover, and nmap pingsweep.

### CIDR, List, IP, Range, or URL
```
Type of scan:

1.  External
2.  Internal
3.  Previous menu
```

* External scan will set the nmap source port to 53 and the max-rrt-timeout to 1500ms.
* Internal scan will set the nmap source port to 88 and the max-rrt-timeout to 500ms.
* Nmap is used to perform host discovery, port scanning, service enumeration, and OS identification.
* Nmap scripts and Metasploit auxiliary modules are used for additional enumeration.
* Addition tools: enum4linux, smbclient, and ike-scan.

## WEB
### Insecure direct object reference
````
Using Burp, authenticate to a site, map & Spider, then log out.
Target > Site map > select the URL > right click > Copy URLs in
this host. Paste the results into a new file.

Enter the location of your file:
````

### Open multiple tabs in Firefox
```
Open multiple tabs in Firefox with:

1.  List
2.  Files in a directory
3.  Directories in robots.txt
4.  Previous menu
```

Examples:
* A list containing multiple IPs and/or URLs.
* You finished scanning multiple web sites with Nikto and want to open every htm report located in a directory.
* Use wget to download a domain's robot.txt file, then open all of the directories.

### Nikto
```
This option cannot be ran as root.

Run multiple instances of Nikto in parallel.

1.  List of IPs
2.  List of IP:port
3.  Previous menu
```
### SSL
```
Check for SSL certificate issues.

List of IP:port.


Enter the location of your file:
```

* Uses sslscan, sslyze, and nmap to check for SSL/TLS certificate issues.


## MISC
### Parse XML
```
Parse XML to CSV.

1.  Burp (Base64)
2.  Nessus (.nessus)
3.  Nexpose (XML 2.0)
4.  Nmap
5.  Qualys
6.  Previous menu
```

### Generate a malicious payload
```
Malicious Payloads

1.   android/meterpreter/reverse_tcp         (.apk)
2.   cmd/windows/reverse_powershell          (.bat)
3.   java/jsp_shell_reverse_tcp (Linux)      (.jsp)
4.   java/jsp_shell_reverse_tcp (Windows)    (.jsp)
5.   java/shell_reverse_tcp                  (.war)
6.   linux/x64/meterpreter_reverse_https     (.elf)
7.   linux/x64/meterpreter_reverse_tcp       (.elf)
8.   linux/x64/shell/reverse_tcp             (.elf)
9.   osx/x64/meterpreter_reverse_https       (.macho)
10.  osx/x64/meterpreter_reverse_tcp         (.macho)
11.  php/meterpreter_reverse_tcp             (.php)
12.  python/meterpreter_reverse_https        (.py)
13.  python/meterpreter_reverse_tcp          (.py)
14.  windows/x64/meterpreter_reverse_https   (multi)
15.  windows/x64/meterpreter_reverse_tcp     (multi)
16.  Previous menu
```

### Start a Metasploit listener
```
Metasploit Listeners

1.   android/meterpreter/reverse_tcp
2.   cmd/windows/reverse_powershell
3.   java/jsp_shell_reverse_tcp
4.   linux/x64/meterpreter_reverse_https
5.   linux/x64/meterpreter_reverse_tcp
6.   linux/x64/shell/reverse_tcp
7.   osx/x64/meterpreter_reverse_https
8.   osx/x64/meterpreter_reverse_tcp
9.   php/meterpreter/reverse_tcp
10.  python/meterpreter_reverse_https
11.  python/meterpreter_reverse_tcp
12.  windows/x64/meterpreter_reverse_https
13.  windows/x64/meterpreter_reverse_tcp
14.  Previous menu
```

### Update

* Update Kali Linux, Discover scripts, various tools, and the locate database.

# Troubleshooting

Some users have reported being unable to use any options except for 3, 4, and 5. 
Nothing happens when choosing other options (1, 2, 6, etc.).

## Always run Discover as root

```
cd /opt/discover/
sudo ./discover.sh
```

## Verify the download hash

Hash-based verification ensures that a file has not been corrupted by comparing the file's hash 
value to a previously calculated value. If these values match, the file is presumed to be unmodified.

### macOS

1. Open Terminal
2. shasum -a 256 /path/to/file
3. Compare the value to the checksum on the website.

### Windows

1. Open PowerShell
2. Get-FileHash C:\path\to\file
3. Compare the value to the checksum on the website.

## Running Kali on VirtualBox or Windows Subsystem for Linux (WSL)

Some users have reported the fix is to use the VMWare image instead of WSL. 
(https://kali.download/virtual-images/kali-2022.3/kali-linux-2022.3-vmware-amd64.7z.torrent)

Other users have noticed issues when running a pre-made VirtualBox Kali image, instead of running the 
bare metal Kali ISO through VirtualBox. 
(https://www.kali.org/get-kali/#kali-bare-metal)

If you are unwilling or unable to use VMWare Workstation to run Kali, we encourage you to try running 
a Kali ISO as a Guest VM in VirtualBox.

1. Download the bare metal ISO provided by Kali.
2. Verify the ISO hash (see above).
3. Start a new Kali VM within VirtualBox with the bare metal Kali ISO.

There will be some [basic installation instructions](https://www.kali.org/docs/installation/hard-disk-install/) 
you will be required to fill out during the installation.

Note: If you have problems accessing root after setting up a bare metal ISO, please refer to: 
https://linuxconfig.org/how-to-reset-kali-linux-root-password
