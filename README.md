```
Custom bash scripts used to automate various penetration testing tasks including recon, scanning, 
enumeration, and malicious payload creation using Metasploit. For use with Kali Linux or Ubuntu.
```

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/leebaird/discover/blob/master/LICENSE)

* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![Twitter Follow](https://img.shields.io/twitter/follow/ninewires.svg?style=social&label=Follow)](https://twitter.com/ninewires) Jason Ashton @ninewires

### Setup and usage
* Download to your home directory.
```
cd ~
git clone https://github.com/leebaird/discover
cd discover/
./discover.sh
```
* Select **Update** (main menu option 16) to update the operating system and install dependencies (`ffuf`, `feroxbuster`, `jq`, etc.).
* Dev scanners are under `dev/` and are also reachable from main menu option **15. Dev**.
* Some options will require root credentials to run.

### Main menu
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
15. Dev
16. Update
17. Exit

```

### Dev submenu (option 15)

Security scanners by [Yiğit ibrahim (ibrahimsql)](https://github.com/ibrahimsql). Scripts live under `dev/` and can also be run directly.

```
Dev scripts | by ibrahimsql

1. API Security
2. Cloud Security
3. Container Security
4. OAuth and JWT Security
5. Open Redirect Scanner
6. Sensitive Information
7. WAF Detection
8. Web and API Security
9. Previous menu
```

```
dev/
├── api-scanner.sh
├── cloud-scanner.sh
├── container-scanner.sh
├── oauth-jwt-scanner.sh
├── open-redirect.sh
├── openredirect-scanner.py
├── sensitive-scanner.sh
├── waf-detect.sh
├── web-api-scanner.sh
├── data/
│   ├── api-paths.txt
│   └── swagger-paths.txt
└── lib/
    └── api-scanner/
        └── common.sh
```

## RECON
### Domain
```
RECON

1.  Passive
2.  Breaches
3.  Find registered domains
4.  Google dorks
5.  Web search
6.  Import names
7.  Import subdomains
8.  Previous menu
```

Note: Passive cannot be ran as root.

Uses ARIN, DNSRecon, dnstwist, subfinder, sublist3r,
theHarvester, Metasploit, Whois, and multiple websites.

* Acquire all free API keys for maximum results with theHarvester.
* Add API keys to $HOME/.theHarvester/api-keys.yaml
* Passive builds an HTML report at $HOME/data/<domain>/.
* Find registered domains updates pages/registered-domains.htm in an existing report.

#### Import names (`import-names.sh`)

Run after a passive scan when you want to add or enrich contacts from manual research
(LinkedIn, company sites, phone directories, etc.).

```
Enter the location of your previous passive scan:
/home/user/data/example.com

Enter manual contacts file (or press Enter for default):
```

* Edit $HOME/data/<domain>/tools/names-manual.tsv
* Format: Name, Title, Phone (tab-separated, one person per line)
* Lines starting with # are comments
* Title and phone may be left blank
* Re-run Import names whenever you add rows to the manual file

Import names merges three sources, then refreshes pages/names.htm:

1. tools/names — auto-discovered names from the passive scan
2. pages/names.htm — existing report table (preserves work already in the page)
3. tools/names-manual.tsv — manual entries; wins for title and phone when filled in

The merged TSV is saved back to tools/names. The names page is a sortable
three-column table: Name, Title, Phone.

#### Import subdomains (`import-subdomains.sh`)

Run after a passive scan when you want to add or enrich hosts from Pentest-Tools
or manual research.

```
Enter the location of your previous passive scan:
/home/user/data/example.com

Enter import file or firefox (or press Enter for default):
```

Supported imports:

* `firefox` — pull `pinia/scans` from your Firefox profile (free Pentest-Tools scans)
* Firefox `pinia/scans` export (`pinia-scans.json`)
* Pentest-Tools JSON (`pentest-tools-<domain>.json`)
* Pentest-Tools text export (`pentest-tools.txt`)
* Tab-separated host/IP rows

* Edit `$HOME/data/<domain>/tools/subdomains-import.tsv` for manual entries
* Format: Subdomain, IP (tab-separated; IP optional)
* Hosts without an IP are resolved with `dig` during import
* Re-run Import subdomains whenever you add rows or run a new Pentest-Tools scan

Import subdomains merges with existing `tools/subdomains`, assigns categories from
`misc/subdomain-categories.tsv`, splits private IPs to `tools/private-subs`, and
refreshes `pages/subdomains.htm` (Subdomain, Category, IP columns).

#### SEC leadership (Names page)

For US public companies, Discover pulls executives and directors from SEC
EDGAR before the names merge step:

1. **DEF 14A** — proxy statement prose and board tables for full titles
2. **Form 4** — recent insider filings to supplement officers and directors

* Results are written to zsec-people and merged into tools/names with the
  existing Name, Title, Phone columns (phone left blank).
* SEC filings do not provide work emails or per-person phone numbers.
* The Names page layout is unchanged — no email column is added.
* Manual override: tools/sec-people-manual.tsv (tab-separated: Name, Title, Phone).

#### Company HQ (Summary page)

During passive recon, Discover attempts to fill the address and phone block on
pages/summary.htm between the company name and domain.

1. **SEC EDGAR 10-K** — for US public companies, reads principal executive
   office fields from the latest 10-K (inline XBRL `dei:` tags).
2. **Website footer** — if SEC has no match, scans the cached homepage footer
   (and contact pages) for address/phone patterns.
3. **Manual override** — add entries to tools/company-manual.tsv when discovery
   is wrong or blocked.

Results are written to tools/company.json and injected into pages/summary.htm.

#### Social media (Summary page)

During passive recon, Discover fetches the company homepage and extracts
official social profile links (facebook, Instagram, LinkedIn, X, YouTube).
It then attempts to pull follower counts from each profile.

* Results are written to tools/social.tsv and injected into pages/summary.htm.
* If a platform blocks scraping, the follower count shows **Blocked**.
* If the homepage is bot-blocked, add URLs to tools/social-manual.tsv
  (tab-separated: Platform, URL) before or after the scan.

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

* Use different tools to create a target list including Angry IP Scanner, arp-scan, netdiscover, and Nmap pingsweep.

### CIDR, List, IP, Range, or URL
```
Type of scan:

1.  External
2.  Internal
3.  Previous menu
```

* External scan will set the Nmap source port to 53 and the max-rrt-timeout to 1500ms.
* Internal scan will set the Nmap source port to 88 and the max-rrt-timeout to 500ms.
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

* Uses sslscan, sslyze, and Nmap to check for SSL/TLS certificate issues.

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

### Update (main menu option 16)

* Updates the operating system, git pull from various repos, and update the locate database.
* Installs tools used by dev scanners (for example `ffuf`, `feroxbuster`, `jq`, `trivy`).

## DEV

Scan results are written under `$HOME/data/` unless noted otherwise.

### API Security Scanner (`dev/api-scanner.sh`)

Phased API discovery and security testing. Shared helpers and wordlists are in `dev/lib/api-scanner/` and `dev/data/`.

**Interactive menu**

```
1. API Discovery and Testing (full)
2. API Quick Scan (discovery + docs)
3. JWT Token Analysis
4. Full API Assessment (orchestrated)
5. Previous menu
```

**CLI** (skips the menu when `-u` is set):

```
./dev/api-scanner.sh -u https://target.example --quick --authorized
./dev/api-scanner.sh -u https://target.example --full --token 'eyJ…' --authorized
./dev/api-scanner.sh --resume ~/data/api-scan_20260703-1200 -u https://target.example
./dev/api-scanner.sh -u https://target.example --orchestrate --authorized
./dev/api-scanner.sh --help
```

| Flag | Purpose |
|------|---------|
| `--quick` | Discovery and documentation only |
| `--full` | All phases (default) |
| `--orchestrate` | Full scan, then prompts for related scanners |
| `--token` | Bearer token for authenticated requests |
| `--cookie-file` | Netscape cookie jar |
| `--max-parallel N` | Concurrent workers (default: 3) |
| `--max-endpoints N` | Cap endpoints tested after merge |
| `--skip PHASE` | Skip a phase (repeatable) |
| `--resume DIR` | Resume using an existing output directory |
| `--authorized` | Skip the authorization confirmation prompt |
| `--aggressive-http` | Include TRACE/CONNECT method tests |

**Phases (full scan):** HTML/JS link extraction, ffuf/feroxbuster fuzzing, path probing, OpenAPI/Swagger discovery, GraphQL tests (introspection, depth, batching), CORS (GET + preflight), HTTP method checks, rate-limit burst, JWT analysis.

**Output:** `$HOME/data/api-scan_<timestamp>/api_scanner/`

* `report.txt` and `report.md` — findings with severity, confidence, and evidence paths
* `findings_registry.tsv` — machine-friendly finding log
* `scan.log` — request audit trail
* `.checkpoint/` — resume markers per phase

Requires `curl` and `jq`. Uses `ffuf` or `feroxbuster` when installed (install via Discover **Update**).

### Cloud Security Scanner (`dev/cloud-scanner.sh`)

```
1. AWS (Amazon Web Services)
2. Azure (Microsoft Azure)
3. GCP (Google Cloud Platform)
4. Previous menu
```

Audits cloud CLI configuration and common misconfigurations. Requires the relevant cloud SDK/CLI and credentials.

### Container Security Scanner (`dev/container-scanner.sh`)

Comprehensive Docker and Kubernetes security assessment using Trivy, Docker, and kubectl.

* **Docker images** — vulnerability and misconfiguration scanning
* **Docker containers** — privileged mode, mounts, exposed ports
* **Kubernetes** — RBAC, network policies, pod security, workload risks

Optional CLI argument: `docker-images`, `docker-containers`, `kubernetes`, or `all` (default).

### OAuth and JWT Security Scanner (`dev/oauth-jwt-scanner.sh`)

```
1. OAuth Configuration/Security Test
2. JWT Security Test
3. Previous menu
```

Tests OAuth/OIDC discovery endpoints and JWT handling. Complements the API scanner JWT checks.

### Open Redirect Scanner (`dev/open-redirect.sh`)

```
1. Scan a single URL
2. Scan a domain
3. Scan multiple URLs from a file
4. Advanced options
5. Previous menu
```

Python engine: `dev/openredirect-scanner.py`.

### Sensitive Information Scanner (`dev/sensitive-scanner.sh`)

```
1. File or folder
2. URL
3. Previous menu
```

Hunts for secrets, credentials, and sensitive data in files or web content.

### WAF Detection (`dev/waf-detect.sh`)

```
1. Single target
2. Multiple targets from file
3. Previous menu
```

Identifies web application firewalls in front of targets.

### Web and API Security (`dev/web-api-scanner.sh`)

```
1. Scan a URL for web app and API vulnerabilities
2. Previous menu
```

Runs Metasploit resource scripts for web/API enumeration and testing. Requires PostgreSQL and Metasploit.

# Troubleshooting

Some users have reported being unable to use any options except for 3, 4, and 5. 
Nothing happens when choosing other options (1, 2, 6, etc.).

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

Some users have reported the fix is to use the VMware image instead of WSL. 

Other users have noticed issues when running a pre-made VirtualBox Kali image, instead of running the 
bare metal Kali ISO through VirtualBox. 
(https://www.kali.org/get-kali/#kali-bare-metal)

If you are unwilling or unable to use VMware Workstation to run Kali, we encourage you to try running 
a Kali ISO as a Guest VM in VirtualBox.

1. Download the bare metal ISO provided by Kali.
2. Verify the ISO hash (see above).
3. Start a new Kali VM within VirtualBox with the bare metal Kali ISO.

There will be some [basic installation instructions](https://www.kali.org/docs/installation/hard-disk-install/) 
you will be required to fill out during the installation.

Note: If you have problems accessing root after setting up a bare metal ISO, please refer to: 
https://linuxconfig.org/how-to-reset-kali-linux-root-password
