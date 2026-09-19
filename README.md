# Discover

Custom Bash and Python scripts used to automate various penetration testing tasks including recon, scanning, enumeration, and malicious payload creation using Metasploit. For use with Ubuntu. Limited support for Kali Linux.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/leebaird/discover/blob/main/LICENSE.txt)

* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1

----------------------------------------------------------------------------------------------

## Setup and usage

* Download to your home directory.

```
cd ~
git clone https://github.com/leebaird/discover
cd discover/
./discover.sh
```

* On first run, Discover asks for your **first name** (max 10 letters) and saves it to `~/.discover/operator-name`. That name is written on every engagement **audit log** line. To change it later, edit or delete that file and restart Discover.
* Select main menu option **18 Update** to update the operating system and install dependencies.
* Some options require root credentials to run.

---

### Optional shell helpers (`config/zshrc`)

```
cd ~/discover/config/
./install.sh
```

| Host | What `install.sh` does |
|------|-------------------------|
| **Ubuntu / other** (incl. macOS) | Copies `zshrc` to `~/.bash_aliases` and sources it |
| **Kali** (detected via `/etc/os-release`) | Appends `zshrc` to `~/.zshrc` |

Also installs `tmux.conf` to `~/.tmux.conf` and `vimrc` to `~/.vimrc`.

**Useful commands** (after install / new shell):

| Command | Purpose |
|---------|---------|
| `n` | Network summary (external/internal IP, DNS, MAC, iface; `ss` without TIME-WAIT; ping 8.8.8.8) |
| `s` | `cd ~/discover` and short `git status` (no pull) |
| `m` / `ms` | Start MSF DB + console / stop MSF DB |
| `web` / `web2` | HTTP server on port 80 (sudo) / 8000 |
| `now` | Formatted date/time (does not override `date`) |
| `update` | Grok update + full apt upgrade chain |
| `bh`, `th`, `smb`, `sip` | BloodHound, theHarvester, smbserver, IP sort |

Network identity (IPs, DNS, MAC) is computed **when you run** `n` / `web` / `upload` — not at shell startup — so new shells stay fast and values stay current after VPN/wifi changes.

**Notes**

* On Ubuntu and other non-Kali hosts, re-running overwrites `~/.bash_aliases` with the repo copy.
* On Kali, re-running `install.sh` **appends** again and can duplicate the block; edit `~/.zshrc` or install only once.
* Default zsh on macOS/Kali does not load `~/.bash_aliases` unless you source it from `~/.zshrc`.

---

## Main menu

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
12. Generate a malicious payload
13. Start a Metasploit listener
14. CVE lookup
15. Parse XML
16. Dev
17. Notes
18. Update
19. Exit
```

----------------------------------------------------------------------------------------------

## RECON

### Domain

```
RECON

1.  Passive
2.  Breaches
3.  Find registered domains
4.  Google dorks
5.  Web search

6.  Active
7.  Open report
8.  Previous menu
```

Note: Passive and Active cannot be run as root.

---

#### Engagement workflow

1. **Passive** — build `$HOME/data/<domain>/` HTML report.
2. **Open report** (or finish Active) so the engagement is on statusd.
3. **Audit > Import** — names, names/titles/emails, subdomains, or another operator’s package into the **current** report.
4. **Active** — httpx / whatweb / gowitness; Active and Subdomains pages; optional NVD CVSS.
5. **Shodan** (optional) — Active page **Enrich** (Shodan checkbox).
6. Software filter on Active, then filtered Subdomains, then host scans in operator mode.
7. **Export** — on Report > Audit (Discover-hosted only): Client, Defender, or Operator package.

---

#### Passive recon

Uses Amass, ARIN, DNSRecon, dnstwist, Metasploit, subfinder, sublist3r, Shodan CTL (free CT hostnames; no API key), theHarvester, Whois, and multiple websites.

* Acquire free API keys for maximum results with theHarvester (`$HOME/.theHarvester/api-keys.yaml`).
* Passive builds an HTML report at `$HOME/data/<domain>/`.
* Find registered domains updates `pages/registered-domains.htm` in an existing report.
* HTML **Reports** menu: **Passive**, **Active**, and **Audit**.
* Names: US public companies pull DEF 14A / Form 4 from SEC EDGAR.
* Summary: HQ from 10-K then website footer (`tools/company-manual.tsv` override); social profile links when found.

---

#### Import

On **Reports > Audit**, **Import** (Discover-hosted only) targets the **current** engagement.

| Choice | What it does |
|--------|----------------|
| **Operator scans** | Merge another operator’s unpacked report (host-scans, screenshots, Active data, their audit lines) |
| **Names** | Merge `tools/names-manual.tsv` (Name, Title, Phone; `#` comments; filled title/phone win) |
| **Names, titles, and emails** | Merge an external names dump into Names and Emails |
| **Subdomains** | Existing sources (Firefox / Pentest-Tools / TSV) or CSV `subdomain,ip,category`; optional Active on **new** public hosts |

CLI (same backends):

```
bash recon/import-names.sh --report /home/user/data/example.com --json
bash recon/import-names-titles-emails.sh --report /home/user/data/example.com --source /path/to/dump --json
bash recon/import-subdomains.sh --report /home/user/data/example.com \
  --mode team-csv --import /home/user/team-hosts.csv --json
# existing: --mode existing --import firefox|/path/to/export
# optional CSV: --run-active
```

CSV list skips hosts already in `tools/subdomains`. Empty IP then `dig`. Category: Discover rules first, else CSV. Never writes `recon/subdomain-categories.tsv`.

---

#### Active

Domain menu option 6. Run after Passive (and optionally Import subdomains).

```
Enter the location of a previous Discover scan:
/home/user/data/example.com
```

* Reads public hostnames from `tools/subdomains` (RFC1918 skipped).
* httpx (`tools/httpx.jsonl`); alive = 200–399, 401, 403, or 405.
* whatweb + gowitness on alive URLs; merge with `recon/active-tech.py`.
* Re-run Active to replace those artifacts and rebuild Active / Subdomains.

Artifacts live under `tools/` (`httpx.jsonl`, `whatweb.json`, `gowitness/`, `software-cves-cache.json`).

##### Software filter and host scans

In **operator** mode only (report opened via **Open report** / Active at `http://127.0.0.1:17322/…`), Subdomains public rows with an HTTP status get a host-scan expand control (also on `?software=` / `?cve=` filtered views). Manual `file://` open never shows chevrons. Expandable rows show host-scan **boxes** (quietest to loudest):

| Tool | Role | When shown |
|------|------|------------|
| **robots** | Fetch `/robots.txt` and list **Disallow** paths (same idea as multiTabs, then Directories in robots.txt); **TXT** = raw body, **WEB** = open Disallow dirs in Firefox | Always on expand |
| **nmap** | TCP-only: `nmap -Pn -n --open -sTV -p <ports> <host>`. With UDP: `sudo nmap --privileged -Pn -n --open -sTV -sUV -p T:<tcp>,U:<udp> <host>` (Shodan transport, else Discover `UDP=` list; port 53 always TCP+UDP). UDP prompts for sudo in the host-scan terminal if needed. If raw UDP sendto is blocked (often VPN/TUN), TXT warns and does not keep `tcpwrapped` as a UDP fingerprint. **TXT**; **web** opens each http/https SERVICE in Firefox (`ssl/unknown` as https) | **Gated:** Shodan ports for that IP, or the row URL is http/https (80 or 443 even if Shodan is empty). No HTTP pre-check |
| **nuclei** | Template recon (product tags) then auto **Pass 2** CVE/KEV from the engagement software-CVE cache + CISA KEV (local nuclei templates only) | **Gated:** product known via `?software=` **or** row fingerprint (Technologies / title / web server / hostname). Hidden when no product is known |
| **droopescan** | CMS enum (`scan drupal` / ...; `-e a -t 4 --hide-progressbar`); TXT drops percent-bar lines | **Gated:** supported CMS from `?software=` **or** row fingerprint (Drupal, Joomla, Moodle, Silverstripe — not WordPress) |
| **WPScan** | WordPress checks (passive plugin detection + moderate enum) | **Gated:** WordPress from `?software=` **or** row fingerprint. Optional `WPSCAN_API_TOKEN` for vuln DB |
| **nikto** | Web server checks (request timeout 5s, FAILURES=8, maxtime 10m, hard stop 11m); report **TXT** + **HTM** when the scan actually ran | Always on expand |
| **feroxbuster** | Content discovery (same wordlist picker as ffuf; no recursion; auto-bail; 10 threads, 20 req/s, 5s timeout, 10m time-limit); report **TXT** + **WEB** | Always on expand |
| **ffuf** | Content discovery (quiet defaults); report **TXT** + **WEB** (open each finding in Firefox) | Always on expand |

Each box shows the tool name and a blue **Run** button on one line, plus last-run time and green output buttons (**TXT** / **HTM** / **WEB** as applicable). A Unicode **ⓘ** in the top-right of each box opens a modal explaining what the tool does, when it appears, what Run does, safety check, and outputs.

**Software fingerprint (expand):** `?software=` wins (e.g. Active Software versions link). Otherwise Discover reads the row Technologies tokens (keeps version when present, e.g. `Kibana:9.4.2`), then title, web server, and hostname labels (every label, e.g. `uatapi.iis.cgi.com` to IIS). Priority products include CMS, Kibana, Grafana, Prometheus, Elasticsearch, Jenkins, Kafka UI / Kafbat UI / AKHQ, Filebrowser, SonarQube, RabbitMQ, Redis Commander, Kiali, Kubecost, Superset, GitLab / Gitea / Gogs, Keycloak, Citrix / NetScaler AAA, Rancher, Argo CD (hostname `argocd` / `argo-*`), Eureka, Harbor, MinIO, Nexus, JFrog / Artifactory, Strapi, CloudBeaver, DBeaver, pgAdmin, UiPath (hostname `accel360`), Oracle (`oci-adb-control` / OCI ADB Control; not the bare `oci` label), Tomcat, WildFly / JBoss, SharePoint, IIS, nginx, Apache, ASP.NET, PHP, Node.js, CrafterCMS, Java (not JavaScript). Not Cisco ASA VPN. Citrix / NetScaler AAA is fingerprinted for nuclei (`-tags citrix,netscaler`). That product string is passed into `run-host-scan.sh` so nuclei Pass 1 uses product tags and Pass 2 can select CVE templates.

**Reachability pre-check** (HTTP expand tools): before nuclei, droopescan, wpscan, robots, nikto, ffuf, or feroxbuster launches, `misc/run-host-scan.sh` runs a **curl HTTP/1.1 GET** (15s max, same User-Agent as the scan). One request records status and time; a `000` result is retried once. **robots** probes `{origin}/robots.txt` (not the site root), so a slow or 403 homepage does not skip a working robots.txt. If the probe does not answer HTTP, Discover **does not run the tool**. The run’s `output.txt` records the skip, `status.json` / `latest.json` set `skip_reason=host_unreachable`, and the box shows **Unreachable** (red) with a **TXT** note. **Nikto** does not show **HTM** on that skip, and **robots** does not show **WEB** (no report / no Disallow list). **nmap** does not use this gate (Shodan ports and/or the row HTTP port).

**Google Sheet (optional):** Audit **Config > Google Sheet** stores a spreadsheet URL for this engagement (`tools/op-notes-url`). Host-scan Start appends one row. **Authorize** in that panel. Empty URL means off. Append uses `uv` (Discover install). A missing `uv`, missing token, or failed write prints on the scan and does not abort the tool. Client/defender exports omit the URL file.

Active **Scope:** public / private / responding hosts. Status codes count all httpx responses; screenshots, whatweb, and Categories use the alive subset.

---

#### API keys, Shodan, and KEV

Audit **Config > APIs** (or `~/.discover/api-keys`, `chmod 600`). Shell export wins if set. Update seeds the file from `resource/api-keys.example` when missing.

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Faster Active CVSS (still runs without a key, slower). [Request a key](https://nvd.nist.gov/developers/request-an-api-key) |
| `DISCOVER_SKIP_CVE=1` | Skip NVD queries; Software table still lists versions |
| `SHODAN_API_KEY` | Active **Enrich** (Shodan). Membership key; host lookups do not use query credits. [Account](https://account.shodan.io/) |
| `WPSCAN_API_TOKEN` | Optional WPScan vuln DB |

theHarvester keys stay in `~/.theHarvester/api-keys.yaml` (Config **APIs** has a link). CVSS values are triage leads from NVD CPE, not confirmed findings.

**Shodan:** Report > Active > Enrich after Active. Looks up public IPs from `tools/httpx.jsonl`. Without a key the flow soft-skips.

**KEV:** Update downloads CISA KEV to `resource/kevs.json`. Open report rewrites `tools/shodan/kev-ids.js` for that engagement (no Shodan re-query). Active Software **Top CVE** prefers a KEV match when present (orange **KEV** badge).

---

#### Open report

Domain menu **7**. Reopen an existing report (does not re-run Passive/Active). Saves the path to `~/.discover/current-report`, refreshes Audit, syncs host-scan assets, refreshes KEV badges if Shodan artifacts exist, and opens the report in a browser.

---

#### Export report

Discover-hosted **Report > Audit > Export**. Default output directory `$HOME/data`. Filename `YYYYMMDD-HHMM` uses the Config **Time zone**. Ledger and audit line stay UTC.

| Kind | Package |
|------|---------|
| **Client** | HTML ZIP; operator IPs redacted; scans disabled |
| **Defender** | Audit log CSV only |
| **Operator** | Full HTML ZIP; IPs included; launches enabled |

---

#### Audit page

Reports > Audit. **Config** (hosted only): Operator name, Time zone (display and metrics only; stamps stay UTC), APIs, Google Sheet. **Delete** on log rows (hosted only). **Import** as above.

---

### Person

```
RECON

First name:
Last name:
```

* Combines info from multiple websites.

----------------------------------------------------------------------------------------------

## SCANNING

### Generate target list

```
SCANNING

1.  ARP scan
2.  Ping sweep
3.  Previous menu
```

* Use different tools to create a target list including Angry IP Scanner, arp-scan, netdiscover, and Nmap pingsweep.

---

### CIDR, List, IP, Range, or URL

```
Type of scan:

1.  External
2.  Internal
3.  Previous menu
```

* External scan sets the Nmap source port to 53 and max-rtt-timeout to 1500ms.
* Internal scan sets the Nmap source port to 88 and max-rtt-timeout to 500ms.
* Nmap performs host discovery, port scanning, service enumeration, and OS identification.
* Nmap scripts and Metasploit auxiliary modules provide additional enumeration.
* Additional tools: enum4linux, smbclient, and ike-scan.

----------------------------------------------------------------------------------------------

## WEB

### Insecure direct object reference

```
Using Burp, authenticate to a site, map & Spider, then log out.
Target > Site map > select the URL > right click > Copy URLs in
this host. Paste the results into a new file.

Enter the location of your file:
```

---

### Open multiple tabs in Firefox

```
Open multiple tabs in Firefox with:

1.  List
2.  Files in a directory
3.  Directories in robots.txt
4.  Previous menu
```

Examples:

* A list containing multiple IPs and/or URLs
* Open every Nikto HTML report in a directory
* wget a domain’s `robots.txt`, then open listed directories

---

### Nikto

```
This option cannot be run as root.

Run multiple instances of Nikto in parallel.

1.  List of IPs
2.  List of IP:port
3.  Previous menu
```

---

### SSL

```
Check for SSL certificate issues.

List of IP:port.

Enter the location of your file:
```

* Uses sslscan, sslyze, and Nmap to check for SSL/TLS certificate issues.

----------------------------------------------------------------------------------------------

## MISC

### Generate a malicious payload

Main menu option **12**.

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

---

### Start a Metasploit listener

Main menu option **13**.

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

---

### CVE lookup

Main menu option **14**.

```
CVE:
CVE-2018-7600
```

* Accepts `CVE-YYYY-NNNN`, `YYYY-NNNN`, or a **4+ digit number** for the current year.
* Opens Firefox tabs for NVD, Rapid7, Tenable, Exploit-DB, Sploitus, CVEbase, GitHub, and CISA KEV search.

---

### Parse XML

Main menu option **15**.

```
Parse XML to CSV.

1.  Burp (Base64)
2.  Nessus (.nessus)
3.  Nexpose (XML 2.0)
4.  Nmap
5.  Qualys
6.  Previous menu
```

---

### Notes

Main menu option **17**. Opens `notes/index.htm` in a browser when available.

---

### Update

Main menu option **18** (`misc/update.sh`). OS packages, git pulls, locate DB, recon/dev tools, desktop handlers, Edge User-Agent, and CISA KEV catalog.

Gotchas:

* **nuclei-templates** — git clone + `git pull --ff-only` (not `nuclei -ut`).
* **gowitness** — clone/build under `/opt/gowitness` (not `go install @latest`; that module uses `replace`).
* **nikto** — git under `/opt/nikto` (not the stale apt 2.1.5 package).
* **Metasploit** — snap refresh when snap is installed; otherwise apt. Snap MSF does not use `msfupdate`.

---

## DEV

Security scanners by [Yiğit ibrahim (ibrahimsql)](https://github.com/ibrahimsql). Main menu **16**.

Standalone reports under `$HOME/data/` (`api-scan_*`, `cloud-scan_*`, and so on). They **do not** write Discover’s domain HTML report (`$HOME/data/<domain>/pages/*.htm`). Flags and output files: each script’s `-h`.

```
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

| Menu | Script |
|------|--------|
| API Security | `dev/api-scanner.sh` |
| Cloud Security | `dev/cloud-scanner.sh` |
| Container Security | `dev/container-scanner.sh` |
| OAuth and JWT Security | `dev/oauth-jwt-scanner.sh` |
| Open Redirect Scanner | `dev/open-redirect.sh` |
| Sensitive Information | `dev/sensitive-scanner.sh` |
| WAF Detection | `dev/waf-detect.sh` |
| Web and API Security | `dev/web-api-scanner.sh` |
