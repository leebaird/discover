```
Custom bash scripts used to automate various penetration testing tasks including recon, scanning,
enumeration, HTML engagement reports, and malicious payload creation using Metasploit. For use with
Kali Linux or Ubuntu.
```

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/leebaird/discover/blob/master/LICENSE)

* [![Twitter Follow](https://img.shields.io/twitter/follow/discoverscripts.svg?style=social&label=Follow)](https://twitter.com/discoverscripts) Lee Baird @discoverscripts
* [![Twitter Follow](https://img.shields.io/twitter/follow/jay_townsend1.svg?style=social&label=Follow)](https://twitter.com/jay_townsend1) Jay "L1ghtn1ng" Townsend @jay_townsend1
* [![Twitter Follow](https://img.shields.io/twitter/follow/ninewires.svg?style=social&label=Follow)](https://twitter.com/ninewires) Jason Ashton @ninewires


## Table of contents

- [Setup and usage](#setup-and-usage)
  - [Shell helpers](#shell-helpers-configzshrc)
- [Main menu](#main-menu)
- [RECON](#recon)
  - [Domain](#domain)
    - [Engagement workflow](#engagement-workflow)
    - [Import names](#import-names)
    - [Import names, titles, and emails](#import-names-titles-and-emails)
    - [Import subdomains](#import-subdomains)
    - [Active](#active)
    - [NVD API key](#nvd-api-key-optional-active-cvss)
    - [CISA KEV](#cisa-known-exploited-vulnerabilities-kev)
    - [Import report](#import-report)
    - [Export report](#export-report)
    - [Enrich with Shodan](#enrich-with-shodan)
    - [Audit page](#audit-page)
    - [SEC leadership](#sec-leadership-names-page)
    - [Company HQ](#company-hq-summary-page)
    - [Social media](#social-media-summary-page)
  - [Person](#person)
- [SCANNING](#scanning)
  - [Generate target list](#generate-target-list)
  - [CIDR, List, IP, Range, or URL](#cidr-list-ip-range-or-url)
- [WEB](#web)
  - [Insecure direct object reference](#insecure-direct-object-reference)
  - [Open multiple tabs in Firefox](#open-multiple-tabs-in-firefox)
  - [Nikto](#nikto)
  - [SSL](#ssl)
- [MISC](#misc)
  - [Generate a malicious payload](#generate-a-malicious-payload)
  - [Start a Metasploit listener](#start-a-metasploit-listener)
  - [CVE lookup](#cve-lookup)
  - [Parse XML](#parse-xml)
  - [Notes](#notes)
  - [Update](#update)
- [DEV](#dev)
  - [Dev menu](#dev-menu)
  - [Layout](#layout)
  - [API Security Scanner](#api-security-scanner)
  - [Cloud Security Scanner](#cloud-security-scanner)
  - [Container Security Scanner](#container-security-scanner)
  - [OAuth and JWT Security Scanner](#oauth-and-jwt-security-scanner)
  - [Open Redirect Scanner](#open-redirect-scanner)
  - [Sensitive Information Scanner](#sensitive-information-scanner)
  - [WAF Detection](#waf-detection)
  - [Web and API Security](#web-and-api-security)

----------------------------------------------------------------------------------------------

## Setup and usage

* Download to your home directory.

```
cd ~
git clone https://github.com/leebaird/discover
cd discover/
./discover.sh
```

* Select **Update** (main menu option **18**) to update the operating system and install dependencies (`droopescan`, `feroxbuster`, `ffuf`, `jq`, `nuclei`, etc.).
* Some options require root credentials to run.
* Optional: install operator shell helpers from `config/` (see below).

---

### Shell helpers (`config/zshrc`)

Discover ships interactive shell helpers used on assessment workstations (network summary, Metasploit, Discover shortcuts, etc.). Source file: **`config/zshrc`** (shared by bash and zsh).

**Install** from the config directory:

```
cd ~/discover/config/
./install.sh
```

| Host | What `install.sh` does |
|------|-------------------------|
| **Kali** (detected via `/etc/os-release`) | Appends `zshrc` to `~/.zshrc` |
| **Other** (e.g. Ubuntu) | Copies `zshrc` to `~/.bash_aliases` and sources it |

Also installs `tmux.conf` → `~/.tmux.conf` and `vimrc` → `~/.vimrc`.

**Useful commands** (after install / new shell):

| Command | Purpose |
|---------|---------|
| `n` | Network summary (external/internal IP, DNS, MAC, iface; `ss` without TIME-WAIT; ping 8.8.8.8) |
| `s` | `cd ~/discover` and short `git status` (no pull) |
| `m` / `ms` | Start MSF DB + console / stop MSF DB |
| `web` / `web2` | HTTP server on port 80 (sudo) / 8000 |
| `now` | Formatted date/time (does not override `date`) |
| `update` | Grok update + full apt upgrade chain |
| `bh`, `th`, `smb`, `sip`, … | BloodHound, theHarvester, smbserver, IP sort, etc. |

Network identity (IPs, DNS, MAC) is computed **when you run** `n` / `web` / `upload` — not at shell startup — so new shells stay fast and values stay current after VPN/wifi changes.

**Notes**

* On Kali, re-running `install.sh` **appends** again and can duplicate the block; edit `~/.zshrc` or install only once.
* On non-Kali, re-running overwrites `~/.bash_aliases` with the repo copy.
* Default zsh on macOS/Kali does not load `~/.bash_aliases` unless you source it from `~/.zshrc`.

Also covered in the HTML notes: `notes/kali.txt`, `notes/ubuntu.txt`, `notes/macos.txt`.

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

6.  Import names
7.  Import names, titles, and emails
8.  Import subdomains

9.  Active
10. Import report
11. Enrich with Shodan
12. Export report
13. Previous menu
```

Note: Passive and Active cannot be run as root.

---

#### Engagement workflow

Typical domain engagement path:

1. **Passive** — build `$HOME/data/<domain>/` HTML report.
2. **Import names** / **Import names, titles, and emails** / **Import subdomains** — enrich contacts and hosts.
3. **Active** — httpx / whatweb / gowitness; Active and Subdomains pages; optional NVD CVSS.
4. **Enrich with Shodan** (optional) — host-by-IP OSINT for public IPs from Active httpx.
5. Software filter on Active → filtered Subdomains → host scans (Nuclei, droopescan when CMS, Nikto, ffuf) in operator mode.
6. **Import report** — reopen the live tree later for more testing (operator mode).
7. **Export report** — Client, Defender, or Audit-only package for delivery.
8. **Reports → Audit** in the HTML report — Target scans, Audit log, and Exports.

---

#### Passive recon

Uses Amass, ARIN, DNSRecon, dnstwist, Metasploit, subfinder, sublist3r, theHarvester, Whois, and multiple websites.

* Acquire free API keys for maximum results with theHarvester.
* Add API keys to `$HOME/.theHarvester/api-keys.yaml`.
* Passive builds an HTML report at `$HOME/data/<domain>/`.
* Find registered domains updates `pages/registered-domains.htm` in an existing report.
* Active uses httpx, whatweb, and gowitness; optional NVD API key speeds CVSS enrichment (see [NVD API key](#nvd-api-key-optional-active-cvss)).
* HTML **Reports** menu: **Passive**, **Active**, and **Audit**.

---

#### Import names

Script: `recon/import-names.sh` (Domain menu **6**).

Run after a passive scan to add or enrich contacts from manual research (LinkedIn, company sites, phone directories, etc.).

```
Enter the location of your previous passive scan:
/home/user/data/example.com

Enter manual contacts file (or press Enter for default):
```

* Edit `$HOME/data/<domain>/tools/names-manual.tsv`
* Format: Name, Title, Phone (tab-separated, one person per line)
* Lines starting with `#` are comments
* Title and phone may be left blank
* Re-run Import names whenever you add rows to the manual file

Merges three sources, then refreshes `pages/names.htm`:

1. `tools/names` — auto-discovered names from the passive scan
2. `pages/names.htm` — existing report table
3. `tools/names-manual.tsv` — manual entries (wins for title/phone when filled in)

The merged TSV is saved back to `tools/names`. The Names page is a sortable three-column table: Name, Title, Phone.

---

#### Import names, titles, and emails

Script: `recon/import-names-titles-emails.sh` (Domain menu **7**).

Merge a separate names dump (with optional titles and emails) into an existing passive engagement.

```
Enter the location of the names file:
/home/user/data/names-from-osint.txt

Enter the location of your previous passive scan:
/home/user/data/example.com
```

* Requires a readable source file and a report that already has `pages/names.htm`
* Accepts free-form lines (`Name Title email@domain`) and tab-separated rows (`Name`, `Title`, `Email`, `Phone`)
* Merges into `tools/names` and `tools/emails`, and refreshes `pages/names.htm` / passive summary counts
* Useful when contacts come from a tool or export outside Discover’s manual TSV

---

#### Import subdomains

Script: `recon/import-subdomains.sh` (Domain menu **8**).

Run after a passive scan to add or enrich hosts from Pentest-Tools or manual research.

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

Merges with existing `tools/subdomains`, assigns categories from `old/subdomain-categories.tsv`, splits private IPs to `tools/private-subs`, and refreshes `pages/subdomains.htm` with Subdomain, Category, and IP columns only. Run **Active** afterward to populate Photo, Status, Web Server, and Technologies.

---

#### Active

Script: `recon/active.sh` (Domain menu **9**).

Run after a passive scan (and optionally Import subdomains) to probe which public hosts respond over HTTP/HTTPS, fingerprint technologies, and capture screenshots.

```
Enter the location of your previous passive scan:
/home/user/data/example.com
```

Requires `httpx`, `whatweb`, `gowitness`, `python3`, and Chrome or Chromium (install via **Update**).

* Reads public hostnames from `tools/subdomains` (RFC1918 IPs are skipped)
* Probes hostnames with httpx; writes `tools/httpx.jsonl`
* Treats responses with status 200–399, 401, 403, or 405 as alive
* Fingerprints alive URLs with whatweb; writes `tools/whatweb.json`
* Screenshots alive URLs with gowitness (go-rod driver) under `tools/gowitness/`
* Merges httpx and whatweb with `recon/active-tech.py` and refreshes `pages/subdomains.htm`
* Writes an Active summary to `pages/active.htm` (Reports menu → Active), including software versions enriched with NVD CVSS when available
* Re-run Active to replace httpx/whatweb/gowitness artifacts and rebuild Active columns

HTML **Reports** menu: **Passive** (`pages/passive.htm`), **Active** (`pages/active.htm`), **Audit** (`pages/audit.htm`).

##### Software filter and host scans

On Active **Software versions**, versions that have NVD CVEs are linked to a filtered Subdomains view (`subdomains.htm?software=…`). The Active page header also has a centered **CVE search** bar: enter `CVE-YYYY-NNNNN` (or `YYYY-NNNNN`) to open Subdomains filtered to hosts running software linked to that CVE in the engagement NVD cache (`tools/cve-software-index.js`). Same filter banner / host-scan layout as software links (`subdomains.htm?cve=…`).

In **operator** mode (live tree opened via **Import report**), expandable rows show host-scan **boxes** (quietest → loudest):

| Tool | Role | When shown |
|------|------|------------|
| **Nuclei** | Template recon (software tags) then auto **Pass 2** CVE/KEV templates from the engagement software-CVE cache + CISA KEV (local nuclei templates only) | Always on filtered expand |
| **droopescan** | CMS enum (`scan drupal` / `wordpress` / …; `-e a -t 4`) | **Gated:** only when the software filter is a supported CMS (Drupal, WordPress, Joomla, Moodle, Silverstripe — including version labels like `Drupal:7`) |
| **Nikto** | Web server checks; report **TXT** + **HTM** when present | Always on filtered expand |
| **ffuf** | Content discovery (quiet defaults); report **TXT** + **URL** (open each finding in Firefox) | Always on filtered expand |

Each box shows the tool name and a blue **Run** button on one line, plus last-run time and green output buttons (**TXT** / **HTM** / **URL** as applicable).

**ffuf quiet defaults** (`misc/run-host-scan.sh`):

* No custom `-mc` (ffuf defaults keep 2xx, 500, etc.)
* `-fc 301,302,307,400,401,403,404,405,429` (drop redirects and common noise; keep 500s for version banners)
* `-t 8 -rate 20 -noninteractive`; SecLists `common.txt` (or fallbacks)
* Report text is ANSI-cleaned (no progress ESC junk); **Duration** stripped from hit lines
* **URL** uses `discover-ffuf:` → `misc/open-ffuf-tabs.sh` (Firefox CLI, one tab per unique finding URL; cap 40)

**Nuclei** writes a structured `output.txt` (Pass 1 / Pass 2). Empty findings files say `No vulnerabilities discovered.`

Launches use the `discover-scan:` handler / `misc/run-host-scan.sh` (one tool at a time). Prefer `~/.local/bin` for **droopescan** on Python 3.12+ (Update runs `misc/patch-droopescan-py314.sh` for cement/`imp` + setuptools). Optional live status via localhost `misc/host-scan-statusd.py`. Client and defender export packages disable launches.

##### Active Scope metrics

| Metric | Meaning |
|--------|---------|
| Public subdomains | Hosts in `tools/subdomains` with non-RFC1918 IPs |
| Private subdomains | Rows in `tools/private-subs` |
| Responding hosts | Unique hosts with an httpx status (any code) |

**Status codes** on the Active page count **all** httpx responses (including 404/5xx). Screenshots, whatweb, and **Alive by category** still use the alive subset only (status 200–399, 401, 403, or 405).

##### Public subdomains table (after Active)

| Column | Source |
|--------|--------|
| Subdomain, Category, IP | Passive scan / Import subdomains |
| Photo | gowitness screenshot link when captured |
| Status | httpx status code |
| Web Server | httpx/whatweb Server header |
| Title / Technologies | httpx page title (filtered) + httpx tech / whatweb plugins |

The private subdomains table stays three columns (Subdomain, Category, Private IP Address).

`active-tech.py` merges and deduplicates overlapping data between columns — for example, OpenSSL and mod_jk versions drop out of Web Server when already listed in Technologies, `Microsoft IIS/10` shortens to `Microsoft IIS` when `IIS:10` is present, `Apache/2.4.37` shortens to `Apache` when `Apache HTTP Server:2.4.37` is present, OS names such as Red Hat are removed from Technologies when already shown in the Web Server banner, and httpx `Nginx` labels are normalized to `nginx`.

Artifacts under `tools/`:

* `active-targets.txt` — public hostnames sent to httpx
* `httpx.jsonl` — httpx JSON output
* `active-alive.tsv` — host, URL, and status for alive responses
* `active.txt` — alive URLs sent to whatweb and gowitness
* `whatweb.json` — whatweb JSON output
* `gowitness/screenshots/` — JPEG screenshots
* `gowitness/gowitness.jsonl` and `gowitness/gowitness.db` — gowitness metadata
* `software-cves-cache.json` — cached NVD CVSS/CVE lookups for the Active report

---

#### NVD API key (optional, Active CVSS)

Active recon can enrich the **Software versions** table on `pages/active.htm` with CVSS scores and CVE IDs from the [National Vulnerability Database](https://nvd.nist.gov/). Lookups are implemented in `recon/software-cve.py`.

**Without a key:** enrichment still runs, but NVD’s anonymous rate limits apply (slower).

**With a key:** authenticated rate limits (much faster).

**Skip enrichment entirely:**

```
export DISCOVER_SKIP_CVE=1
```

**Get a free API key**

1. [Request an NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
2. Confirm the email NIST sends
3. Provide the key to Discover (shell export and/or private `.env` — see below)

**How Discover finds the key** (non-empty values higher in the list win):

1. Shell environment — `export NVD_API_KEY=...`
2. Private `.env` in the Discover install — `$DISCOVER/.env`
3. Private `.env` in your home config — `~/.discover/.env`

Example `.env` line (no quotes required):

```
NVD_API_KEY=your-key-here
```

* Copy the template: `cp ~/discover/.env.example ~/discover/.env` or `mkdir -p ~/.discover && cp ~/discover/.env.example ~/.discover/.env`
* `.env` is gitignored; never commit real keys
* `.env.example` is tracked as documentation only

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Optional NVD API key for faster CVSS lookups |
| `DISCOVER_SKIP_CVE=1` | Skip NVD queries; Software table still lists versions |
| `DISCOVER_CVE_PROGRESS=1` | Print each product lookup while building Active |
| `SHODAN_API_KEY` | Optional Shodan key for post-Active host enrichment (Domain menu **11**) |

Cache file: `<report>/tools/software-cves-cache.json`. CVSS values are **triage leads** from NVD CPE matches, not confirmed findings — validate before reporting to a client.

---

#### Enrich with Shodan

Script: `recon/shodan-enrich.sh` + `recon/shodan-enrich.py` (Domain menu **11**).

After **Active** recon, look up unique **public** IPs from `tools/httpx.jsonl` in the [Shodan](https://www.shodan.io/) host database (org, ports, banners, vulns when present).

**Requires a Shodan membership (or higher) API key.** Without a key the option soft-skips (prints how to add the key and exits cleanly). IP host lookups do **not** consume Shodan query credits.

**Get a key**

1. [Shodan account](https://account.shodan.io/) / [Membership](https://www.shodan.io/store/member)
2. Copy the API key from the account page
3. Provide it to Discover (same pattern as NVD):

```
export SHODAN_API_KEY=...
# or
# SHODAN_API_KEY=...  in $DISCOVER/.env or ~/.discover/.env
```

**How it works**

1. Prefers the current engagement from Import report / Active (`~/.discover/current-report`)
2. Collects unique public IPv4/IPv6 from `tools/httpx.jsonl` (`host_ip`, then `a[]`)
3. Calls `GET https://api.shodan.io/shodan/host/{ip}` (rate-limited; default ~1.1s between requests)
4. Resumes: skips IPs that already have a successful cache under `tools/shodan/hosts/`
5. Appends an Audit log line and refreshes `pages/audit.htm`

**Artifacts** (`<report>/tools/shodan/`)

| Path | Content |
|------|---------|
| `hosts/<ip>.json` | Per-IP raw Shodan response (wrapped with Discover status) |
| `summary.json` | Aggregate stats + flattened host rows |
| `summary.tsv` | Spreadsheet-friendly (org, ports, vulns, hostnames) |
| `index.json` | Compact IP → org / ports / hostnames |

**Subdomains UI:** when enrichment has run, public rows whose IP is in Shodan show a small **▸** to the left of the subdomain. Click it for Hostnames, Location, Org, ISP, Ports, and NVD-linked CVEs. CVEs that appear in the CISA KEV catalog get a red **KEV** badge (links to the catalog search). Values are **IP-level** (same record on every hostname sharing that IP).

Powered by `tools/shodan/index.js` and `tools/shodan/kev-ids.js` (works under local `file://`). `index.json` is the same data for tools/scripts. KEV IDs come from Discover’s CISA catalog (`resource/known_exploited_vulnerabilities.json`).

**Keeping KEV badges current:** **Update** only refreshes the install-wide CISA catalog (reports can live on the Desktop or anywhere — Update cannot find them all). **Import report** rewrites `tools/shodan/kev-ids.js` for the report you open, using that catalog (no Shodan API re-query). Import any engagement after Update to pick up new KEV entries. No Shodan index → no toggles. Hard-refresh Subdomains after Import.

**CLI** (outside the menu):

```
python3 $DISCOVER/recon/shodan-enrich.py /path/to/report
python3 $DISCOVER/recon/shodan-enrich.py /path/to/report --dry-run
python3 $DISCOVER/recon/shodan-enrich.py /path/to/report --limit 5
python3 $DISCOVER/recon/shodan-enrich.py /path/to/report --force
# After Update (or manually): refresh KEV badges only
python3 $DISCOVER/recon/shodan-enrich.py --refresh-kev --all-engagements
python3 $DISCOVER/recon/shodan-enrich.py --refresh-kev /path/to/report
```

Shodan data can be stale — confirm open ports and services with live scans before reporting.

---

#### CISA Known Exploited Vulnerabilities (KEV)

Discover **Update** (main menu option **18** / `misc/update.sh`) downloads the CISA KEV JSON catalog into Discover’s `resource/` folder:

```
$DISCOVER/resource/known_exploited_vulnerabilities.json
```

* Feed: [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
* Catalog: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

If the download fails, any previous local catalog is left in place. The file is gitignored (refreshed by Update, not committed).

Reports may live under `$HOME/data/`, the Desktop, or elsewhere. Update does **not** rewrite every engagement’s `kev-ids.js`. After Update, **Import report** on each engagement that has Shodan data to refresh Subdomains **KEV** badges from the new catalog (no Shodan API re-query).

On the Active **Software versions** table, **Top CVE** prefers a CISA KEV match when any of the product’s NVD CVEs appear in the KEV catalog (highest CVSS among KEVs wins). Otherwise Top CVE is the highest-CVSS NVD result. KEV selections show an orange **KEV** badge next to the linked CVE ID.

---

#### Import report

Script: `recon/import-report.sh` (Domain menu **10**).

Reopen an existing engagement HTML report for continued operator work (does not re-run Passive/Active).

```
Enter the location of your report:
/home/user/data/example.com
```

* Accepts a report root directory (or a page under it such as `index.htm` / `pages/active.htm`) — any path (Desktop, `$HOME/data/`, external disk)
* Marks the live tree as **operator** mode (`assets/report-mode.json`, launches enabled)
* Saves the engagement path to `~/.discover/current-report` for host-scan helpers
* Seeds `tools/audit/` and refreshes `pages/audit.htm`
* Syncs host-scan UI assets and ensures **Reports → Audit** on all pages (including the homepage)
* If the report has Shodan artifacts (`tools/shodan/`), rewrites `tools/shodan/kev-ids.js` from Discover’s CISA KEV catalog (keeps Subdomains **KEV** badges current after **Update**)
* Opens the report in a browser when possible

Empty or invalid paths show an error and exit (same style as Active / Import names).

---

#### Export report

Script: `recon/export-report.sh` (Domain menu **12**).

Package a snapshot for delivery without leaving the live tree in client mode.

```
Package for:
  c) Client   — HTML report; audit log redacts operator egress IPs (default)
  d) Defender — HTML report; audit log keeps operator egress IPs
  a) Audit only (defenders) — plain-text audit log with operator IPs

Export label (e.g. briefing, update) [briefing]:
```

* Prefers the session engagement from Import report when available
* **Client** — ZIP of the HTML report; operator IPs redacted in the shipped audit log; scan launches disabled
* **Defender** — ZIP of the HTML report; operator IPs kept; launches disabled
* **Audit only** — plain-text audit log with operator IPs (for defenders)
* Writes an **Exports** entry under `tools/exports/` and an audit log line
* Live report under `$HOME/data/<domain>/` stays operator mode for continued testing

---

#### Audit page

Built by `recon/audit-build.py` into `pages/audit.htm` (HTML **Reports → Audit**).

| Section | Content |
|---------|---------|
| **Target scans** | Per-host history for **Nuclei**, **droopescan**, **Nikto**, **ffuf** (quietest → loudest columns). Timestamp plus **TXT** / **HTM** / **URL** buttons when outputs exist |
| **Audit log** | Newest-first by default; **Time (UTC)**, **Operator IP**, **Action**, **Output**. Hides routine noise (report open, nuclei pass-2 start/finish). Strips successful `(exit 0)` from display |
| **Exports** | Label, kind (Client / Defender / Audit only), exported time (UTC), operator IPs (Included / Redacted), file name |

Import report rebuilds this page. Host scans and exports append data under `tools/` that appears on Audit after the next rebuild (Import, host-scan finish, or export path).

---

#### SEC leadership (Names page)

For US public companies, Discover pulls executives and directors from SEC EDGAR before the names merge step:

1. **DEF 14A** — proxy statement prose and board tables for full titles
2. **Form 4** — recent insider filings to supplement officers and directors

* Results are written to `zsec-people` and merged into `tools/names` (Name, Title, Phone; phone left blank).
* SEC filings do not provide work emails or per-person phone numbers.
* Manual override: `tools/sec-people-manual.tsv` (tab-separated: Name, Title, Phone).

---

#### Company HQ (Summary page)

During passive recon, Discover attempts to fill the address and phone block on `pages/summary.htm`:

1. **SEC EDGAR 10-K** — principal executive office from the latest 10-K (inline XBRL `dei:` tags)
2. **Website footer** — homepage footer / contact pages when SEC has no match
3. **Manual override** — `tools/company-manual.tsv`

Results go to `tools/company.json` and `pages/summary.htm`.

---

#### Social media (Summary page)

During passive recon, Discover extracts official social profile links (Facebook, Instagram, LinkedIn, X, YouTube) and attempts follower counts.

* Results: `tools/social.tsv` → `pages/summary.htm`
* Blocked platforms show **Blocked**
* Manual URLs: `tools/social-manual.tsv` (Platform, URL)

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

Main menu option **14** (`misc/cve.sh`).

```
CVE:
CVE-2018-7600
```

* Accepts `CVE-YYYY-NNNN` (normalized to uppercase)
* Opens Firefox tabs for NVD, Rapid7, Tenable, Exploit-DB, GitHub (site search), and CISA KEV search
* Related: Active Top CVE multi-tab opens use `misc/open-cve-tabs.sh` / `discover-cve:` handler

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

Main menu option **17**.

Opens Discover’s notes HTML (`notes/index.htm`) in a browser when available.

---

### Update

Main menu option **18** (`misc/update.sh`).

* Updates the operating system, git pull from various repos, and update the locate database
* Installs tools used by recon and dev scanners (for example `ffuf`, `nuclei`, `droopescan`, `feroxbuster`, `jq`, `trivy`, ProjectDiscovery stack)
* Installs **Nikto** from [sullo/nikto](https://github.com/sullo/nikto) under `/opt/nikto` (wrapper `/usr/local/bin/nikto`); removes the stale apt `2.1.5` package when present
* Patches **droopescan** for modern Python (3.12+) via `misc/patch-droopescan-py314.sh` after pipx install (cement `imp` + setuptools/`distutils`)
* Registers desktop handlers: `discover-scan:`, `discover-cve:`, `discover-ffuf:` (open ffuf finding URLs in Firefox)
* Refreshes the default scanner User-Agent (Microsoft Edge) in `resource/user-agent.txt` for Nikto, Nmap, ffuf, Active, and related tools
* Downloads/refreshes the CISA KEV catalog under `resource/` (Subdomains Shodan **KEV** badges pick up new catalog entries when you **Import report** that engagement)

Main menu option **16. Dev** is documented in the [DEV](#dev) section below.

---

## DEV

Security scanners by [Yiğit ibrahim (ibrahimsql)](https://github.com/ibrahimsql). Reachable from main menu option **16** or by running scripts under `dev/` directly.

Scan results are written under `$HOME/data/` unless noted otherwise. Dev scanners produce **standalone reports** in their own output directories (`api-scan_*`, `cloud-scan_*`, etc.). They source `discover.sh` for menu helpers and colors when needed, but **do not** write to or update Discover’s domain recon HTML report (`$HOME/data/<domain>/pages/*.htm`).

---

### Dev menu

```
Dev scripts originally by ibrahimsql

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

---

### Layout

```
dev/
├── api-scanner.sh
├── cloud-scanner.sh
├── container-scanner.sh
├── oauth-jwt-scanner.sh
├── open-redirect.sh
├── sensitive-scanner.sh
├── waf-detect.sh
├── web-api-scanner.sh
├── data/
│   ├── api-paths.txt
│   ├── openredirect-payloads.txt
│   ├── sensitive-denylist.txt
│   ├── sensitive-patterns.tsv
│   ├── sensitive-skip-paths.txt
│   ├── sensitive-web-paths-quick.txt
│   ├── sensitive-web-paths-full.txt
│   ├── waf-aliases.tsv
│   ├── waf-labels.tsv
│   ├── waf-signatures.tsv
│   ├── web-api-phases.tsv
│   ├── web-api-tech-signatures.tsv
│   └── swagger-paths.txt
└── lib/
    ├── api-scanner/
    │   └── common.sh
    ├── cloud-scanner/
    │   ├── common.sh
    │   ├── aws.sh
    │   ├── azure.sh
    │   └── gcp.sh
    ├── container-scanner/
    │   ├── common.sh
    │   ├── docker.sh
    │   └── k8s.sh
    ├── oauth-jwt-scanner/
    │   ├── common.sh
    │   ├── oauth.sh
    │   └── jwt.sh
    ├── open-redirect-scanner/
    │   ├── common.sh
    │   └── engine.py
    ├── sensitive-scanner/
    │   ├── common.sh
    │   ├── files.sh
    │   ├── web.sh
    │   ├── filescan.py
    │   ├── engine.py
    │   ├── fixtures/
    │   └── run-tests.sh
    ├── waf-detect/
    │   ├── common.sh
    │   ├── probe.sh
    │   ├── fixtures/
    │   └── run-tests.sh
    └── web-api-scanner/
        ├── common.sh
        ├── phases.sh
        ├── waf.sh
        ├── targets.sh
        ├── msf.sh
        ├── msf_parse.py
        ├── probe.sh
        ├── fixtures/
        └── run-tests.sh
```

---

### API Security Scanner

Script: `dev/api-scanner.sh`.

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

* `report.txt` and `report.md` — scanner-local findings (not merged into Discover recon report)
* `findings.json` — consolidated JSON export of all findings
* `findings_registry.tsv` — tab-separated finding log (source for JSON export)
* `scan.log` — request audit trail
* `.checkpoint/` — resume markers per phase

Requires `curl` and `jq`. Uses `ffuf` or `feroxbuster` when installed (install via Discover **Update**). Sources `discover.sh` when run directly for `f_banner` / menu helpers.

---

### Cloud Security Scanner

Script: `dev/cloud-scanner.sh`.

Phased cloud misconfiguration audit for AWS, Azure, and GCP. Shared helpers live in `dev/lib/cloud-scanner/`.

**Interactive menu**

```
1. AWS (Amazon Web Services)
2. Azure (Microsoft Azure)
3. GCP (Google Cloud Platform)
4. All providers
5. Previous menu
```

**CLI** (skips the menu when provider flags are set):

```
./dev/cloud-scanner.sh --aws --quick
./dev/cloud-scanner.sh --azure --gcp --full
./dev/cloud-scanner.sh --aws --output-dir ~/data/cloud-scan_custom
./dev/cloud-scanner.sh --resume ~/data/cloud-scan_20260704-1200 --aws
./dev/cloud-scanner.sh --help
```

| Flag | Purpose |
|------|---------|
| `--aws` / `--azure` / `--gcp` | Run one provider (combine for multiple) |
| `--quick` | Exposure-focused checks (public access, MFA, open ingress) |
| `--full` | Comprehensive audit including IAM deep-dive, multi-region EC2/SG, extras |
| `--output-dir DIR` | Custom output directory |
| `--resume DIR` | Resume using an existing scan directory (skips completed phases) |
| `-h`, `--help` | Show usage |

Results are written under `$HOME/data/cloud-scan_YYYYMMDD-HHMM/` (or `--output-dir`):

* `findings_registry.tsv` — severity, provider, service, resource, check, detail, evidence
* `findings.json` — consolidated JSON export of all findings
* `report.txt` / `report.md` — scanner-local rollup (not merged into Discover recon report)
* `scan.log` — API activity and finding log
* `.checkpoint/` — phase markers for `--resume`

Requires `jq` and the relevant cloud CLI (`aws`, `az`, `gcloud`/`gsutil`) with credentials configured before scanning. The scanner does not auto-install CLIs or run interactive `aws configure` / `gcloud init`. Sources `discover.sh` when run directly for `f_banner` / menu helpers.

---

### Container Security Scanner

Script: `dev/container-scanner.sh`.

Comprehensive Docker and Kubernetes security assessment using Trivy, Docker, and kubectl. Standalone output under `$HOME/data/container-scan_*` (does not update Discover recon HTML reports).

* **Docker images** — Trivy vulnerability/secret/config scan, SBOM (full mode), Dockerfile analysis
* **Docker containers** — privileged mode, mounts, capabilities, runtime checks (full mode)
* **Kubernetes** — RBAC, NetworkPolicies, PSS labels, deprecated APIs, pod security

**Scan types:** `docker-images`, `docker-containers`, `kubernetes`, or `all` (default when run from Discover menu).

**CLI options:** `--quick`, `--full`, `--output-dir`, `--resume`, `--dockerfile-root`, `--include-ns`, `--exclude-ns`, `--trivy-jobs`, `--menu`, `-h`

**Output artifacts:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `scan.log`, `container_security_report.txt`

**Dependencies:** `docker`, `kubectl` (kubernetes scan), `trivy`, `jq`, `numfmt` — install via Discover Update; no auto-install.

**Environment:** `CONTAINER_OUTPUT_DIR`, `CONTAINER_DOCKERFILE_ROOT`, `CONTAINER_SCAN_MODE`, `CONTAINER_EXCLUDE_NS`

---

### OAuth and JWT Security Scanner

Script: `dev/oauth-jwt-scanner.sh`.

OAuth/OIDC discovery, live authorize probes, offline JWT analysis, and optional live token verification. Complements `api-scanner.sh` JWT checks. Standalone output under `$HOME/data/oauth-jwt-scan_*`.

* **OAuth/OIDC** — discovery metadata, JWKS, redirect_uri/state/PKCE/implicit probes
* **JWT offline** — alg=none, RS256→HS256 confusion, jku/x5u/kid attacks, claim hygiene, privilege-escalation payloads
* **JWT live** — optional Bearer tests against `--jwt-endpoint` (auto-filled from userinfo when discovered)

**Scan types:** `oauth`, `jwt`, or `all` (combined).

**Menu:** OAuth test, JWT test, combined scan, or previous menu.

**CLI examples:**
```bash
./dev/oauth-jwt-scanner.sh --target https://app.example.com --full
./dev/oauth-jwt-scanner.sh --jwt 'eyJhbG...' --jwt-endpoint https://app.example.com/api/me
./dev/oauth-jwt-scanner.sh --target https://app.example.com --api-scan-dir ~/data/api-scan_20260101-1200 --all
```

**Options:** `--target`, `--jwt`, `--jwt-file`, `--api-scan-dir`, `--jwt-endpoint`, `--client-id`, `--redirect-uri`, `--quick`, `--full`, `--oauth`, `--jwt-only`, `--all`, `--output-dir`, `--resume`, `--menu`, `-h`

**Output:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `scan.log`

**Dependencies:** `curl`, `jq`

---

### Open Redirect Scanner

Script: `dev/open-redirect.sh`.

Fuzzes redirect parameters (inject + mutate existing query params) with configurable canary hosts. Detects 3xx `Location` (with one-hop follow), meta refresh, and JavaScript/body redirects. Full mode adds POST and header probes. Confirmation pass uses a second canary host to reduce false positives. Python engine: `dev/lib/open-redirect-scanner/engine.py`; payloads: `dev/data/openredirect-payloads.txt`. Standalone output under `$HOME/data/openredirect-scan_*`.

**Menu:** Single URL, domain, URL file, advanced options, prior scan dir, or previous menu.

**CLI examples:**
```bash
./dev/open-redirect.sh --url https://app.example.com/login?next=/home --full
./dev/open-redirect.sh --domain example.com --quick
./dev/open-redirect.sh --scan-dir ~/data/api-scan_20260101-1200 --crawl --quick
./dev/open-redirect.sh --file ~/targets.txt --max-requests 500 --rps 5
```

**Options:** `--url`, `--domain`, `--file`, `--scan-dir`, `--wordlist`, `--canary-host`, `--quick`, `--full`, `--crawl`, `--workers`, `--delay`, `--rps`, `--max-requests`, `--no-confirm`, `--quiet`, `--output-dir`, `--resume`, `--menu`, `-h`

**Output:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `scan.log`, `openredirect_engine/results.json`, `openredirect_engine/checkpoint.json`

**Dependencies:** `python3`, `requests` (Discover Update installs `python3-requests`), `jq`

---

### Sensitive Information Scanner

Script: `dev/sensitive-scanner.sh`.

Hunts for secrets, credentials, and PII in local files/directories and exposed web paths. Bash orchestration plus Python engines: `filescan.py` (single-pass file scan) and `engine.py` (parallel web probing). Pattern data: `dev/data/sensitive-patterns.tsv`, `sensitive-denylist.txt`, `sensitive-skip-paths.txt`. Standalone output under `$HOME/data/sensitive-scan_*`.

* **File scan** — one pass per file via `filescan.py`; denylist, skip globs, entropy filter, Luhn/SSN/TC validation; optional `gitleaks` / `trufflehog` (`--external auto`)
* **Web scan** — parallel workers/RPS, per-path checkpoint resume, robots disallow + sitemap paths, api-scanner endpoint import, soft-404 guard, directory listing detection, deep `filescan.py` on HTTP 200 bodies
* **api-scanner hook** — inline response checks use `filescan.py`; orchestrator can auto-launch `--all` with bearer token
* **Reports** — deduplicated `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`; `--no-store-content` / `--shred-content` for safer artifacts

**Menu:** File or folder, URL, file/folder + prior scan dir, URL + api-scan output, or previous menu.

**Examples:**

```
./dev/sensitive-scanner.sh --path ./myapp --files --full
./dev/sensitive-scanner.sh --url https://app.example.com --web --quick --workers 8 --rps 5
./dev/sensitive-scanner.sh --url https://app.example.com --scan-dir ~/data/api-scan_20260101-1200 --all --quick --bearer-token "$TOKEN"
./dev/sensitive-scanner.sh --path /var/www/html/config.php --files --external gitleaks
./dev/lib/sensitive-scanner/run-tests.sh
```

**Options:** `--path`, `--url`, `--scan-dir`, `--wordlist`, `--quick`, `--full`, `--workers`, `--delay`, `--rps`, `--max-paths`, `--bearer-token`, `--insecure`, `--no-store-content`, `--shred-content`, `--redact-emails`, `--entropy-min`, `--external`, `--files`, `--web`, `--all`, `--output-dir`, `--resume`, `--quiet`, `--menu`, `-h`

**Output:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `scan.log`, `sensitive_info/`, `web_sensitive/engine/{results,checkpoint}.json`

**Dependencies:** `python3`, `jq`, `find`; web scans need `python3-requests`; optional `gitleaks`, `trufflehog`, `rg`

---

### WAF Detection

Script: `dev/waf-detect.sh`.

Identifies web application firewalls and CDN edge layers in front of targets. Modular library: `dev/lib/waf-detect/{common,probe}.sh`, `wafw00f_run.py`; data: `dev/data/waf-signatures.tsv`, `waf-aliases.tsv`, `waf-labels.tsv`. Standalone output under `$HOME/data/waf-detection_*`.

* **True passive (default for api-scanner hook)** — `--passive` sends a normal HTTP GET only; matches response headers/body against `waf-signatures.tsv`. No wafw00f, no SQLi triggers, no `X-Forwarded-For` injection.
* **Active mode** — wafw00f via `wafw00f_run.py` (primary, high confidence) plus supplemental signature/behavioral probes. Non-interactive active scans require `--i-understand`.
* **Supplemental** — `--supplemental auto` skips redundant probes after a confident wafw00f hit; behavioral findings require WAF header corroboration
* **Consolidated findings** — one row per vendor with confidence (`high`/`medium`/`low`), source, and type (`waf`/`cdn`/`both`)
* **Structured hits** — `waf_engine/hits.jsonl` and `findings.json` `hits[]` for downstream tooling
* **Resume** — `--resume DIR` continues from `waf_engine/checkpoint.json`
* **Reports** — `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `waf_results.tsv`

**Menu:** Single target, targets file, or previous menu (with active/passive choice).

**Examples:**

```
./dev/waf-detect.sh --url https://app.example.com --passive
./dev/waf-detect.sh --file ~/targets.txt --passive --delay 2
./dev/waf-detect.sh --url example.com --i-understand --output-dir ~/data/waf-test
./dev/waf-detect.sh --resume ~/data/waf-detection_20260704-1200 --workers 4
./dev/lib/waf-detect/run-tests.sh
```

**Options:** `--url`, `--file`, `--output-dir`, `--resume`, `--passive`, `--i-understand`, `--waf-only`, `--insecure`, `--no-redirect`, `--proxy`, `--delay`, `--max-targets`, `--workers`, `--wafw00f`, `--supplemental`, `--input-format`, `--quiet`, `--menu`, `-h`

**Output:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `waf_results.tsv`, `scan.log`, `waf_engine/{hits.jsonl,checkpoint.json,*.json}`

**Dependencies:** `curl`, `jq`, `grep`, `python3`; optional `wafw00f` (active mode, recommended)

**api-scanner integration:** `api-scanner.sh --orchestrate` prompts to run waf-detect after the main scan (passive by default).

---

### Web and API Security

Script: `dev/web-api-scanner.sh`.

Metasploit-based web/API assessment. Modular library: `dev/lib/web-api-scanner/{common,phases,msf,probe,waf,targets}.sh`, `msf_parse.py`; data: `dev/data/web-api-{phases,tech-signatures}.tsv`. Standalone output under `$HOME/data/web-api-scan_*`.

* **Tiers** — `passive` (recon) | `standard`/`--quick` (recon + tech scanners) | `intrusive` (+ SQLi/brute) | `exploit` (+ exploit checks)
* **Phase control** — `--phases`, `--skip-phases`; per-phase `msfconsole` with `--phase-timeout`
* **Technology fingerprint** — weighted `web-api-tech-signatures.tsv` (Laravel, Spring, Swagger, nginx, …)
* **WAF-aware** — skips brute phases when WAF/CDN detected (`--scan-dir` or header signatures)
* **Auth** — `--bearer-token`, `--cookie-file` for curl + MSF
* **api-scanner integration** — `--scan-dir` loads `api_scanner/all_endpoints.txt` for `brute_dirs` paths
* **Structured hits** — `msf_parse.py` → `msf_engine/hits.jsonl` + `findings.json` `hits[]`
* **Multi-target** — `--file`, `--workers`, `--max-targets`
* **Stealth** — `--delay`, `--jitter`, `--proxy`, tier-based `THREADS`
* **MSF DB** — checks only by default; `--msf-db-bootstrap` for opt-in setup

**Menu:** Scan URL (passive default) or previous menu.

**Examples:**

```
./dev/web-api-scanner.sh --url https://app.example.com --passive
./dev/web-api-scanner.sh --url example.com --quick --scan-dir ~/data/api-scan_*/ 
./dev/web-api-scanner.sh --url example.com --tier exploit --i-understand --bearer-token "$TOKEN"
./dev/web-api-scanner.sh --file ~/targets.txt --quick --workers 2 --max-targets 10
WEBAPI_RUN_LIVE_MSF=1 ./dev/lib/web-api-scanner/run-tests.sh
```

**Options:** `--url`, `--file`, `--tier`, `--quick`, `--phases`, `--skip-phases`, `--scan-dir`, `--bearer-token`, `--cookie-file`, `--proxy`, `--phase-timeout`, `--workers`, `--threads`, `--jitter`, `--target-ip`, `--output-dir`, `--resume`, `--passive`, `--i-understand`, `--dry-run`, `--skip-msf-db`, `--msf-db-bootstrap`, `--keep-resources`, `--no-waf-aware`, `--insecure`, `--delay`, `--quiet`, `--menu`, `-h`

**Output:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `scan.log`, `msf_engine/`

**Dependencies:** `curl`, `jq`, `grep`, `msfconsole`; PostgreSQL recommended for MSF DB (optional with `--skip-msf-db`)

**api-scanner integration:** `api-scanner.sh --orchestrate` prompts to run web-api-scanner (passive by default).
