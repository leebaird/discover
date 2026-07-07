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

8.  Active
9.  Previous menu
```

Note: Passive and Active cannot be ran as root.

PASSIVE RECON

Uses Amass, ARIN, DNSRecon, dnstwist, Metasploit, subfinder,
sublist3r, theHarvester, Whois, and multiple websites.

* Acquire all free API keys for maximum results with theHarvester.
* Add API keys to $HOME/.theHarvester/api-keys.yaml
* Passive builds an HTML report at $HOME/data/<domain>/.
* Find registered domains updates pages/registered-domains.htm in an existing report.
* Active uses httpx, whatweb, and gowitness.

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
`old/subdomain-categories.tsv`, splits private IPs to `tools/private-subs`, and
refreshes `pages/subdomains.htm` (Subdomain, Category, IP columns).

#### Active (`active.sh`)

ACTIVE RECON

Run after a passive scan (and optionally Import subdomains) when you want to probe
which public hosts respond over HTTP/HTTPS and capture screenshots.

```
Enter the location of your previous passive scan:
/home/user/data/example.com
```

Requires `httpx`, `whatweb`, `gowitness`, and Chrome or Chromium (install via **Update**).

* Reads public hostnames from `tools/subdomains` (RFC1918 IPs are skipped)
* Probes hostnames with httpx; writes `tools/httpx.jsonl`
* Marks hosts **Alive** on the public subdomains table when httpx returns status
  200–399, 401, 403, or 405; private subdomains table stays three columns
* Fingerprints alive URLs with whatweb; writes `tools/whatweb.json`
* Screenshots alive URLs with gowitness under `tools/gowitness/`
* Re-run Active to replace httpx/whatweb/gowitness artifacts and rebuild the Alive column

Artifacts written under `tools/`:

* `active-targets.txt` — public hostnames sent to httpx
* `httpx.jsonl` — httpx JSON output
* `active-alive.tsv` — host, URL, and status for alive responses
* `active.txt` — alive URLs sent to whatweb and gowitness
* `whatweb.json` — whatweb JSON output
* `gowitness/screenshots/` — JPEG screenshots
* `gowitness/gowitness.jsonl` and `gowitness/gowitness.db` — gowitness metadata

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

Scan results are written under `$HOME/data/` unless noted otherwise. Dev scanners produce **standalone reports** in their own output directories (`api-scan_*`, `cloud-scan_*`, etc.). They source `discover.sh` for menu helpers and colors when needed, but **do not** write to or update Discover's recon HTML report (`report.sh`, `$NAME`, `pages/*.htm`).

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

* `report.txt` and `report.md` — scanner-local findings (not merged into Discover recon report)
* `findings.json` — consolidated JSON export of all findings
* `findings_registry.tsv` — tab-separated finding log (source for JSON export)
* `scan.log` — request audit trail
* `.checkpoint/` — resume markers per phase

Requires `curl` and `jq`. Uses `ffuf` or `feroxbuster` when installed (install via Discover **Update**). Sources `discover.sh` when run directly for `f_banner` / menu helpers.

### Cloud Security Scanner (`dev/cloud-scanner.sh`)

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

### Container Security Scanner (`dev/container-scanner.sh`)

Comprehensive Docker and Kubernetes security assessment using Trivy, Docker, and kubectl. Standalone output under `$HOME/data/container-scan_*` (does not update Discover recon HTML reports).

* **Docker images** — Trivy vulnerability/secret/config scan, SBOM (full mode), Dockerfile analysis
* **Docker containers** — privileged mode, mounts, capabilities, runtime checks (full mode)
* **Kubernetes** — RBAC, NetworkPolicies, PSS labels, deprecated APIs, pod security

**Scan types:** `docker-images`, `docker-containers`, `kubernetes`, or `all` (default when run from Discover menu).

**CLI options:** `--quick`, `--full`, `--output-dir`, `--resume`, `--dockerfile-root`, `--include-ns`, `--exclude-ns`, `--trivy-jobs`, `--menu`, `-h`

**Output artifacts:** `findings_registry.tsv`, `findings.json`, `report.txt`, `report.md`, `scan.log`, `container_security_report.txt`

**Dependencies:** `docker`, `kubectl` (kubernetes scan), `trivy`, `jq`, `numfmt` — install via Discover Update; no auto-install.

**Environment:** `CONTAINER_OUTPUT_DIR`, `CONTAINER_DOCKERFILE_ROOT`, `CONTAINER_SCAN_MODE`, `CONTAINER_EXCLUDE_NS`

### OAuth and JWT Security Scanner (`dev/oauth-jwt-scanner.sh`)

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

### Open Redirect Scanner (`dev/open-redirect.sh`)

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

### Sensitive Information Scanner (`dev/sensitive-scanner.sh`)

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

### WAF Detection (`dev/waf-detect.sh`)

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

### Web and API Security (`dev/web-api-scanner.sh`)

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
