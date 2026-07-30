# Discover agent notes

Conventions agreed with the operator for Discover development. **Read and follow this file.** When we discuss and agree on a durable rule (layout, install order, Update UX, host-scan gating, etc.), **add or update it here** in the same change set when practical—do not leave it only in chat history.

## Writing (operator-facing text)

- **Never use three periods in a row (`...`) at the end of a sentence.** End with a single period (`.`).
- Same for Unicode ellipsis (`…`) in operator-facing text (logs, UI status lines, scan `output.txt`, help copy): use a single `.` when finishing a sentence. Do not write “Running…”, “Updating…”, or “pre-check (15s)…”.
- Mid-list “and more” truncation in docs/comments is fine when not sentence-final (e.g. `2xx,301,302,...` as a list tail). Prefer plain ASCII over fancy punctuation in plain-text scan logs.

## Git commits

- **Only commit when the operator explicitly asks** (e.g. “do a commit”). Do not commit proactively after finishing a feature or when they only ask whether a commit is needed.

## `old/` folder

- **`old/` is not part of the Discover framework.** It holds personal/legacy scripts from earlier work that are unrelated to Discover’s recon/scan/report flow.
- Do **not** put new Discover features, helpers, or data files under `old/`.
- Live subdomain categorizer + rules live under **`recon/`** (`recon/subdomain-categorize.py`, `recon/subdomain-categories.tsv`). Do not reintroduce Discover paths that point at `old/`.

## Operator name (audit log)

- First name only, max 10 letters only, stored at `~/.discover/operator-name`.
- Prompted once when Discover starts if missing/invalid (`f_ensure_operator_name` in `discover.sh`).
- Audit lines: `mm-dd-yyyy - hh:mm Z | <name> | <egress IP> | <action>` (`f_audit_log` / host-scan `f_audit`). Legacy stamps (`mm-dd-yyyy Z - hh:mm`) and 3-field lines still parse on the Audit page.
- **Shodan**, **Updated software CVE data**, **Imported subdomains** / **Imported CSV list subdomains**, and **Imported operator package**: Operator IP is always a dash (`-` in the log, `—` on the Audit page). Do not record egress IP for those events.

## Report homepage date (`index.htm`)

- Home hero date (`#DATE#` / first `inc-home-meta` value) is format `Month DD, YYYY` (same as Discover `DATESTAMP`).
- **Update to today** whenever the engagement changes: Passive finish, Active, host-scan finish, Shodan enrich/Update, software CVE refresh, subdomain/names imports, operator package import.
- Helper: `recon/touch-report-date.py <report_dir>` (also callable from Python via `touch_report_index_date`).

## Import operator package (Audit page)

- **Import** button on Audit only when Discover-hosted (`http://127.0.0.1:17322/…`). Modal: path to **unpacked** other-operator report + their first name (1–10 letters).
- Backend: statusd `POST /import-operator-package` → `recon/import-operator-package.py --dest <live> --source <path> --operator <Name> --json`.
- Merges `tools/host-scans` (copy missing run dirs), gowitness screenshots/jsonl, httpx/whatweb (by host), new `tools/subdomains` hosts, audit lines for that operator name. Rebuilds Audit (and Active when Active data merged). Never copies their `pages/*.htm` over the live tree.
- Assets: `inc-audit-import.js`; bust `?v=` / `modern.css` on Audit after UI changes; import-report injects the script on `audit.htm`.

## Report UI layout (CSS)

When designing or tweaking **report page layouts** (especially Audit and other `modern.css` tables/containers):

- Prefer **`px`** for widths, min/max-widths, padding, and gaps you are dialing in with the operator.
- **Do not use `rem` for layout sizing.** Bootstrap sets `html { font-size: 10px }`, so `1rem = 10px` (not 16px). That made earlier “rem” floors look far too narrow.
- `%` / `width: 1%` + `nowrap` is fine for shrink-to-content columns; once a column needs a **fixed** size, use **px**.
- Bust `modern.css?v=…` on the affected page after CSS changes and deploy to the live engagement report when applicable.

## `misc/update.sh` tool install order

Tool install/update blocks in **`misc/update.sh` must stay in case-insensitive alphabetical order** by tool/display name (e.g. DomainPasswordSpray → droopescan → Egress-Assess → … → WhatWeb → Windows Exploit Suggester → **wpscan** → xdotool).

- Do **not** group by feature (e.g. “CMS tools together”). Place new tools where the alphabet says, not next to a related tool.
- Comments already mark some blocks this way (e.g. CISA KEV after chromium, before curl); follow that convention.
- Same idea for README Update bullet lists when they mirror install order.

## Host-scan reachability pre-check (expand dropdown only)

- Applies only to tools launched from the Subdomains expand panel: **nuclei**, **nikto**, **ffuf**, plus **droopescan** / **wpscan** when shown.
- Before the tool runs, `run-host-scan.sh` does a **curl HTTP/1.1 GET** (15s max, same UA as the tool).
- If no HTTP response (`000` / timeout): **do not launch the tool**. Write skip note in that run’s `output.txt`, set `meta.skip_reason=host_unreachable` and the same on `status.json` / `latest.json`, exit 1.
- Expand panel shows **Unreachable** (red) under that tool box (plus txt link when present).
- **Nikto HTM** is omitted when `skip_reason=host_unreachable` (no HTML report was written).
- Nikto has no second internal pre-check (shared gate only).
- Help modals (ⓘ) and README host-scan section document this gate.

## Host-scan expand (Subdomains)

- Host-scan chevrons appear **only** when the report is opened via Discover statusd HTTP (`http://127.0.0.1:17322/…`, Import report / Active). Manual `file://` open never shows chevrons, even if statusd is still running.
- Chevrons on the **full** public Subdomains table (rows with HTTP status), not only `?software=` / `?cve=` filtered views.
- **Software for expand:** `?software=` query wins; else fingerprint the row (Technologies tokens with version when present, title, web server, hostname label). Priority products include CMS, Kibana, Grafana, Elasticsearch, Jenkins, Tomcat, IIS, nginx, Apache, PHP, Node.js.
- **nuclei only when a product is known** (filter or fingerprint). Do not offer nuclei for blind `-tags tech` with empty software. Backend `run-host-scan.sh` refuses nuclei when SOFTWARE is empty.
- **nikto** / **ffuf** always on expand when the UI is shown.
- **droopescan** / **wpscan** gate on CMS software (query or fingerprint). **WordPress → wpscan only** (no droopescan for WP). Drupal / Joomla / Moodle / Silverstripe still use droopescan when matched.
- Each tool box has a Unicode ⓘ help modal. Bust `inc-host-scan.js?v=…` (and `modern.css?v=…` on Subdomains) after changes and sync via Import when testing live reports.

## Shodan panel Update (Subdomains)

- Shodan ▸ expand panel shows an **Update** button **only** on Discover-hosted pages (`http://127.0.0.1:17322/…`). Manual `file://` never shows it.
- Backend: statusd `POST /shodan-refresh` → `recon/shodan-enrich.py <report> --ip <IP> --json` (force host API lookup; rewrites that host cache + index; audit log line).
- Requires `SHODAN_API_KEY` from shell or **`~/.discover/api-keys`**. Bust `inc-shodan.js?v=…` / `modern.css?v=…` after UI changes; restart statusd (Import report) so the new endpoint is live.
- Opening the panel on statusd calls `GET /shodan-status` (`api_key` true/false only). If false, show where to add the key (`~/.discover/api-keys`) and disable **Update**.

## API keys

- Preferred file: **`~/.discover/api-keys`** (`KEY=value` lines; `chmod 600`). Template: `resource/api-keys.example`.
- Keys: `NVD_API_KEY`, `SHODAN_API_KEY`, **`WPSCAN_API_TOKEN`** (optional free token for wpscan vuln DB; `run-host-scan.sh` loads api-keys and passes `--api-token`).
- Lookup order: shell export → `~/.discover/api-keys` (first non-empty wins per key).
- **Update:** `misc/update.sh` ensures the file exists — if missing, copies `resource/api-keys.example` → `~/.discover/api-keys` (`chmod 600`). Under `sudo`, seeds the **invoking user’s** home (`SUDO_USER`), not only root. If already present, only re-applies `chmod 600` (quiet).
- **Auto-migrate:** if `$DISCOVER/.env` or `~/.discover/.env` still exist, Discover merges them into `~/.discover/api-keys` (existing `api-keys` values win) and **removes** the legacy files. Implemented in `software-cve.migrate_legacy_api_key_files()` (also run from Active / Shodan shell loaders).

## Report Export (Passive / Active / Audit)

- **No Domain menu item** for export. UI is an **Export** button at the top of Report → Passive / Active / Audit only when the page is Discover-hosted (`http://127.0.0.1:17322/…`). Manual `file://` never shows the button.
- Modal: Client / Defender / Operator radios + **Export** + **Cancel**; success shows the output path (`$HOME/data` by default).
- Backend: statusd `POST /export` → `recon/export-report.sh --kind … --report … --out-dir … --quiet` (JSON path on stdout).
- Assets: `inc-report-export.js`, `modern.css` (export classes); import-report syncs JS and injects the script on those three pages. Bust `inc-report-export.js?v=…` / `modern.css?v=export…` after changes.

## Import subdomains (Domain menu 8)

- Two choices: **(1)** existing Firefox/Pentest-Tools/TSV **(2)** CSV list (`subdomain,ip,category`).
- CSV list: one IPv4 per host (empty IP → dig). **Skip hosts already in `tools/subdomains`** (no overwrite). Category = **Discover rules first**, else CSV. Never write `recon/subdomain-categories.tsv`.
- After import: refresh `pages/subdomains.htm` and `pages/hosts.htm` (unique public IPs). CSV list also writes `tools/import-batch-hosts.txt` (**new** public hosts only) and may offer Active on that batch only (`DISCOVER_ACTIVE_SCOPE=import-batch`).
- **After import + Active (full or import-batch):** rebuild the **entire** Active page from merged `tools/` artifacts — Scope (public/private/responding), status codes, alive-by-category, CMS, web servers, technologies, software versions + CVE enrichment, and scan date. Batch Active must merge httpx/whatweb/gowitness into the engagement files first, then call the same full `pages/active.htm` rebuild (not a batch-only summary). Scan date = **latest** httpx timestamp, not the first line.

## Active page Update (Shodan + Software CVEs)

- **Update** button on Active (statusd only), left of Export. Modal checkboxes (default both on):
  - **Shodan** → `POST /shodan-refresh-all` → `shodan-enrich.py <report> --force --json-summary`
  - **Software CVEs** → `POST /software-cve-refresh` → `active-tech.py <report> --refresh-cves --json` (re-queries NVD for missing/empty cache entries by default; `--force-all` optional; rebuilds `pages/active.htm` Software versions table + `cve-software-index.js`)
- Software versions CVE data is **NVD CPE**, not Shodan host vulns. Permanent skips: Microsoft HTTPAPI, Java Servlet, JavaServer Pages (`SKIP_PRODUCTS` in `software-cve.py`).
- Assets: `inc-active-refresh.js`; bust `?v=` and `modern.css` after UI changes. Restart statusd after endpoint changes.
