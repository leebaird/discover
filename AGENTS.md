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
- Audit lines: `mm/dd/yyyy - hh:mm Z | <name> | <egress IP> | <action>` (`f_audit_log` / host-scan `f_audit`). Dash-date stamps (`mm-dd-yyyy - hh:mm Z`), legacy (`mm-dd-yyyy Z - hh:mm`), and 3-field lines still parse on the Audit page.
- **Shodan**, **Updated software CVE data**, **Imported subdomains** / **Imported CSV list subdomains**, **Imported names** (incl. titles/emails), and **Imported operator package**: Operator IP is always a dash (`-` in the log, `—` on the Audit page). Do not record egress IP for those events.

## Timestamps (UTC write, view timezone)

- **Always record timestamps in UTC** when a scan runs or any engagement event is written (audit log, host-scan meta `started`/`finished` / `*_utc`, status stamps, export `exported_at_utc`, etc.). Human stamps are `mm/dd/yyyy - hh:mm Z`; ISO fields stay `YYYY-MM-DDTHH:MM:SSZ`.
- Operators may **choose a timezone for viewing** (e.g. Audit Config → Time zone). That preference is **display only** for Audit/metrics.
- **View timezone must not change how data is written** — no local-time stamps in `tools/audit/log.txt`, meta.json, or other on-disk artifacts. Convert only when rendering the report UI (and label the column, e.g. Time (UTC) vs local).
- **Export filename** is the exception: `YYYYMMDD-HHMM` in `domain-kind-YYYYMMDD-HHMM.zip` (or `.csv`) uses the operator view timezone (`~/.discover/timezone`). Ledger `exported_at_utc` and the audit line stay UTC.
- Preference store: `~/.discover/timezone` (not inside a single engagement report), so it applies across engagements for that operator machine. UI: Audit **Config → Time zone**.

## Report homepage date (`index.htm`)

- Home hero date (`#DATE#` / first `inc-home-meta` value) is format `Month DD, YYYY` (same as Discover `DATESTAMP`).
- **Update to today** whenever the engagement changes: Passive finish, Active, host-scan finish, Shodan enrich/Update, software CVE refresh, subdomain/names imports, operator package import.
- Helper: `recon/touch-report-date.py <report_dir>` (also callable from Python via `touch_report_index_date`).

## Import hub (Audit page)

- **Import** button on Audit only when Discover-hosted (`http://127.0.0.1:17322/…`). Label stays **Import**. Always targets the **current** engagement (statusd `report_root`); no report path in the UI.
- Hub choice rows: **Operator scans** · **Names** · **Names, titles, and emails** · **Subdomains**.
- **Operator scans:** path to **unpacked** other-operator report + their first name (1–10 letters). Backend: `POST /import-operator-package` → `recon/import-operator-package.py --dest <live> --source <path> --operator <Name> --json`. Merges host-scans, gowitness, httpx/whatweb, new subdomains, audit lines for that name. Never copies their `pages/*.htm` over the live tree.
- **Names:** optional manual TSV path (default `tools/names-manual.tsv` in the live report). `POST /import-names` → `recon/import-names.sh --report <live> [--manual …] --json`.
- **Names, titles, and emails:** source file path. `POST /import-names-titles-emails` → `import-names-titles-emails.sh --report <live> --source … --json`.
- **Subdomains:** mode `existing` | `team-csv`, import path (`firefox` allowed), optional `run_active` for CSV new public hosts. `POST /import-subdomains` → `import-subdomains.sh --report … --mode … --import … [--run-active] --json`.
- Domain menu no longer lists import items 6–8; menu is **6 Active · 7 Open report · 8 Previous**. Scripts remain for CLI.
- Assets: `inc-audit-import.js`; bust `?v=` / `modern.css` on Audit after UI changes; import-report injects the script on `audit.htm`. Restart statusd after endpoint changes.

## Audit log operator filter

- Client-side dropdown next to **Audit log** heading: **All operators** + each unique name from the table.
- Rows use `data-audit-operator` (from `audit-build.py`). Optional URL `?operator=Name` (case-insensitive; updates via `history.replaceState`).
- Works on statusd and `file://`. Asset: `inc-audit-log-filter.js`; bust `?v=` / `modern.css` on Audit after UI changes.

## Audit log line delete

- **Delete** on each Audit log row only when Discover-hosted (`http://127.0.0.1:17322/…`). Manual `file://` never shows it.
- Confirm modal: **`<Operator>, are you sure you want to delete this line?`** (operator from `~/.discover/operator-name` / GET `/config`) plus a short line preview. **Cancel** / **Delete**.
- Backend: statusd `POST /audit-line-delete` → `audit-build.py --delete-line <sha256> <report> --json`. Removes **one** matching line from `tools/audit/log.txt` (hash of stripped raw line), rebuilds `pages/audit.htm` (metrics + log).
- Row markup: `data-audit-hash` / `data-audit-preview` on each log `<tr>` from `audit-build.py`. Assets: `inc-audit-line-delete.js`; bust `?v=` / `modern.css` on Audit; import-report injects the script. Restart statusd after endpoint changes.

## Audit last-7-days metrics (Option A strip)


- Shown **above the Audit log** on `pages/audit.htm` (all report modes; built by `audit-build.py`).
- Range dropdown (aligned with **By CVE** / **Targets scanned**): **Today** · **Yesterday** · **Last 7 days** (default) · **Last week** · **All**. Asset: `inc-audit-metrics-range.js`.
  - Calendar windows use the operator **view timezone** (`~/.discover/timezone`). Audit stamps stay UTC on disk.
  - **Today:** current calendar day in the view timezone (start = today 00:00).
  - **Yesterday:** previous calendar day in the view timezone (yesterday 00:00 through today 00:00).
  - **Last 7 days:** last 7 calendar days inclusive of today in the view timezone (start = today−6 00:00).
  - **Last week:** previous full calendar week in the view timezone (Monday 00:00 through this Monday 00:00).
  - **All:** no date filter (Scans per day chart capped at newest 60 calendar days of activity).
- **KPI cards** (compact row, centered): **Targets scanned**, **Scans completed**; **Incomplete scans** only when count > 0 (then three cards; otherwise two cards centered).
- **Charts layout (top → bottom):** KPI row; **By CVE** | **By software** (2 equal boxes); **By tool** | **By category** (2 equal boxes); **Scans per day** (full width of two-box row); **By operator** (full width of two-box row). Horizontal bar charts show **top 10** entries each.
- Data: host-scan **Finished** / **Started** lines in `tools/audit/log.txt`; software from `(software: …)` on Finished lines; CVEs from nuclei pass-2 `meta.pass2.ids` (canonical `CVE-YYYY-NNNN` only) for runs finished in the window; category from `tools/subdomains` / `tools/private-subs` host→category lookup (empty → `(none)`).
- Incomplete: **Started** in the selected window with no **Finished** for the same tool+host at/after that start (Finished may be outside the window — e.g. started last week, finished this week is complete for Last week).
- Rebuild with Audit (host-scan finish, Open report, Config name rewrite, etc.). Bust `modern.css?v=` on Audit after CSS changes.

## Config (Audit page only)

- **Config** button on Audit only when Discover-hosted (`http://127.0.0.1:17322/…`). Header order: **Config** · **Import** · **Export**.
- Modal hub with **three choice rows**: **APIs**, **Operator name**, **Time zone**.
- Backend: `recon/discover-config.py` via statusd `GET /config`, `POST /config/api-keys`, `POST /config/operator-name`, `POST /config/timezone`.
- **APIs:** show/edit/save `NVD_API_KEY`, `SHODAN_API_KEY`, `WPSCAN_API_TOKEN` in `~/.discover/api-keys` (chmod 600). Localhost only. **theHarvester** is a link (not a field) that opens `~/.theHarvester/api-keys.yaml` via statusd `POST /config/open-theharvester` or `discover-theharvester:` → `misc/open-theharvester-keys.sh` (`open`, else `xdg-open`). If that file is missing, copy `~/theHarvester/theHarvester/data/api-keys.yaml` into place (do not overwrite an existing file). Do not store theHarvester keys in Discover `api-keys`.
- **theHarvester sources:** `recon/passive.sh` `sources_no_api` / `sources_api` must stay in lockstep with `old/test-theHarvester.sh`. Cover every name in `~/theHarvester` `SOURCE_SPECS`. Split by theHarvester README **API key** column: **No** → `sources_no_api`; **Required** or **Optional** → `sources_api`. Domain menu 98 = free list, 99 = API list. After a theHarvester update, run option 99 leftover check (`old/newModules.sh`) and add any new engines to the matching list.
- **Operator name:** read/write `~/.discover/operator-name` (1–10 letters). On change, rewrite **only audit lines whose Operator field matches the previous name** (other operators’ lines untouched; do not rewrite names inside Action text). Rebuild Audit after rewrite.
- **Time zone:** display preference (`~/.discover/timezone`). UTC + US zones. **Does not change written stamps** (always UTC). Audit Time column converts in the browser. Metrics **Today** / **Yesterday** / **Last 7 days** / **Last week** use this timezone when Audit is built. Saving it rebuilds Audit.
- Assets: `inc-audit-config.js`; bust `?v=` / `modern.css` on Audit after UI changes; import-report injects the script on `audit.htm`. Restart statusd after endpoint changes.

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

- Applies only to tools launched from the Subdomains expand panel: **nuclei**, **robots**, **nikto**, **ffuf**, **feroxbuster**, plus **droopescan** / **wpscan** when shown.
- Before the tool runs, `run-host-scan.sh` does a **curl HTTP/1.1 GET** (15s max, same UA as the tool).
- If no HTTP response (`000` / timeout): **do not launch the tool**. Write skip note in that run’s `output.txt`, set `meta.skip_reason=host_unreachable` and the same on `status.json` / `latest.json`, exit 1.
- Expand panel shows **Unreachable** (red) under that tool box (plus txt link when present).
- **Nikto HTM** and **robots HTM** are omitted when `skip_reason=host_unreachable` (no report / no Disallow list).
- Nikto has no second internal pre-check (shared gate only).
- Help modals (ⓘ) and README host-scan section document this gate.

## Host-scan expand (Subdomains)

- Host-scan chevrons appear **only** when the report is opened via Discover statusd HTTP (`http://127.0.0.1:17322/…`, Open report / Active). Manual `file://` open never shows chevrons, even if statusd is still running.
- Chevrons on the **full** public Subdomains table (rows with HTTP status), not only `?software=` / `?cve=` filtered views.
- **Software for expand:** `?software=` query wins; else fingerprint the row (Technologies tokens with version when present, title, web server, hostname label). Priority products include CMS, Kibana, Grafana, Elasticsearch, Jenkins, Tomcat, IIS, nginx, Apache, PHP, Node.js.
- **nuclei only when a product is known** (filter or fingerprint). Do not offer nuclei for blind `-tags tech` with empty software. Backend `run-host-scan.sh` refuses nuclei when SOFTWARE is empty.
- **robots** / **nikto** / **feroxbuster** / **ffuf** always on expand when the UI is shown. Order: **robots** → nuclei (if product) → CMS tools → nikto → feroxbuster → ffuf.
- **robots:** fetch `/robots.txt` (same idea as multiTabs → Directories in robots.txt). **txt** = raw `robots.txt` body; **htm** = open Disallow directories in Firefox via `discover-robots:` → `misc/open-robots-tabs.sh` (only when `disallow_count` > 0). Run does not open Firefox.
- **ffuf / feroxbuster url:** green **url** (Firefox tabs) only when the run has at least one finding URL. Auto-filter-only / empty JSON → **txt** only. Count stored as `meta.url_count`.
- **droopescan** / **wpscan** gate on CMS software (query or fingerprint). **WordPress → wpscan only** (no droopescan for WP). Drupal / Joomla / Moodle / Silverstripe still use droopescan when matched.
- Each tool box has a Unicode ⓘ help modal. Finished stamps use the Config **Time zone** (same display conversion as Audit; on-disk stamps stay UTC). Bust `inc-host-scan.js?v=…` (and `modern.css?v=…` on Subdomains) after changes and sync via Import when testing live reports.

## Shodan panel Update (Subdomains)

- Shodan ▸ expand panel shows an **Update** button **only** on Discover-hosted pages (`http://127.0.0.1:17322/…`). Manual `file://` never shows it.
- Backend: statusd `POST /shodan-refresh` → `recon/shodan-enrich.py <report> --ip <IP> --json` (force host API lookup; rewrites that host cache + index; audit log line).
- Requires `SHODAN_API_KEY` from shell or **`~/.discover/api-keys`**. Bust `inc-shodan.js?v=…` / `modern.css?v=…` after UI changes; restart statusd (Open report) so the new endpoint is live.
- Opening the panel on statusd calls `GET /shodan-status` (`api_key` true/false only). If false, show where to add the key (`~/.discover/api-keys`) and disable **Update**.

## API keys

- Preferred file: **`~/.discover/api-keys`** (`KEY=value` lines; `chmod 600`). Template: `resource/api-keys.example`.
- Keys: `NVD_API_KEY`, `SHODAN_API_KEY`, **`WPSCAN_API_TOKEN`** (optional free token for wpscan vuln DB; `run-host-scan.sh` loads api-keys and passes `--api-token`).
- Lookup order: shell export → `~/.discover/api-keys` (first non-empty wins per key).
- **Update:** `misc/update.sh` ensures the file exists — if missing, copies `resource/api-keys.example` → `~/.discover/api-keys` (`chmod 600`). Under `sudo`, seeds the **invoking user’s** home (`SUDO_USER`), not only root. If already present, only re-applies `chmod 600` (quiet).
- **Auto-migrate:** if `$DISCOVER/.env` or `~/.discover/.env` still exist, Discover merges them into `~/.discover/api-keys` (existing `api-keys` values win) and **removes** the legacy files. Implemented in `software-cve.migrate_legacy_api_key_files()` (also run from Active / Shodan shell loaders).
- **Agent / automation must never destroy live secrets:**
  - Do **not** run `discover-config.py set-api-keys`, statusd `POST /config/api-keys`, or any write to `~/.discover/api-keys` (or legacy `.env` key files) with dummy/test values.
  - Do **not** “verify” save paths against the operator’s real key file. Use a temp file, dry logic, or read-only checks.
  - Do **not** clear, overwrite, or restore keys unless the operator **explicitly** asks to save or change a specific key.
  - Tests may read presence only (configured / empty); never paste or rewrite real key material for convenience.

## Report Export (Audit only)

- **No Domain menu item** for export. UI is an **Export** button at the top of **Report → Audit only** when the page is Discover-hosted (`http://127.0.0.1:17322/…`). **Not shown on Passive or Active.** Manual `file://` never shows the button.
- Modal: Client / Defender / Operator radios + **Export** + **Cancel**; success shows the output path (`$HOME/data` by default).
- Backend: statusd `POST /export` → `recon/export-report.sh --kind … --report … --out-dir … --quiet` (JSON path on stdout).
- Assets: `inc-report-export.js`, `modern.css` (export classes); import-report syncs JS. Bust `inc-report-export.js?v=…` after changes.

## Import subdomains (Audit Import hub / CLI)

- Two modes: **existing** (Firefox/Pentest-Tools/TSV) or **team-csv** (`subdomain,ip,category`). UI: Audit → Import → Subdomains. CLI: `import-subdomains.sh --report … --mode … --import … [--run-active] [--json]`.
- CSV list: one IPv4 per host (empty IP → dig). **Skip hosts already in `tools/subdomains`** (no overwrite). Category = **Discover rules first**, else CSV. Never write `recon/subdomain-categories.tsv`.
- After import: refresh `pages/subdomains.htm` and `pages/hosts.htm` (unique public IPs). CSV list also writes `tools/import-batch-hosts.txt` (**new** public hosts only) and may offer Active on that batch only (`DISCOVER_ACTIVE_SCOPE=import-batch`).
- **After import + Active (full or import-batch):** rebuild the **entire** Active page from merged `tools/` artifacts — Scope (public/private/responding), status codes, alive-by-category, CMS, web servers, technologies, software versions + CVE enrichment, Login pages, and scan date. Batch Active must merge httpx/whatweb/gowitness into the engagement files first, then call the same full `pages/active.htm` rebuild (not a batch-only summary). Scan date = **latest** httpx timestamp, not the first line.

## Active Login pages (by category)

- **Login pages** table on Active (under CMS when any category exists). The Source / Type column icon (same look as sort) switches **By source** (default, ▲) · **By type** (▼). It does not sort that column. Unicode **ⓘ** next to the heading explains overlapping By source counts vs By type. Asset: `inc-active-login-view.js`.
- **By source** column **Source**: **Path**, **Title**, **Tech**, **Status** with host counts; each links to Subdomains `?login=path|title|tech|status`.
- **By type** column **Type**: **Basic** (HTTP challenge: Basic / Digest / NTLM / Negotiate, including 401 with empty title) · **Form** (Path / Title / Tech, or WhatWeb PasswordField). Generic `401 Authorization Required` titles with HTTP-challenge do not count as Form. Host may be both. Links: `?login=basic|form`. PasswordField stays out of Technologies / Software versions (`NOISE_PLUGINS`).
- **Source categories** (host may match more than one; counts are unique hosts per category, alive public hosts):
  - **Path** — newest `tools/host-scans/<host>/ffuf/*/ffuf.json` FUZZ path matches high-confidence login paths (`login`, `wp-login.php`, `oauth`, `sso`, …). Avoid bare `admin`. **SPA filter:** when a run has many hits sharing one body length (≥50 results, mode count ≥20, mode ≥50% of results), login-named paths with that same length are ignored (soft-200 app shell).
  - **Title** — httpx/page title matches login / sign-in / SSO / unauthorized / password phrases.
  - **Tech** — fingerprint includes products that typically expose a login UI (CMS, Grafana, Kibana, GitLab/Gitea, Citrix, Keycloak, …).
  - **Status** — HTTP **401** from httpx **and** an auth-related page title, or **401** with HTTP-challenge tech (Basic / Digest / NTLM / Negotiate) even if the title is empty. Bare **403** and bare **401** with empty title and no challenge are noise.
  - **Skip Microsoft SSO:** if httpx `final_url` / `url` contains `login.microsoftonline.com` (or related Microsoft IdP hosts), the host gets **no** Login pages signals (all four). **Citrix:** short live probe `POST /p/u/doAuthentication.do` → follow `doSaml` when present; if the SAML hop is Microsoft, skip (covers NetScaler AAA that only show LogonPoint in httpx). **RNAS:** title `Unified Access RNAS` or hostname `rnas-*` / `.rnas.` — remote network access gateways, skip (not app logins).
- Subdomains public rows get `data-login-path|title|tech|status="1"` when rebuilt (Active / `write_subdomains_active_page` / software-cve refresh). Filter: `inc-subdomains-filter.js` (`?login=`). Bust filter `?v=` after changes.

## Active page Enrich (Shodan + Software CVEs)

- **Enrich** button on Active (statusd only). Modal checkboxes (default both on):
  - **Shodan** → `POST /shodan-refresh-all` → `shodan-enrich.py <report> --force --json-summary`
  - **Software CVEs** → `POST /software-cve-refresh` → `active-tech.py <report> --refresh-cves --json` (re-queries NVD for missing/empty cache entries by default; `--force-all` optional; rebuilds `pages/active.htm` Software versions table + `cve-software-index.js`)
- Software versions CVE data is **NVD CPE**, not Shodan host vulns. Permanent skips: Microsoft HTTPAPI, Java Servlet, JavaServer Pages (`SKIP_PRODUCTS` in `software-cve.py`).
- Assets: `inc-active-refresh.js`; bust `?v=` and `modern.css` after UI changes. Restart statusd after endpoint changes.
