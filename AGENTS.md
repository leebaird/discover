# Discover agent notes

Conventions agreed with the operator for Discover development. **Read and follow this file.** When we discuss and agree on a durable rule (layout, install order, Update UX, host-scan gating, etc.), **add or update it here** in the same change set when practical—do not leave it only in chat history.

## Git commits

- **Only commit when the operator explicitly asks** (e.g. “do a commit”). Do not commit proactively after finishing a feature or when they only ask whether a commit is needed.

## Operator name (audit log)

- First name only, max 10 letters only, stored at `~/.discover/operator-name`.
- Prompted once when Discover starts if missing/invalid (`f_ensure_operator_name` in `discover.sh`).
- Audit lines: `mm-dd-yyyy - hh:mm Z | <name> | <egress IP> | <action>` (`f_audit_log` / host-scan `f_audit`). Legacy stamps (`mm-dd-yyyy Z - hh:mm`) and 3-field lines still parse on the Audit page.

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

## Host-scan expand (Subdomains)

- Host-scan chevrons appear **only** when the report is opened via Discover statusd HTTP (`http://127.0.0.1:17322/…`, Import report / Active). Manual `file://` open never shows chevrons, even if statusd is still running.
- Chevrons on the **full** public Subdomains table (rows with HTTP status), not only `?software=` / `?cve=` filtered views.
- **droopescan** / **wpscan** gate on the `software` query when present; otherwise infer from the row’s Title/Technologies text (e.g. tech list contains `WordPress`).
- **WordPress → wpscan only.** Do not offer droopescan for WordPress (UI map and `run-host-scan.sh` both exclude WP/droopescan). Drupal / Joomla / Moodle / Silverstripe still use droopescan when matched.
- Base tools (`nuclei`, `nikto`, `ffuf`) are always offered on expand when the UI is shown. Each tool box has a Unicode ⓘ that opens a short help modal. Bust `inc-host-scan.js?v=…` (and `modern.css?v=…` on Subdomains) after changes and sync via Import when testing live reports.

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

## Active page Update (Shodan + Software CVEs)

- **Update** button on Active (statusd only), left of Export. Modal checkboxes (default both on):
  - **Shodan** → `POST /shodan-refresh-all` → `shodan-enrich.py <report> --force --json-summary`
  - **Software CVEs** → `POST /software-cve-refresh` → `active-tech.py <report> --refresh-cves --json` (re-queries NVD for missing/empty cache entries by default; `--force-all` optional; rebuilds `pages/active.htm` Software versions table + `cve-software-index.js`)
- Software versions CVE data is **NVD CPE**, not Shodan host vulns. Permanent skips: Microsoft HTTPAPI, Java Servlet, JavaServer Pages (`SKIP_PRODUCTS` in `software-cve.py`).
- Assets: `inc-active-refresh.js`; bust `?v=` and `modern.css` after UI changes. Restart statusd after endpoint changes.
