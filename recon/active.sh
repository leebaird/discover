#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Check for root
if [ $EUID -eq 0 ]; then
    echo
    echo -e "${YELLOW}[!] This script cannot be ran as root.${NC}"
    echo
    exit 1
fi

f_active_die(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $1${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 1
}

# Move legacy $DISCOVER/.env and ~/.discover/.env into ~/.discover/api-keys.
f_discover_migrate_api_keys(){
    local py

    if [ -z "${DISCOVER:-}" ]; then
        DISCOVER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
    py="$DISCOVER/recon/software-cve.py"
    [ -f "$py" ] || return 0
    # shellcheck disable=SC2090
    DISCOVER="$DISCOVER" python3 - "$py" <<'PY' 2>/dev/null || true
import importlib.util
import sys

path = sys.argv[1]
spec = importlib.util.spec_from_file_location("software_cve", path)
if spec is None or spec.loader is None:
    raise SystemExit(0)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
if hasattr(mod, "migrate_legacy_api_key_files"):
    mod.migrate_legacy_api_key_files()
PY
}

# Load private API key / env files without overriding non-empty shell exports.
# Preferred: ~/.discover/api-keys (legacy .env files are migrated first).
f_discover_load_env(){
    local env_file line key value

    if [ -z "${DISCOVER:-}" ]; then
        DISCOVER="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi

    f_discover_migrate_api_keys

    for env_file in "$HOME/.discover/api-keys" "$DISCOVER/.env" "$HOME/.discover/.env"; do
        [ -f "$env_file" ] || continue
        while IFS= read -r line || [ -n "$line" ]; do
            # Trim whitespace
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [ -z "$line" ] && continue
            case "$line" in
                \#*) continue ;;
            esac
            case "$line" in
                export\ *) line="${line#export }"
                    line="${line#"${line%%[![:space:]]*}"}"
                    ;;
            esac
            case "$line" in
                *=*) ;;
                *) continue ;;
            esac
            key="${line%%=*}"
            value="${line#*=}"
            key="${key%"${key##*[![:space:]]}"}"
            key="${key#"${key%%[![:space:]]*}"}"
            case "$key" in
                ''|*[!A-Za-z0-9_]*|[0-9]*) continue ;;
            esac
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            # Strip matching single/double quotes
            if [ "${#value}" -ge 2 ]; then
                if [ "${value:0:1}" = '"' ] && [ "${value: -1}" = '"' ]; then
                    value="${value:1:${#value}-2}"
                elif [ "${value:0:1}" = "'" ] && [ "${value: -1}" = "'" ]; then
                    value="${value:1:${#value}-2}"
                fi
            fi
            # Shell export wins over file values
            if [ -n "${!key:-}" ]; then
                continue
            fi
            export "$key=$value"
        done < "$env_file"
    done
}

f_active_read_report(){
    # Allow caller (Import subdomains) to pre-set DISCOVER_REPORT.
    if [ -n "${DISCOVER_REPORT:-}" ] \
        && [ -d "$DISCOVER_REPORT/pages" ] \
        && [ -f "$DISCOVER_REPORT/pages/subdomains.htm" ]; then
        DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)"
        return 0
    fi

    echo
    echo -n "Enter the location of a previous Discover scan: "
    read -r DISCOVER_REPORT

    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

    if [ -z "$DISCOVER_REPORT" ]; then
        f_active_die "No scan location provided."
    fi

    if [ -f "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT" ] \
        || [ ! -r "$DISCOVER_REPORT" ] \
        || [ ! -x "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT/pages" ] \
        || [ ! -f "$DISCOVER_REPORT/pages/subdomains.htm" ]; then
        f_active_die "Passive scan not found."
    fi
}

f_active_chrome_path(){
    local bin

    for bin in google-chrome-stable google-chrome chromium chromium-browser; do
        if command -v "$bin" >/dev/null 2>&1; then
            command -v "$bin"
            return 0
        fi
    done

    return 1
}

f_active_build_targets(){
    local subdomains_file="$1"
    local targets_file="$2"

    python3 - "$subdomains_file" "$targets_file" <<'PY'
import csv
import re
import sys

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_private_ip(ip):
    if not IPV4_RE.match(ip):
        return False
    octets = [int(part) for part in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False

def parse_row(raw):
    raw = raw.strip()
    if not raw:
        return None

    if "\t" in raw:
        row = next(csv.reader([raw], delimiter="\t"))
        while len(row) < 3:
            row.append("")
        subdomain, ipaddr, category = row[0].strip(), row[1].strip(), row[2].strip()
    else:
        parts = raw.split()
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0], "", ""
        if IPV4_RE.match(parts[-1]):
            subdomain, ipaddr = " ".join(parts[:-1]), parts[-1]
            category = ""
        else:
            subdomain = parts[0]
            ipaddr = parts[1] if len(parts) > 1 else ""
            category = parts[2] if len(parts) > 2 else ""

    if not subdomain or not ipaddr:
        return None
    return subdomain, ipaddr, category

subdomains_path, targets_path = sys.argv[1:3]
hosts = []

with open(subdomains_path, newline="") as handle:
    for raw in handle:
        parsed = parse_row(raw)
        if not parsed:
            continue
        subdomain, ipaddr, _category = parsed
        if is_private_ip(ipaddr):
            continue
        hosts.append(subdomain)

unique_hosts = sorted(set(hosts))

with open(targets_path, "w", newline="") as handle:
    for host in unique_hosts:
        handle.write(host + "\n")
PY
}

f_active_parse_httpx(){
    local jsonl_file="$1"
    local alive_tsv="$2"
    local active_txt="$3"

    python3 - "$jsonl_file" "$alive_tsv" "$active_txt" <<'PY'
import json
import sys

ALIVE_STATUSES = set(range(200, 400)) | {401, 403, 405}

jsonl_path, alive_tsv_path, active_txt_path = sys.argv[1:4]
alive_rows = []
alive_urls = set()

try:
    with open(jsonl_path, encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue

            status = entry.get("status_code")
            if status is None:
                continue

            host = entry.get("host") or entry.get("input") or ""
            url = entry.get("url") or ""
            if not host or not url:
                continue

            if status not in ALIVE_STATUSES:
                continue

            alive_rows.append((host, url, status))
            alive_urls.add(url)
except FileNotFoundError:
    pass

with open(alive_tsv_path, "w", encoding="utf-8", newline="") as handle:
    for host, url, status in alive_rows:
        handle.write(f"{host}\t{url}\t{status}\n")

with open(active_txt_path, "w", encoding="utf-8", newline="") as handle:
    for url in sorted(alive_urls):
        handle.write(url + "\n")
PY
}

f_active_write_report(){
    local private_file="$1"
    local public_file="$2"
    local gowitness_jsonl="$3"
    local screenshots_dir="$4"
    local httpx_jsonl="$5"
    local whatweb_json="$6"
    local page="$7"

    cp "$DISCOVER/report/pages/subdomains.htm" "$page"

    python3 - "$page" "$DISCOVER/recon/active-tech.py" "$private_file" "$public_file" "$gowitness_jsonl" "$screenshots_dir" "$httpx_jsonl" "$whatweb_json" <<'PY'
import csv
import html
import importlib.util
import json
import os
import re
import sys
from urllib.parse import urlparse

page_path, tech_module_path, private_path, public_path, gowitness_jsonl, screenshots_dir, httpx_path, whatweb_path = sys.argv[1:9]

spec = importlib.util.spec_from_file_location("active_tech", tech_module_path)
active_tech = importlib.util.module_from_spec(spec)
spec.loader.exec_module(active_tech)
host_tech = active_tech.load_host_tech(httpx_path, whatweb_path)
# Engagement root for ffuf path signals (pages/ → report root).
report_root = os.path.dirname(os.path.dirname(os.path.abspath(page_path)))
path_hosts = active_tech.collect_login_path_hosts(report_root)
login_skip_hosts = active_tech.collect_login_skip_hosts(host_tech)

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_private_ip(ip):
    if not IPV4_RE.match(ip):
        return False
    octets = [int(part) for part in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False

def parse_row(raw):
    raw = raw.strip()
    if not raw:
        return None

    if "\t" in raw:
        row = next(csv.reader([raw], delimiter="\t"))
        while len(row) < 3:
            row.append("")
        subdomain, ipaddr, category = row[0].strip(), row[1].strip(), row[2].strip()
    else:
        parts = raw.split()
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0], "", ""
        if IPV4_RE.match(parts[-1]):
            subdomain, ipaddr = " ".join(parts[:-1]), parts[-1]
            category = ""
        else:
            subdomain = parts[0]
            ipaddr = parts[1] if len(parts) > 1 else ""
            category = parts[2] if len(parts) > 2 else ""

    if not subdomain:
        return None
    return subdomain, ipaddr, category

def load_rows(path):
    rows = []
    if not path or not os.path.isfile(path):
        return rows
    with open(path, newline="") as handle:
        for raw in handle:
            parsed = parse_row(raw)
            if parsed and parsed[1]:
                rows.append(parsed)
    return rows

def host_from_url(url):
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()

def load_photo_hosts(jsonl_path, screenshots_dir):
    photos = {}
    if not jsonl_path or not os.path.isfile(jsonl_path) or not screenshots_dir:
        return photos

    with open(jsonl_path, encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if entry.get("failed"):
                continue

            file_name = (entry.get("file_name") or "").strip()
            if not file_name:
                continue

            screenshot_path = os.path.join(screenshots_dir, file_name)
            if not os.path.isfile(screenshot_path):
                continue

            url_value = entry.get("url") or entry.get("final_url") or ""
            if "://" not in url_value:
                url_value = "https://" + url_value

            parsed = urlparse(url_value)
            host = (parsed.hostname or "").lower()
            if not host:
                continue

            scheme = parsed.scheme

            rel_href = f"../tools/gowitness/screenshots/{file_name}"
            current = photos.get(host)
            if not current or scheme == "https":
                photos[host] = rel_href

    return photos

def build_private_table(rows, empty_message, ip_header="IP Address"):
    lines = [
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        '                    <th scope="col" class="inc-sortable">Subdomain</th>',
        '                    <th scope="col" class="inc-sortable">Category</th>',
        f'                    <th scope="col" class="inc-sortable">{html.escape(ip_header)}</th>',
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    if rows:
        for subdomain, ipaddr, category in rows:
            lines.append(
                "                <tr>"
                f"<td>{html.escape(subdomain)}</td>"
                f"<td>{html.escape(category)}</td>"
                f"<td>{html.escape(ipaddr)}</td>"
                "</tr>"
            )
    else:
        lines.append(f'                <tr><td colspan="3">{html.escape(empty_message)}</td></tr>')

    lines.extend(
        [
            "            </tbody>",
            "        </table>",
        ]
    )
    return lines

def photo_cell(subdomain, photo_hosts):
    href = photo_hosts.get(subdomain.lower())
    if not href:
        return ""
    return f'<a href="{html.escape(href)}" target="_blank">Yes</a>'

def host_cell(subdomain, status, url):
    """Link subdomain when it has an HTTP status (opens target in a new tab)."""
    text = html.escape(subdomain)
    if not str(status or "").strip():
        return f'<td class="inc-subdomain-host">{text}</td>'

    href = (url or "").strip()
    if not href:
        href = f"https://{subdomain}"
    elif "://" not in href:
        href = f"https://{href}"

    return (
        f'<td class="inc-subdomain-host">'
        f'<a class="inc-subdomain-host-link" href="{html.escape(href, quote=True)}" '
        f'target="_blank" rel="noopener noreferrer">{text}</a>'
        f"</td>"
    )

def tech_cell(title, technologies):
    title_text = title.strip() if title else ""
    if not title_text:
        title_text = "-"
    tech_title = f' title="{html.escape(technologies)}"' if technologies else ""
    return (
        f'<td class="inc-subdomain-tech">'
        f'<div class="inc-subdomain-title" data-sort-field="title">{html.escape(title_text)}</div>'
        f'<div class="inc-subdomain-techs" data-sort-field="tech"{tech_title}>{html.escape(technologies)}</div>'
        f"</td>"
    )

def build_public_table(rows, photo_hosts, host_tech, empty_message, ip_header="IP Address"):
    lines = [
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        '                    <th scope="col" class="inc-sortable">Subdomain</th>',
        '                    <th scope="col" class="inc-sortable">Category</th>',
        f'                    <th scope="col" class="inc-sortable">{html.escape(ip_header)}</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center" data-sort-then="4,5">Photo</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">Status</th>',
        '                    <th scope="col" class="inc-sortable inc-subdomain-webserver-h">Web Server</th>',
        '                    <th scope="col" class="inc-subdomain-title-tech-header">',
        '                        <span class="inc-sortable" data-sort-field="title">Title</span>',
        '                        <span class="inc-sortable" data-sort-field="tech">Technologies</span>',
        "                    </th>",
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    if rows:
        for subdomain, ipaddr, category in rows:
            photo = photo_cell(subdomain, photo_hosts)
            tech = host_tech.get(subdomain.lower(), {})
            status = tech.get("status", "")
            webserver = tech.get("webserver", "")
            title = tech.get("title", "")
            technologies = tech.get("technologies", "")
            row_attrs = active_tech.login_data_attrs(
                subdomain, tech, path_hosts, skip_hosts=login_skip_hosts
            )
            lines.append(
                f"                <tr{row_attrs}>"
                f"{host_cell(subdomain, status, tech.get('url', ''))}"
                f"<td>{html.escape(category)}</td>"
                f'<td class="inc-subdomain-ip">{html.escape(ipaddr)}</td>'
                f'<td class="inc-col-center">{photo}</td>'
                f'<td class="inc-col-center">{html.escape(status)}</td>'
                f'<td class="inc-subdomain-webserver">{html.escape(webserver)}</td>'
                f"{tech_cell(title, technologies)}"
                "</tr>"
            )
    else:
        lines.append(f'                <tr><td colspan="7">{html.escape(empty_message)}</td></tr>')

    lines.extend(
        [
            "            </tbody>",
            "        </table>",
        ]
    )
    return lines

private_rows = load_rows(private_path)
public_rows = [
    row for row in load_rows(public_path) if not is_private_ip(row[1])
]
photo_hosts = load_photo_hosts(gowitness_jsonl, screenshots_dir)

out = []
if private_rows:
    out.append('    <div class="inc-content-frame inc-content-frame--table">')
    out.extend(build_private_table(private_rows, "No private subdomains found.", "Private IP Address"))
    out.append("    </div>")

if public_rows or not private_rows:
    out.append('    <div class="inc-content-frame inc-content-frame--table inc-subdomains-public">')
    if public_rows:
        out.extend(build_public_table(public_rows, photo_hosts, host_tech, "No data found."))
    else:
        out.extend(build_public_table([], photo_hosts, host_tech, "No data found."))
    out.append("    </div>")

out.extend(
    [
        "    </div>",
        "</div>",
        "",
        '<script src="../assets/javascript/inc-data-table.js"></script>',
        '<script src="../tools/cve-software-index.js"></script>',
        '<script src="../assets/javascript/inc-subdomains-filter.js?v=17"></script>',
        '<script src="../tools/shodan/index.js"></script>',
        '<script src="../tools/shodan/kev-ids.js"></script>',
        '<script src="../assets/javascript/inc-shodan.js?v=18"></script>',
        '<script src="../assets/javascript/inc-host-scan.js?v=34"></script>',
        "</body>",
        "</html>",
    ]
)

with open(page_path, "a") as handle:
    handle.write("\n".join(out) + "\n")
PY
}

f_active_report_substitute_placeholders(){
    local page="$1"
    local index="$2"

    [ -f "$page" ] || return 0
    [ -f "$index" ] || return 0

    python3 - "$page" "$index" <<'PY'
import re
import sys
from pathlib import Path

page = Path(sys.argv[1])
index = Path(sys.argv[2])
text = index.read_text()


def extract(label):
    match = re.search(
        rf'inc-home-meta-label">{label}</span>\s*<span class="value">([^<]*)</span>',
        text,
    )
    return match.group(1).strip() if match else ""


company = extract("Company")
domain = extract("Domain")
if not domain:
    domain = index.parent.name

content = page.read_text()
content = content.replace("#COMPANY#", company)
content = content.replace("#DOMAIN#", domain)
page.write_text(content)
PY
}

f_active_write_active_page(){
    local subdomains_file="$1"
    local private_file="$2"
    local alive_tsv="$3"
    local httpx_jsonl="$4"
    local whatweb_json="$5"
    local page="$6"

    cp "$DISCOVER/report/pages/active.htm" "$page"

    local report_dir
    report_dir=$(dirname "$(dirname "$page")")

    python3 - "$page" "$DISCOVER/recon/active-tech.py" "$subdomains_file" "$private_file" "$alive_tsv" "$httpx_jsonl" "$whatweb_json" <<'PY'
import importlib.util
import sys

page_path, tech_module_path, subdomains_path, private_path, alive_tsv_path, httpx_path, whatweb_path = sys.argv[1:8]

spec = importlib.util.spec_from_file_location("active_tech", tech_module_path)
active_tech = importlib.util.module_from_spec(spec)
spec.loader.exec_module(active_tech)

summary = active_tech.build_active_summary(
    subdomains_path,
    private_path,
    alive_tsv_path,
    httpx_path,
    whatweb_path,
)
scan_date = active_tech.httpx_scan_date(httpx_path)

content = open(page_path, encoding="utf-8").read()
content = content.replace("#ACTIVE_CONTENT#", summary)
content = content.replace("#ACTIVE_SCAN_DATE#", scan_date)
with open(page_path, "w", encoding="utf-8") as handle:
    handle.write(content)
PY

    f_active_report_substitute_placeholders "$page" "$report_dir/index.htm"
}

clear
f_banner

echo -e "${BLUE}ACTIVE RECON${NC}"
echo
echo -e "${BLUE}Uses httpx, whatweb, and gowitness.${NC}"
echo

f_active_read_report

TOOLS_DIR="$DISCOVER_REPORT/tools"
SUBDOMAINS_FILE="$TOOLS_DIR/subdomains"
PRIVATE_FILE="$TOOLS_DIR/private-subs"
TARGETS_FILE="$TOOLS_DIR/active-targets.txt"
HTTPX_JSONL="$TOOLS_DIR/httpx.jsonl"
ALIVE_TSV="$TOOLS_DIR/active-alive.tsv"
ACTIVE_TXT="$TOOLS_DIR/active.txt"
WHATWEB_JSON="$TOOLS_DIR/whatweb.json"
GOWITNESS_DIR="$TOOLS_DIR/gowitness"
GOWITNESS_JSONL="$GOWITNESS_DIR/gowitness.jsonl"
SCREENSHOTS_DIR="$GOWITNESS_DIR/screenshots"
# Prefer Discover-refreshed Edge UA (resource/user-agent.txt via f_discover_user_agent).
if [ -z "${USER_AGENT:-}" ] || [[ "$USER_AGENT" != Mozilla/* ]]; then
    if declare -F f_discover_user_agent >/dev/null 2>&1; then
        USER_AGENT="$(f_discover_user_agent)"
    elif [ -n "${DISCOVER:-}" ] && [ -f "$DISCOVER/resource/user-agent.txt" ]; then
        USER_AGENT=$(grep -v '^[[:space:]]*#' "$DISCOVER/resource/user-agent.txt" | sed '/^[[:space:]]*$/d' | head -n 1)
    fi
fi
if [ -z "${USER_AGENT:-}" ] || [[ "$USER_AGENT" != Mozilla/* ]]; then
    USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0'
fi
WHATWEB_UA="$USER_AGENT"
PAGE="$DISCOVER_REPORT/pages/subdomains.htm"
ACTIVE_PAGE="$DISCOVER_REPORT/pages/active.htm"

if [ ! -f "$SUBDOMAINS_FILE" ] || [ ! -s "$SUBDOMAINS_FILE" ]; then
    f_active_die "Subdomains data not found. Run a passive scan or import subdomains first."
fi

for CMD in httpx whatweb gowitness python3; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        f_active_die "$CMD is not installed. Run Discover update to install dependencies."
    fi
done

CHROME_PATH=$(f_active_chrome_path) || f_active_die "Chrome or Chromium is not installed. Run Discover update to install dependencies."

mkdir -p "$TOOLS_DIR" "$SCREENSHOTS_DIR"

ACTIVE_SCOPE="${DISCOVER_ACTIVE_SCOPE:-all}"
BATCH_HOSTS_FILE="$TOOLS_DIR/import-batch-hosts.txt"
TMPDIR_ACTIVE=$(mktemp -d)
trap 'rm -rf "$TMPDIR_ACTIVE"' EXIT
HTTPX_BATCH="$TMPDIR_ACTIVE/httpx-batch.jsonl"
WHATWEB_BATCH="$TMPDIR_ACTIVE/whatweb-batch.json"
GOWITNESS_BATCH="$TMPDIR_ACTIVE/gowitness-batch.jsonl"
ACTIVE_TXT_BATCH="$TMPDIR_ACTIVE/active-batch.txt"

echo
if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
    echo -e "${BLUE}[*] Building active target list from last CSV list import (public hosts only).${NC}"
    if [ ! -s "$BATCH_HOSTS_FILE" ]; then
        f_active_die "No import-batch hosts at tools/import-batch-hosts.txt. Run Import subdomains (CSV list) first."
    fi
    # Only hosts still public in tools/subdomains
    python3 - "$SUBDOMAINS_FILE" "$BATCH_HOSTS_FILE" "$TARGETS_FILE" <<'PY'
import csv, re, sys
from pathlib import Path
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
def is_private(ip):
    if not IPV4_RE.match(ip): return True
    o=[int(x) for x in ip.split(".")]
    if o[0]==10: return True
    if o[0]==172 and 16<=o[1]<=31: return True
    if o[0]==192 and o[1]==168: return True
    return False
sub_path, batch_path, out_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
host_ip={}
for raw in sub_path.read_text(encoding="utf-8", errors="replace").splitlines():
    p=raw.split("\t")
    if len(p)>=2: host_ip[p[0].strip().lower()]=p[1].strip()
hosts=[]
for raw in batch_path.read_text(encoding="utf-8", errors="replace").splitlines():
    h=raw.strip().lower()
    if not h: continue
    ip=host_ip.get(h,"")
    if ip and not is_private(ip): hosts.append(h)
out_path.write_text("\n".join(sorted(set(hosts)))+("\n" if hosts else ""), encoding="utf-8")
PY
else
    echo -e "${BLUE}[*] Building active target list from public subdomains.${NC}"
    f_active_build_targets "$SUBDOMAINS_FILE" "$TARGETS_FILE"
fi

TARGET_COUNT=$(wc -l < "$TARGETS_FILE" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
TARGET_COUNT=${TARGET_COUNT:-0}

if [ "$TARGET_COUNT" -eq 0 ]; then
    f_active_die "No public subdomains found to probe."
fi

echo "[*] $TARGET_COUNT public hostnames queued for httpx."
echo
echo -e "${BLUE}[*] Running httpx.${NC}"
echo "[*] User-Agent: $USER_AGENT"

HTTPX_OUT="$HTTPX_JSONL"
if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
    HTTPX_OUT="$HTTPX_BATCH"
fi

httpx -l "$TARGETS_FILE" -silent -sc -title -server -td -cl -ip -cname -cdn \
    -fhr -maxr 2 \
    -H "User-Agent: $USER_AGENT" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -json -o "$HTTPX_OUT" >/dev/null

if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
    # Merge batch httpx into engagement jsonl (replace lines for batch hosts).
    python3 - "$HTTPX_JSONL" "$HTTPX_BATCH" "$TARGETS_FILE" <<'PY'
import json, sys
from pathlib import Path
from urllib.parse import urlparse

main_path, batch_path, targets_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
batch_hosts = {
    h.strip().lower()
    for h in targets_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if h.strip()
}

def host_of(entry):
    for key in ("input", "host", "url", "final_url"):
        v = entry.get(key) or ""
        if not v:
            continue
        if "://" in str(v):
            h = (urlparse(str(v)).hostname or "").lower()
        else:
            h = str(v).split("/")[0].split(":")[0].lower()
        if h:
            return h
    return ""

kept = []
if main_path.is_file():
    for raw in main_path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            e = json.loads(raw)
        except json.JSONDecodeError:
            continue
        h = host_of(e)
        if h and h in batch_hosts:
            continue
        kept.append(raw)
if batch_path.is_file():
    for raw in batch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.strip():
            kept.append(raw.strip())
main_path.parent.mkdir(parents=True, exist_ok=True)
main_path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
PY
fi

echo
echo -e "${BLUE}[*] Parsing httpx results.${NC}"
# Parse full merged set for report tables; for batch-only whatweb/gowitness use batch alive.
f_active_parse_httpx "$HTTPX_JSONL" "$ALIVE_TSV" "$ACTIVE_TXT"

if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
    python3 - "$ALIVE_TSV" "$ACTIVE_TXT" "$TARGETS_FILE" "$TMPDIR_ACTIVE/alive-batch.tsv" "$ACTIVE_TXT_BATCH" <<'PY'
import sys
from pathlib import Path
alive_path, urls_path, targets_path, alive_out, urls_out = [Path(p) for p in sys.argv[1:6]]
batch = {h.strip().lower() for h in targets_path.read_text().splitlines() if h.strip()}
alive_lines = []
if alive_path.is_file():
    for raw in alive_path.read_text().splitlines():
        host = raw.split("\t")[0].strip().lower() if raw.strip() else ""
        if host in batch:
            alive_lines.append(raw)
alive_out.write_text("\n".join(alive_lines) + ("\n" if alive_lines else ""), encoding="utf-8")
url_lines = []
if urls_path.is_file():
    from urllib.parse import urlparse
    for raw in urls_path.read_text().splitlines():
        u = raw.strip()
        if not u:
            continue
        h = (urlparse(u if "://" in u else "https://" + u).hostname or "").lower()
        if h in batch:
            url_lines.append(u)
urls_out.write_text("\n".join(url_lines) + ("\n" if url_lines else ""), encoding="utf-8")
PY
    WHATWEB_INPUT="$ACTIVE_TXT_BATCH"
    GOWITNESS_INPUT="$ACTIVE_TXT_BATCH"
    URL_COUNT=$(wc -l < "$ACTIVE_TXT_BATCH" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
else
    WHATWEB_INPUT="$ACTIVE_TXT"
    GOWITNESS_INPUT="$ACTIVE_TXT"
    URL_COUNT=$(wc -l < "$ACTIVE_TXT" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
fi
URL_COUNT=${URL_COUNT:-0}

ALIVE_COUNT=$(wc -l < "$ALIVE_TSV" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
ALIVE_COUNT=${ALIVE_COUNT:-0}

ALIVE_HOST_COUNT=$(awk -F '\t' 'NF >= 1 && $1 != "" { print $1 }' "$ALIVE_TSV" | sort -u | wc -l | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
ALIVE_HOST_COUNT=${ALIVE_HOST_COUNT:-0}

echo "[*] $ALIVE_COUNT alive responses across $ALIVE_HOST_COUNT hostnames ($URL_COUNT URLs for this run)."
echo

if [ "$URL_COUNT" -gt 0 ]; then
    echo -e "${BLUE}[*] Running whatweb on alive URLs.${NC}"
    if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
        whatweb -a 3 -i "$WHATWEB_INPUT" \
            -U "$WHATWEB_UA" \
            --log-json="$WHATWEB_BATCH" \
            --no-errors -q
        # Merge whatweb JSON arrays / NDJSON-ish
        python3 - "$WHATWEB_JSON" "$WHATWEB_BATCH" <<'PY'
import json, sys
from pathlib import Path
main_p, batch_p = Path(sys.argv[1]), Path(sys.argv[2])

def load_entries(path):
    if not path.is_file() or path.stat().st_size == 0:
        return []
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass
    out = []
    for raw in text.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out

def target_key(entry):
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("target") or entry.get("http_status") or entry.get("uri") or json.dumps(entry, sort_keys=True)[:200])

main = load_entries(main_p)
batch = load_entries(batch_p)
# Drop main entries whose target host is in batch set (best-effort by target URL)
from urllib.parse import urlparse
def host_of(e):
    t = str(e.get("target") or "")
    if "://" in t:
        return (urlparse(t).hostname or "").lower()
    return t.split("/")[0].lower()
batch_hosts = {host_of(e) for e in batch if host_of(e)}
kept = [e for e in main if host_of(e) not in batch_hosts]
merged = kept + batch
main_p.parent.mkdir(parents=True, exist_ok=True)
main_p.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
PY
    else
        whatweb -a 3 -i "$WHATWEB_INPUT" \
            -U "$WHATWEB_UA" \
            --log-json="$WHATWEB_JSON" \
            --no-errors -q
    fi

    echo
    echo -e "${BLUE}[*] Running gowitness on alive URLs.${NC}"
    if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
        # Keep existing screenshots; merge jsonl by host (replace batch hosts, keep others).
        gowitness scan file -f "$GOWITNESS_INPUT" \
            --driver gorod \
            --chrome-path "$CHROME_PATH" \
            --screenshot-path "$SCREENSHOTS_DIR" \
            --write-jsonl --write-jsonl-file "$GOWITNESS_BATCH" \
            --write-db --write-db-uri "sqlite://$GOWITNESS_DIR/gowitness.db"
        if [ -f "$GOWITNESS_BATCH" ]; then
            python3 - "$GOWITNESS_JSONL" "$GOWITNESS_BATCH" "$TARGETS_FILE" <<'PY'
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

main_path, batch_path, targets_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
batch_hosts = {
    h.strip().lower()
    for h in targets_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if h.strip()
}


def host_of(entry):
    if not isinstance(entry, dict):
        return ""
    url = entry.get("url") or entry.get("final_url") or ""
    if "://" not in str(url):
        url = "https://" + str(url)
    return (urlparse(str(url)).hostname or "").lower()


def load_jsonl(path):
    rows = []
    if not path.is_file():
        return rows
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return rows

kept = []
for entry in load_jsonl(main_path):
    h = host_of(entry)
    if h and h in batch_hosts:
        continue
    kept.append(entry)
kept.extend(load_jsonl(batch_path))
main_path.parent.mkdir(parents=True, exist_ok=True)
with main_path.open("w", encoding="utf-8") as handle:
    for entry in kept:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
PY
        fi
    else
        rm -rf "$SCREENSHOTS_DIR"/*
        gowitness scan file -f "$GOWITNESS_INPUT" \
            --driver gorod \
            --chrome-path "$CHROME_PATH" \
            --screenshot-path "$SCREENSHOTS_DIR" \
            --write-jsonl --write-jsonl-file "$GOWITNESS_JSONL" \
            --write-db --write-db-uri "sqlite://$GOWITNESS_DIR/gowitness.db"
    fi
    echo
else
    echo
    echo "[*] No alive URLs found for this run. Skipping whatweb and gowitness."
    if [ "$ACTIVE_SCOPE" != "import-batch" ]; then
        rm -f "$WHATWEB_JSON" "$GOWITNESS_JSONL" "$GOWITNESS_DIR/gowitness.db" 2>/dev/null
        rm -rf "$SCREENSHOTS_DIR"/*
    fi
    echo
fi

# ---------------------------------------------------------------------------
# Full report rebuild from merged tools/ (import-batch and full Active).
# Scope / status / category / tech / software counts all come from these files.
# ---------------------------------------------------------------------------
# Re-parse entire httpx.jsonl so active-alive.tsv matches the merged inventory
# (batch path already merged jsonl; full Active overwrote it).
f_active_parse_httpx "$HTTPX_JSONL" "$ALIVE_TSV" "$ACTIVE_TXT"

# Keep private-subs aligned with tools/subdomains (source of truth after import).
python3 - "$SUBDOMAINS_FILE" "$PRIVATE_FILE" <<'PY'
import re
import sys
from pathlib import Path

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_private(ip: str) -> bool:
    if not IPV4_RE.match(ip or ""):
        return False
    o = [int(x) for x in ip.split(".")]
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    return False

sub_path, priv_path = Path(sys.argv[1]), Path(sys.argv[2])
rows = []
if sub_path.is_file():
    for raw in sub_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        host, ip = parts[0].strip(), parts[1].strip()
        if host and ip and is_private(ip):
            cat = parts[2].strip() if len(parts) > 2 else ""
            rows.append((host, ip, cat))
priv_path.parent.mkdir(parents=True, exist_ok=True)
with priv_path.open("w", encoding="utf-8", newline="") as handle:
    for host, ip, cat in sorted(rows, key=lambda r: r[0].lower()):
        if cat:
            handle.write(f"{host}\t{ip}\t{cat}\n")
        else:
            handle.write(f"{host}\t{ip}\n")
PY

SCREENSHOT_COUNT=0
if [ -d "$SCREENSHOTS_DIR" ]; then
    SCREENSHOT_COUNT=$(find "$SCREENSHOTS_DIR" -type f \( -name '*.jpeg' -o -name '*.jpg' -o -name '*.png' \) 2>/dev/null | wc -l | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
    SCREENSHOT_COUNT=${SCREENSHOT_COUNT:-0}
fi

PHOTO_HOST_COUNT=$(python3 - "$GOWITNESS_JSONL" "$SCREENSHOTS_DIR" <<'PY'
import json
import os
import sys
from urllib.parse import urlparse

jsonl_path, screenshots_dir = sys.argv[1:3]
hosts = set()

if not os.path.isfile(jsonl_path):
    print(0)
    raise SystemExit(0)

with open(jsonl_path, encoding="utf-8") as handle:
    for raw in handle:
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if entry.get("failed"):
            continue
        file_name = (entry.get("file_name") or "").strip()
        if not file_name or not os.path.isfile(os.path.join(screenshots_dir, file_name)):
            continue
        url = entry.get("url") or entry.get("final_url") or ""
        if "://" not in url:
            url = "https://" + url
        host = (urlparse(url).hostname or "").lower()
        if host:
            hosts.add(host)

print(len(hosts))
PY
)
PHOTO_HOST_COUNT=${PHOTO_HOST_COUNT:-0}

echo -e "${BLUE}[*] Updating subdomains report with Photo, Status, Web Server, Title, and Technologies.${NC}"
f_active_write_report "$PRIVATE_FILE" "$SUBDOMAINS_FILE" "$GOWITNESS_JSONL" "$SCREENSHOTS_DIR" "$HTTPX_JSONL" "$WHATWEB_JSON" "$PAGE"

f_discover_load_env

echo -e "${BLUE}[*] Updating Active report (includes NVD CVSS lookup for software versions).${NC}"
if [ -n "${NVD_API_KEY:-}" ]; then
    echo -e "${BLUE}[*] NVD_API_KEY found (~/.discover/api-keys) — using authenticated rate limits.${NC}"
else
    echo -e "${BLUE}[*] No NVD_API_KEY — anonymous NVD rate limits (slower).${NC}"
    echo -e "${BLUE}[*] Add export NVD_API_KEY=... or put it in ~/.discover/api-keys${NC}"
    echo -e "${BLUE}[*] Free key: https://nvd.nist.gov/developers/request-an-api-key${NC}"
    echo -e "${BLUE}[*] Skip lookups: DISCOVER_SKIP_CVE=1${NC}"
fi
# Full Active page: Scope / status / category / CMS / web servers / tech / software
# always rebuilt from tools/subdomains + private-subs + active-alive + httpx + whatweb
# (import-batch merges into those files first, then this runs).
f_active_write_active_page "$SUBDOMAINS_FILE" "$PRIVATE_FILE" "$ALIVE_TSV" "$HTTPX_JSONL" "$WHATWEB_JSON" "$ACTIVE_PAGE"
echo

# Engagement session + audit
printf '%s\n' "$DISCOVER_REPORT" > "${HOME}/.discover/current-report" 2>/dev/null || true
mkdir -p "${HOME}/.discover" "$DISCOVER_REPORT/assets" "$DISCOVER_REPORT/tools/audit" "$DISCOVER_REPORT/tools/host-scans" 2>/dev/null || true
cat > "$DISCOVER_REPORT/assets/report-mode.json" <<'EOF'
{
  "mode": "operator",
  "launches": true
}
EOF
if declare -F f_audit_log >/dev/null 2>&1; then
    if [ "$ACTIVE_SCOPE" = "import-batch" ]; then
        f_audit_log "$DISCOVER_REPORT" "Ran active recon on imported hosts ($TARGET_COUNT targets)"
    else
        f_audit_log "$DISCOVER_REPORT" "Ran active recon"
    fi
else
    ts=$(date -u +"%m-%d-%Y - %H:%M Z")
    op=$(head -n 1 "${HOME}/.discover/operator-name" 2>/dev/null | tr -d '\r' | tr -cd "A-Za-z" | cut -c1-10)
    [ -n "$op" ] || op=unknown
    ip=$(curl -4 -fsS --connect-timeout 5 --max-time 10 http://ifconfig.me 2>/dev/null | tr -d '[:space:]')
    [ -n "$ip" ] || ip=unknown
    printf '%s | %s | %s | Ran active recon.\n' "$ts" "$op" "$ip" >> "$DISCOVER_REPORT/tools/audit/log.txt" 2>/dev/null || true
fi

if [ -f "$DISCOVER/recon/audit-build.py" ]; then
    python3 "$DISCOVER/recon/audit-build.py" "$DISCOVER_REPORT" "$DISCOVER/report/pages/audit.htm" >/dev/null 2>&1 || true
fi

if [ -f "$DISCOVER/recon/touch-report-date.py" ]; then
    python3 "$DISCOVER/recon/touch-report-date.py" "$DISCOVER_REPORT" >/dev/null 2>&1 || true
fi

# Status helper for live host-scan UI (localhost only)
if [ -f "$DISCOVER/misc/host-scan-statusd.py" ]; then
    if ! curl -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:17322/health" >/dev/null 2>&1; then
        nohup python3 "$DISCOVER/misc/host-scan-statusd.py" "$DISCOVER_REPORT" 17322 \
            >/dev/null 2>&1 &
    fi
fi

echo "$MEDIUM"
echo
echo "[*] Active scan complete."
echo "[*] Probed $TARGET_COUNT hostnames; $ALIVE_HOST_COUNT with active probe data in report."
if [ "$URL_COUNT" -gt 0 ]; then
    echo "[*] Captured $SCREENSHOT_COUNT screenshots; $PHOTO_HOST_COUNT linked in report."
fi
echo
echo -e "Artifacts saved under ${YELLOW}$TOOLS_DIR${NC}"
echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
echo
exit 0