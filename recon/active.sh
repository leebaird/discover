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

f_active_read_report(){
    echo
    echo -n "Enter the location of your previous passive scan: "
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

def build_public_table(rows, photo_hosts, host_tech, empty_message, ip_header="IP Address"):
    lines = [
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        '                    <th scope="col" class="inc-sortable">Subdomain</th>',
        '                    <th scope="col" class="inc-sortable">Category</th>',
        f'                    <th scope="col" class="inc-sortable">{html.escape(ip_header)}</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">Photo</th>',
        '                    <th scope="col" class="inc-sortable inc-col-center">Status</th>',
        '                    <th scope="col" class="inc-sortable">Web Server</th>',
        '                    <th scope="col" class="inc-sortable">Technologies</th>',
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
            technologies = tech.get("technologies", "")
            tech_title = f' title="{html.escape(technologies)}"' if technologies else ""
            lines.append(
                "                <tr>"
                f'<td class="inc-subdomain-host">{html.escape(subdomain)}</td>'
                f"<td>{html.escape(category)}</td>"
                f"<td>{html.escape(ipaddr)}</td>"
                f'<td class="inc-col-center">{photo}</td>'
                f'<td class="inc-col-center">{html.escape(status)}</td>'
                f'<td class="inc-subdomain-webserver">{html.escape(webserver)}</td>'
                f'<td class="inc-subdomain-tech"{tech_title}>{html.escape(technologies)}</td>'
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

with open(page_path, "a") as handle:
    handle.write(summary + "\n")
    handle.write("</pre>\n")
    handle.write("    </div>\n")
    handle.write("</div>\n\n")
    handle.write("</body>\n")
    handle.write("</html>\n")
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
WHATWEB_UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36'
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

echo
echo -e "${BLUE}[*] Building active target list from public subdomains.${NC}"
f_active_build_targets "$SUBDOMAINS_FILE" "$TARGETS_FILE"

TARGET_COUNT=$(wc -l < "$TARGETS_FILE" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
TARGET_COUNT=${TARGET_COUNT:-0}

if [ "$TARGET_COUNT" -eq 0 ]; then
    f_active_die "No public subdomains found to probe."
fi

echo "[*] $TARGET_COUNT public hostnames queued for httpx."
echo
echo -e "${BLUE}[*] Running httpx.${NC}"

httpx -l "$TARGETS_FILE" -silent -random-agent -sc -title -server -td -cl -ip -cname -cdn \
    -fhr -maxr 2 \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -json -o "$HTTPX_JSONL" >/dev/null

echo
echo -e "${BLUE}[*] Parsing httpx results.${NC}"
f_active_parse_httpx "$HTTPX_JSONL" "$ALIVE_TSV" "$ACTIVE_TXT"

ALIVE_COUNT=$(wc -l < "$ALIVE_TSV" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
ALIVE_COUNT=${ALIVE_COUNT:-0}
URL_COUNT=$(wc -l < "$ACTIVE_TXT" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
URL_COUNT=${URL_COUNT:-0}

ALIVE_HOST_COUNT=$(awk -F '\t' 'NF >= 1 && $1 != "" { print $1 }' "$ALIVE_TSV" | sort -u | wc -l | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
ALIVE_HOST_COUNT=${ALIVE_HOST_COUNT:-0}

echo "[*] $ALIVE_COUNT alive responses across $ALIVE_HOST_COUNT hostnames ($URL_COUNT URLs for gowitness)."
echo

if [ "$URL_COUNT" -gt 0 ]; then
    echo
    echo -e "${BLUE}[*] Running whatweb on alive URLs.${NC}"
    whatweb -a 3 -i "$ACTIVE_TXT" \
        -U "$WHATWEB_UA" \
        --log-json="$WHATWEB_JSON" \
        --no-errors -q

    echo
    echo -e "${BLUE}[*] Running gowitness on alive URLs.${NC}"
    rm -rf "$SCREENSHOTS_DIR"/*
    gowitness scan file -f "$ACTIVE_TXT" \
        --driver gorod \
        --chrome-path "$CHROME_PATH" \
        --screenshot-path "$SCREENSHOTS_DIR" \
        --write-jsonl --write-jsonl-file "$GOWITNESS_JSONL" \
        --write-db --write-db-uri "sqlite://$GOWITNESS_DIR/gowitness.db"
    echo
else
    echo
    echo "[*] No alive URLs found. Skipping whatweb and gowitness."
    rm -f "$WHATWEB_JSON" "$GOWITNESS_JSONL" "$GOWITNESS_DIR/gowitness.db" 2>/dev/null
    rm -rf "$SCREENSHOTS_DIR"/*
    echo
fi

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

echo -e "${BLUE}[*] Updating subdomains report with Photo, Status, Web Server, and Technologies.${NC}"
f_active_write_report "$PRIVATE_FILE" "$SUBDOMAINS_FILE" "$GOWITNESS_JSONL" "$SCREENSHOTS_DIR" "$HTTPX_JSONL" "$WHATWEB_JSON" "$PAGE"

echo -e "${BLUE}[*] Updating Active report.${NC}"
f_active_write_active_page "$SUBDOMAINS_FILE" "$PRIVATE_FILE" "$ALIVE_TSV" "$HTTPX_JSONL" "$WHATWEB_JSON" "$ACTIVE_PAGE"
echo

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