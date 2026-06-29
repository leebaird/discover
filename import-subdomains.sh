#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

DISCOVER="${DISCOVER:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

BLUE="${BLUE:-\033[1;34m}"
YELLOW="${YELLOW:-\033[1;33m}"
RED="${RED:-\033[1;31m}"
NC="${NC:-\033[0m}"
SMALL="${SMALL:-========================================}"
MEDIUM="${MEDIUM:-==================================================================}"

if ! declare -f f_banner >/dev/null 2>&1; then
    DISCOVER_SOURCE_ONLY=1 source "$DISCOVER/discover.sh"
fi

f_subdomains_die(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $1${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
}

f_subdomains_read_report(){
    echo
    echo -n "Enter the location of your previous passive scan: "
    read -r DISCOVER_REPORT

    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

    if [ -z "$DISCOVER_REPORT" ] \
        || [ -f "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT" ] \
        || [ ! -r "$DISCOVER_REPORT" ] \
        || [ ! -x "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT/pages" ] \
        || [ ! -f "$DISCOVER_REPORT/pages/subdomains.htm" ]; then
        f_subdomains_die "Passive scan not found."
    fi
}

f_subdomains_read_import(){
    local domain="$1"
    local default="$DISCOVER_REPORT/tools/subdomains-import.tsv"

    echo
    echo "Supported imports:"
    echo "  - firefox (pull pinia/scans from Firefox profile)"
    echo "  - Firefox pinia/scans export (pinia-scans.json)"
    echo "  - Pentest-Tools JSON (pentest-tools-${domain}.json)"
    echo "  - Pentest-Tools text export (pentest-tools.txt)"
    echo "  - Tab-separated host/IP rows"
    echo
    echo -n "Enter import file or firefox (or press Enter for default): "
    read -r SUBDOMAINS_IMPORT

    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT#"${SUBDOMAINS_IMPORT%%[![:space:]]*}"}"
    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT%"${SUBDOMAINS_IMPORT##*[![:space:]]}"}"
    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT/#\~/$HOME}"

    if [ -z "$SUBDOMAINS_IMPORT" ]; then
        SUBDOMAINS_IMPORT="$default"
    fi

    SUBDOMAINS_IMPORT_LOWER="${SUBDOMAINS_IMPORT,,}"
    if [ "$SUBDOMAINS_IMPORT_LOWER" = "firefox" ] || [ "$SUBDOMAINS_IMPORT_LOWER" = "ff" ]; then
        SUBDOMAINS_IMPORT="firefox"
        return 0
    fi

    if [ ! -f "$SUBDOMAINS_IMPORT" ]; then
        mkdir -p "$DISCOVER_REPORT/tools"
        cat > "$SUBDOMAINS_IMPORT" <<'EOF'
# Manual subdomains — tab-separated: Subdomain, IP (IP optional)
# Add one host per line, then re-run Import subdomains.
EOF
        f_subdomains_die "Import file created. Add rows or point to a Pentest-Tools export, then run Import subdomains again."
    fi

    if [ ! -s "$SUBDOMAINS_IMPORT" ] || ! grep -qv '^[[:space:]]*#' "$SUBDOMAINS_IMPORT" 2>/dev/null; then
        f_subdomains_die "Import file is empty. Add data, then run Import subdomains again."
    fi
}

f_subdomains_require_snappy(){
    if python3 -c 'import cramjam' 2>/dev/null || python3 -c 'import snappy' 2>/dev/null; then
        return 0
    fi

    echo "[!] Snappy decoder not found (needed for Firefox localStorage)."
    echo "[*] Install one of:"
    echo "    pip install cramjam --break-system-packages"
    echo "    pip install python-snappy --break-system-packages"
    return 1
}

f_subdomains_extract_firefox_pinia(){
    local outfile=$1

    f_subdomains_require_snappy || return 1

    python3 - "$outfile" <<'PY'
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

outfile = Path(sys.argv[1])
roots = [
    Path.home() / "snap/firefox/common/.mozilla/firefox",
    Path.home() / ".mozilla/firefox",
]

def find_ls_db():
    matches = []
    for root in roots:
        if not root.is_dir():
            continue
        pattern = "storage/default/https+++pentest-tools.com/ls/data.sqlite"
        for profile in root.iterdir():
            if not profile.is_dir() or profile.name in {"Crash Reports", "Pending Pings", "Profile Groups"}:
                continue
            candidate = profile / pattern
            if candidate.is_file():
                matches.append(candidate)
    if not matches:
        return None
    return max(matches, key=lambda path: path.stat().st_mtime)

def decode_value(blob, conversion_type, compression_type):
    if compression_type == 1:
        try:
            import cramjam
            data = bytes(cramjam.snappy.decompress_raw(blob))
        except ImportError:
            import snappy
            data = snappy.decompress(blob)
    else:
        data = blob

    if conversion_type == 0:
        return data.decode("utf-16-be")
    return data.decode("utf-8")

source = find_ls_db()
if not source:
    print("Firefox profile with pentest-tools.com localStorage not found", file=sys.stderr)
    print("Run a free Subdomain Finder scan in Firefox first", file=sys.stderr)
    sys.exit(1)

tmpdir = tempfile.mkdtemp(prefix="discover-ff-ls-")
try:
    copied = Path(tmpdir) / "data.sqlite"
    shutil.copy2(source, copied)
    conn = sqlite3.connect(f"file:{copied}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT value, conversion_type, compression_type FROM data WHERE key = ?",
            ("pinia/scans",),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        print("pinia/scans not found in Firefox localStorage", file=sys.stderr)
        print(f"Profile: {source.parents[3]}", file=sys.stderr)
        sys.exit(1)

    value, conversion_type, compression_type = row
    try:
        text = decode_value(value, conversion_type, compression_type)
    except Exception as exc:
        print(f"failed to decode pinia/scans: {exc}", file=sys.stderr)
        sys.exit(1)

    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(text)
    print(f"[*] Firefox profile: {source.parents[3]}", file=os.sys.stderr)
    print(f"[*] pinia/scans: {len(text)} bytes from {source}", file=os.sys.stderr)
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
PY
}

f_subdomains_write_report(){
    local PRIVATE_FILE="$1"
    local PUBLIC_FILE="$2"
    local PAGE="$3"

    cp "$DISCOVER/report/pages/subdomains.htm" "$PAGE"

    python3 - "$PAGE" "$PRIVATE_FILE" "$PUBLIC_FILE" <<'PY'
import csv
import html
import os
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
        while len(row) < 2:
            row.append("")
        subdomain, ipaddr = row[0].strip(), row[1].strip()
    else:
        parts = raw.split()
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0], ""
        if IPV4_RE.match(parts[-1]):
            return " ".join(parts[:-1]), parts[-1]
        return parts[0], parts[1] if len(parts) > 1 else ""

    if not subdomain:
        return None
    return subdomain, ipaddr

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

def build_table(rows, empty_message, ip_header="IP Address"):
    lines = [
        '        <table class="table table-bordered inc-data-table">',
        "            <thead>",
        "                <tr>",
        '                    <th scope="col" class="inc-sortable">Subdomain</th>',
        f'                    <th scope="col" class="inc-sortable">{html.escape(ip_header)}</th>',
        "                </tr>",
        "            </thead>",
        "            <tbody>",
    ]

    if rows:
        for subdomain, ipaddr in rows:
            lines.append(
                "                <tr>"
                f'<td class="inc-col-domain">{html.escape(subdomain)}</td>'
                f"<td>{html.escape(ipaddr)}</td>"
                "</tr>"
            )
    else:
        lines.append(f'                <tr><td colspan="2">{html.escape(empty_message)}</td></tr>')

    lines.extend(
        [
            "            </tbody>",
            "        </table>",
        ]
    )
    return lines

page_path, private_path, public_path = sys.argv[1:4]
private_rows = load_rows(private_path)
public_rows = [
    row for row in load_rows(public_path) if not is_private_ip(row[1])
]

out = []
if private_rows:
    out.append('    <div class="inc-content-frame inc-content-frame--table">')
    out.extend(build_table(private_rows, "No private subdomains found.", "Private IP Address"))
    out.append("    </div>")

if public_rows or not private_rows:
    out.append('    <div class="inc-content-frame inc-content-frame--table">')
    if public_rows:
        out.extend(build_table(public_rows, "No data found."))
    else:
        out.extend(build_table([], "No data found."))
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

f_subdomains_update_report(){
    local PRIVATE_FILE="$1"
    local SUBDOMAINS_FILE="$2"
    local REPORT_PAGE="$3"

    [ -f "$REPORT_PAGE" ] || return 0

    python3 - "$REPORT_PAGE" "$PRIVATE_FILE" "$SUBDOMAINS_FILE" <<'PY'
import re
import subprocess
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
private_path = Path(sys.argv[2])
subdomains_path = Path(sys.argv[3])
separator = "=" * 127

NEXT_SECTION = re.compile(
    r"^(Private Subdomains|Subdomains|Registered Domains|Whois Domain|Whois IP|Creds|Names \()"
)


def format_rows(path):
    if not path.is_file() or path.stat().st_size == 0:
        return []
    result = subprocess.run(
        ["column", "-t", "-s", "\t"],
        input=path.read_text(),
        text=True,
        capture_output=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def replace_section(lines, section_name, count, body_lines):
    header = f"{section_name} ({count})"
    for i, line in enumerate(lines):
        if re.fullmatch(rf"{re.escape(section_name)} \(\d+\)", line):
            j = i + 2
            while j < len(lines) and not NEXT_SECTION.match(lines[j]):
                j += 1
            block = [header, separator]
            if body_lines:
                block.extend(body_lines)
                block.append("")
            lines[i:j] = block
            return True
    return False


def update_summary_count(lines, label, count):
    width = 22
    pattern = re.compile(rf"^{re.escape(label)}\s+\d+$")
    for i, line in enumerate(lines):
        if pattern.match(line):
            lines[i] = f"{label:<{width}}{count}"
            return True
    return False


text = report_path.read_text()
marker_open = '<pre class="inc-pre">\n'
marker_close = "</pre>"
open_at = text.find(marker_open)
if open_at == -1:
    sys.exit(0)

body_start = open_at + len(marker_open)
close_at = text.find(marker_close, body_start)
if close_at == -1:
    sys.exit(0)

prefix = text[:body_start]
suffix = text[close_at:]
lines = text[body_start:close_at].splitlines()

private_rows = format_rows(private_path)
subdomain_rows = format_rows(subdomains_path)
private_count = len(private_rows)
subdomain_count = len(subdomain_rows)

update_summary_count(lines, "Private Subdomains", private_count)
update_summary_count(lines, "Subdomains", subdomain_count)
replace_section(lines, "Private Subdomains", private_count, private_rows)
replace_section(lines, "Subdomains", subdomain_count, subdomain_rows)

report_path.write_text(prefix + "\n".join(lines) + suffix)
PY
}

clear
f_banner

echo -e "${BLUE}Import subdomains.${NC}"

for CMD in python3 dig; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        f_subdomains_die "$CMD is not installed. Run Discover update to install dependencies."
    fi
done

f_subdomains_read_report

REPORT_DOMAIN=$(basename "$DISCOVER_REPORT")
TOOLS_DIR="$DISCOVER_REPORT/tools"
mkdir -p "$TOOLS_DIR"

f_subdomains_read_import "$REPORT_DOMAIN"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

SUBDOMAINS_SOURCE="$SUBDOMAINS_IMPORT"
if [ "$SUBDOMAINS_IMPORT" = "firefox" ]; then
    SUBDOMAINS_IMPORT="$TMPDIR/pinia-scans.json"
    echo
    echo "[*] Reading pinia/scans from Firefox localStorage"
    echo
    if ! f_subdomains_extract_firefox_pinia "$SUBDOMAINS_IMPORT"; then
        f_subdomains_die "Failed to read pinia/scans from Firefox."
    fi
    SUBDOMAINS_SOURCE="Firefox localStorage (pinia/scans)"
fi

MERGED="$TMPDIR/subdomains.tsv"
EXISTING="$TOOLS_DIR/subdomains"

if ! python3 - "$SUBDOMAINS_IMPORT" "$REPORT_DOMAIN" "$MERGED" "$EXISTING" 2>"$TMPDIR/import.err" <<'PY'
import csv
import json
import re
import sys
from pathlib import Path

import_path = Path(sys.argv[1])
domain = sys.argv[2].strip().lower()
out_path = Path(sys.argv[3])
existing_path = Path(sys.argv[4])

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
store = {}


def normalize_host(value):
    value = str(value or "").strip().lower()
    if value.startswith("www."):
        value = value[4:]
    return value


def normalize_ip(value):
    value = str(value or "").strip()
    return value if IPV4_RE.match(value) else ""


def upsert(host, ip="", prefer=False):
    host = normalize_host(host)
    if not host or not HOST_RE.fullmatch(host):
        return
    ip = normalize_ip(ip)
    row = store.setdefault(host, {"host": host, "ip": ""})
    if ip and (prefer or not row["ip"]):
        row["ip"] = ip


def rows_from_subdomain_objects(rows):
    for row in rows:
        if not isinstance(row, dict):
            continue
        upsert(row.get("hostname") or row.get("host"), row.get("ip_address") or row.get("ip"), prefer=True)


def load_existing(path):
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line:
            continue
        if "\t" in line:
            host, ip = (line.split("\t", 1) + [""])[:2]
        else:
            parts = line.split()
            if not parts:
                continue
            if len(parts) == 1:
                host, ip = parts[0], ""
            elif IPV4_RE.match(parts[-1]):
                host, ip = " ".join(parts[:-1]), parts[-1]
            else:
                host, ip = parts[0], parts[1]
        upsert(host, ip)


def load_manual(path):
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            host, ip = (line.split("\t", 1) + [""])[:2]
        else:
            parts = line.split()
            if not parts:
                continue
            if len(parts) >= 2 and IPV4_RE.match(parts[-1]):
                host, ip = " ".join(parts[:-1]), parts[-1]
            else:
                host, ip = parts[0], parts[1] if len(parts) > 1 else ""
        upsert(host, ip, prefer=True)


def load_pentest_text(path):
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("=", "#", "Pentest-Tools", "Scan id", "Total", "Resolved", "Unresolved", "Subdomains")):
            continue
        if re.search(r"(?i)subdomain|hostname", line):
            continue
        if "\t" in line:
            host, ip = (line.split("\t", 1) + [""])[:2]
        else:
            parts = line.split()
            if not parts:
                continue
            host = parts[0]
            ip = parts[-1] if len(parts) >= 2 and IPV4_RE.match(parts[-1]) else ""
        upsert(host, ip, prefer=True)


def rows_from_output(output):
    if isinstance(output, list):
        return output
    if not isinstance(output, dict):
        return []
    if output.get("output_type") == "subdomain_list":
        return (output.get("output_data") or {}).get("subdomains") or []
    if output.get("type") == "subdomains":
        return (output.get("data") or {}).get("subdomains") or []
    if isinstance(output.get("subdomains"), list):
        return output["subdomains"]
    data = output.get("data")
    if isinstance(data, dict) and isinstance(data.get("subdomains"), list):
        return data["subdomains"]
    return []


def load_pinia(path):
    payload = json.loads(path.read_text())
    scans = payload
    if isinstance(payload, dict):
        if isinstance(payload.get("scans"), list):
            scans = payload["scans"]
        elif isinstance(payload.get("data"), list):
            scans = payload["data"]
        elif "id" in payload:
            scans = [payload]
    if not isinstance(scans, list):
        raise SystemExit("pinia/scans export must be a JSON array")

    selected = None
    for scan in scans:
        if not isinstance(scan, dict):
            continue
        target = scan.get("target") or {}
        initial = ""
        if isinstance(target, dict):
            initial = str(target.get("initial") or "").strip().lower()
        elif isinstance(target, str):
            initial = target.strip().lower()
        if domain and initial == domain:
            selected = scan
            break

    if not selected:
        finished = [
            scan for scan in scans
            if isinstance(scan, dict)
            and (scan.get("status") == "finished" or (scan.get("info") or {}).get("status_name") == "finished")
            and rows_from_output(scan.get("output") or [])
        ]
        if len(finished) == 1:
            selected = finished[0]
        elif len(scans) == 1 and isinstance(scans[0], dict):
            selected = scans[0]

    if not selected:
        raise SystemExit(f"no matching finished scan found for {domain or 'requested domain'}")

    rows_from_subdomain_objects(rows_from_output(selected.get("output") or []))


def load_pentest_json(path):
    payload = json.loads(path.read_text())
    if isinstance(payload, dict) and "output" in payload:
        payload = payload["output"]
    rows_from_subdomain_objects(rows_from_output(payload))


name = import_path.name.lower()
if name.endswith(".json"):
    peek = json.loads(import_path.read_text())
    if isinstance(peek, list) or (isinstance(peek, dict) and "scans" in peek):
        load_pinia(import_path)
    else:
        load_pentest_json(import_path)
elif "pinia" in name or "scans" in name:
    load_pinia(import_path)
elif name.startswith("pentest-tools") and name.endswith(".txt"):
    load_pentest_text(import_path)
else:
    load_manual(import_path)

load_existing(existing_path)

if not store:
    raise SystemExit("no subdomains found in import")

with out_path.open("w", newline="") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    for row in sorted(store.values(), key=lambda item: item["host"]):
        writer.writerow([row["host"], row["ip"]])
PY
then
    sed -n '1,6p' "$TMPDIR/import.err" >&2
    f_subdomains_die "Failed to parse import file."
fi

RESOLVED="$TMPDIR/subdomains-resolved.tsv"
cp "$MERGED" "$RESOLVED"

MISSING=$(awk -F '\t' 'NF < 2 || $2 == "" { count++ } END { print count + 0 }' "$MERGED")
DIG_RESOLVED=0

if [ "$MISSING" -gt 0 ]; then
    > "$RESOLVED"
    CURRENT=0

    echo -e "${BLUE}[*] Resolving $MISSING subdomains without IPs using dig.${NC}"
    while IFS=$'\t' read -r HOST IP; do
        HOST="${HOST//$'\r'/}"
        IP="${IP//$'\r'/}"
        if [ -z "$IP" ]; then
            ((CURRENT++))
            echo -ne "\r    $CURRENT of $MISSING"
            IP=$(dig +timeout=2 +tries=1 +short "$HOST" 2>/dev/null | grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -n 1)
            if [ "$IP" = "1.1.1.1" ] || [ "$IP" = "127.0.0.53" ]; then
                IP=""
            fi
            if [ -n "$IP" ]; then
                ((DIG_RESOLVED++))
            fi
        fi
        if [ -n "$IP" ]; then
            printf '%s\t%s\n' "$HOST" "$IP" >> "$RESOLVED"
        fi
    done < "$MERGED"
    echo
fi

FILTERED="$TMPDIR/subdomains-filtered.tsv"
awk -F '\t' 'NF >= 2 && $2 != "" { print }' "$RESOLVED" > "$FILTERED"

IMPORTED_COUNT=$(wc -l < "$MERGED" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
FINAL_COUNT=$(wc -l < "$FILTERED" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
OMITTED=$((IMPORTED_COUNT - FINAL_COUNT))

if [ "$FINAL_COUNT" -eq 0 ]; then
    f_subdomains_die "No subdomains with resolvable IPs found."
fi

SUBDOMAINS_FILE="$TOOLS_DIR/subdomains"
PRIVATE_FILE="$TOOLS_DIR/private-subs"
PAGE="$DISCOVER_REPORT/pages/subdomains.htm"
REPORT_PAGE="$DISCOVER_REPORT/pages/report.htm"

cp "$FILTERED" "$SUBDOMAINS_FILE"
awk -F'\t' 'NF >= 2 && $2 ~ /^10\./ { print }' "$SUBDOMAINS_FILE" > "$PRIVATE_FILE"
awk -F'\t' 'NF >= 2 && $2 ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./ { print }' "$SUBDOMAINS_FILE" >> "$PRIVATE_FILE"
awk -F'\t' 'NF >= 2 && $2 ~ /^192\.168\./ { print }' "$SUBDOMAINS_FILE" >> "$PRIVATE_FILE"
sort -u -o "$PRIVATE_FILE" "$PRIVATE_FILE"

f_subdomains_write_report "$PRIVATE_FILE" "$SUBDOMAINS_FILE" "$PAGE"
f_subdomains_update_report "$PRIVATE_FILE" "$SUBDOMAINS_FILE" "$REPORT_PAGE"

PRIVATE_COUNT=$(wc -l < "$PRIVATE_FILE" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

echo "$MEDIUM"
echo
echo "[*] Subdomains import complete."
echo "[*] $FINAL_COUNT subdomains in report ($PRIVATE_COUNT private)."
if [ "$MISSING" -gt 0 ]; then
    echo "[*] dig resolved $DIG_RESOLVED of $MISSING subdomains without IPs."
fi
if [ "$OMITTED" -gt 0 ]; then
    echo "[*] $OMITTED subdomains without IPs were omitted from the report."
fi
echo
echo -e "Merged data saved to ${YELLOW}$SUBDOMAINS_FILE${NC}"
echo -e "Import source: ${YELLOW}$SUBDOMAINS_SOURCE${NC}"
echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
echo