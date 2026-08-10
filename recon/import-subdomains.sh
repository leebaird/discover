#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)
#
# Fail fast: any unexpected command failure prints [!] and exits.

set -euo pipefail

# Colors / separators when not launched from Discover menu.
RED=${RED:-'\033[1;31m'}
YELLOW=${YELLOW:-'\033[1;33m'}
BLUE=${BLUE:-'\033[1;34m'}
NC=${NC:-'\033[0m'}
SMALL=${SMALL:-'========================================'}
MEDIUM=${MEDIUM:-'=================================================================='}

SUBS_JSON=0
SUBS_QUIET=0
SUBS_NONINTERACTIVE=0
SUBS_RUN_ACTIVE=0
CLI_REPORT=""
CLI_MODE=""
CLI_IMPORT=""

f_subdomains_usage(){
    echo "Usage: import-subdomains.sh --report <path> --mode existing|team-csv --import <path|firefox> [--run-active] [--json]"
    echo "  Interactive when --report is omitted. team-csv = CSV list; existing = Firefox/Pentest-Tools/TSV."
}

f_subdomains_json_fail(){
    local msg="$1"
    if [ "$SUBS_JSON" -eq 1 ]; then
        python3 -c 'import json,sys; print(json.dumps({"ok":False,"error":sys.argv[1]}))' "$msg" 2>/dev/null || \
            printf '{"ok":false,"error":%s}\n' "$(printf '%s' "$msg" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
    fi
}

f_subdomains_die(){
    # Disable ERR trap so exit 1 does not re-enter.
    trap - ERR
    f_subdomains_json_fail "$1"
    if [ "$SUBS_JSON" -eq 0 ]; then
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        echo -e "${RED}[!] $1${NC}"
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        [ "$SUBS_NONINTERACTIVE" -eq 0 ] && sleep 2
    fi
    exit 1
}

f_subdomains_on_err(){
    local line="${1:-?}"
    f_subdomains_die "Command failed (line ${line})."
}

trap 'f_subdomains_on_err $LINENO' ERR

f_subdomains_validate_report(){
    DISCOVER_REPORT="${DISCOVER_REPORT//$'\r'/}"
    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

    if [ -f "$DISCOVER_REPORT" ]; then
        case "$DISCOVER_REPORT" in
            */pages/*)
                DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")/.." && pwd)" || f_subdomains_die "Incorrect file path."
                ;;
            *)
                DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")" && pwd)" || f_subdomains_die "Incorrect file path."
                ;;
        esac
    fi

    # Empty, missing, not a dir, unreadable, or not a passive report → same message.
    if [ -z "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT" ] \
        || [ ! -r "$DISCOVER_REPORT" ] \
        || [ ! -x "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT/pages" ] \
        || [ ! -f "$DISCOVER_REPORT/pages/subdomains.htm" ]; then
        f_subdomains_die "Incorrect file path."
    fi
    DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)" || f_subdomains_die "Incorrect file path."
}

f_subdomains_read_report(){
    echo
    echo -n "Enter the location of a previous Discover scan: "
    read -r DISCOVER_REPORT || f_subdomains_die "Incorrect file path."
    f_subdomains_validate_report
}

f_subdomains_set_import_path(){
    local domain="$1"
    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT//$'\r'/}"
    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT#"${SUBDOMAINS_IMPORT%%[![:space:]]*}"}"
    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT%"${SUBDOMAINS_IMPORT##*[![:space:]]}"}"
    SUBDOMAINS_IMPORT="${SUBDOMAINS_IMPORT/#\~/$HOME}"

    if [ -z "$SUBDOMAINS_IMPORT" ]; then
        f_subdomains_die "Incorrect file path."
    fi

    SUBDOMAINS_IMPORT_LOWER="${SUBDOMAINS_IMPORT,,}"
    if [ "$SUBDOMAINS_IMPORT_LOWER" = "firefox" ] || [ "$SUBDOMAINS_IMPORT_LOWER" = "ff" ]; then
        SUBDOMAINS_IMPORT="firefox"
        return 0
    fi

    # Must be an existing readable non-empty file (not a directory).
    if [ -d "$SUBDOMAINS_IMPORT" ] \
        || [ ! -f "$SUBDOMAINS_IMPORT" ] \
        || [ ! -r "$SUBDOMAINS_IMPORT" ]; then
        f_subdomains_die "Incorrect file path."
    fi
    if [ ! -s "$SUBDOMAINS_IMPORT" ] || ! grep -qv '^[[:space:]]*#' "$SUBDOMAINS_IMPORT" 2>/dev/null; then
        f_subdomains_die "Incorrect file path."
    fi
    # Silence unused domain hint in noninteractive path.
    : "${domain:=}"
}

f_subdomains_read_import(){
    local domain="$1"

    echo
    echo "Supported imports:"
    echo "  - firefox (pull pinia/scans from Firefox profile)"
    echo "  - Firefox pinia/scans export (pinia-scans.json)"
    echo "  - Pentest-Tools JSON (pentest-tools-${domain}.json)"
    echo "  - Pentest-Tools text export (pentest-tools.txt)"
    echo "  - Tab-separated host/IP rows (e.g. tools/subdomains-import.tsv)"
    echo
    echo -n "Location of file to import: "
    read -r SUBDOMAINS_IMPORT || f_subdomains_die "Incorrect file path."
    f_subdomains_set_import_path "$domain"
}

f_subdomains_write_audit_fallback(){
    local action="$1"
    if declare -F f_audit_log >/dev/null 2>&1; then
        f_audit_log "$DISCOVER_REPORT" "$action" || true
        return 0
    fi
    mkdir -p "$DISCOVER_REPORT/tools/audit" 2>/dev/null || return 0
    local ts op
    ts=$(date -u +"%m-%d-%Y - %H:%M Z")
    op="Operator"
    if [ -f "$HOME/.discover/operator-name" ]; then
        op=$(tr -d '[:space:]' < "$HOME/.discover/operator-name" 2>/dev/null || true)
        [ -n "$op" ] || op="Operator"
    fi
    case "$action" in
        *.) ;;
        *) action="${action}." ;;
    esac
    printf '%s | %s | - | %s\n' "$ts" "$op" "$action" >> "$DISCOVER_REPORT/tools/audit/log.txt" 2>/dev/null || true
}

f_subdomains_rebuild_audit(){
    local root="${DISCOVER:-}"
    if [ -z "$root" ] || [ ! -f "$root/recon/audit-build.py" ]; then
        root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
    if [ -f "$root/recon/audit-build.py" ] && [ -f "$root/report/pages/audit.htm" ]; then
        python3 "$root/recon/audit-build.py" "$DISCOVER_REPORT" "$root/report/pages/audit.htm" >/dev/null 2>&1 || true
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

# Unique public IPv4 list + pages/hosts.htm from tools/subdomains.
f_subdomains_write_hosts_page(){
    local subdomains_file="$1"
    local public_ips_file="$2"
    local page="$3"
    local template="${DISCOVER:-}/report/pages/hosts.htm"

    python3 - "$subdomains_file" "$public_ips_file" <<'PY'
import csv
import re
import sys
from pathlib import Path

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_private(ip: str) -> bool:
    if not IPV4_RE.match(ip):
        return True
    o = [int(x) for x in ip.split(".")]
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    return False

sub_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
ips = set()
if sub_path.is_file():
    for raw in sub_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            parts = line.split("\t")
            ip = parts[1].strip() if len(parts) > 1 else ""
        else:
            parts = line.split()
            ip = parts[-1] if len(parts) >= 2 and IPV4_RE.match(parts[-1]) else ""
        if ip and not is_private(ip):
            ips.add(ip)

def ip_key(ip: str):
    return tuple(int(x) for x in ip.split("."))

out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("w", encoding="utf-8") as handle:
    for ip in sorted(ips, key=ip_key):
        handle.write(ip + "\n")
PY

    if [ ! -f "$template" ]; then
        echo "[!] hosts.htm template missing — skip Hosts page."
        return 0
    fi
    cp -f "$template" "$page"
    if [ -s "$public_ips_file" ]; then
        cat "$public_ips_file" >> "$page"
    else
        echo "No data found." >> "$page"
    fi
    {
        echo "</pre>"
        echo "    </div>"
        echo "</div>"
        echo
        echo "</body>"
        echo "</html>"
    } >> "$page"
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

def build_table(rows, empty_message, ip_header="IP Address"):
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
        '<script src="../assets/javascript/inc-subdomains-filter.js?v=17"></script>',
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


def plain_line(line):
    return re.sub(r"<[^>]+>", "", line)


def report_heading(text):
    return f'<span class="inc-report-heading">{text}</span>'


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
    header = report_heading(f"{section_name} ({count})")
    for i, line in enumerate(lines):
        if re.fullmatch(rf"{re.escape(section_name)} \(\d+\)", plain_line(line)):
            j = i + 2
            while j < len(lines) and not NEXT_SECTION.match(plain_line(lines[j])):
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

# Parse optional CLI args (non-interactive / statusd).
while [ $# -gt 0 ]; do
    case "$1" in
        --report)
            CLI_REPORT="${2:-}"
            shift 2
            ;;
        --mode)
            CLI_MODE="${2:-}"
            shift 2
            ;;
        --import|--file|--source)
            CLI_IMPORT="${2:-}"
            shift 2
            ;;
        --run-active)
            SUBS_RUN_ACTIVE=1
            shift
            ;;
        --json)
            SUBS_JSON=1
            SUBS_NONINTERACTIVE=1
            shift
            ;;
        --quiet|-q)
            SUBS_QUIET=1
            shift
            ;;
        -h|--help)
            f_subdomains_usage
            exit 0
            ;;
        *)
            f_subdomains_die "Unknown option: $1"
            ;;
    esac
done

if [ -n "$CLI_REPORT" ]; then
    SUBS_NONINTERACTIVE=1
fi

# Discover install root (templates / categorizer). Prefer env from menu; else repo parent of recon/.
if [ -z "${DISCOVER:-}" ] || [ ! -d "${DISCOVER:-/}/report/pages" ]; then
    _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -d "$_script_dir/../report/pages" ]; then
        DISCOVER="$(cd "$_script_dir/.." && pwd)"
    fi
    unset _script_dir
fi
if [ -z "${DISCOVER:-}" ] || [ ! -d "${DISCOVER}/report/pages" ]; then
    f_subdomains_die "DISCOVER install root not found (set DISCOVER or run from Discover menu)."
fi
export DISCOVER

if ! declare -F f_banner >/dev/null 2>&1; then
    f_banner(){ echo; }
fi

if [ "$SUBS_NONINTERACTIVE" -eq 0 ]; then
    clear 2>/dev/null || true
    f_banner
    echo -e "${BLUE}Import subdomains.${NC}"
    echo
    echo "1. Existing sources (Firefox / Pentest-Tools / TSV)"
    echo "2. CSV list (subdomain, IPv4, category)"
    echo
    echo -n "Choice: "
    # Do not treat EOF alone as "command failed" under set -e; die with a clear message.
    if ! read -r IMPORT_CHOICE; then
        f_subdomains_die "No choice entered. Enter 1 or 2."
    fi
    IMPORT_CHOICE="${IMPORT_CHOICE//$'\r'/}"
    IMPORT_CHOICE="${IMPORT_CHOICE#"${IMPORT_CHOICE%%[![:space:]]*}"}"
    IMPORT_CHOICE="${IMPORT_CHOICE%"${IMPORT_CHOICE##*[![:space:]]}"}"

    case "$IMPORT_CHOICE" in
        1) IMPORT_MODE="existing" ;;
        2) IMPORT_MODE="team-csv" ;;
        "") f_subdomains_die "No choice entered. Enter 1 or 2." ;;
        *) f_subdomains_die "Invalid choice. Enter 1 or 2." ;;
    esac
else
    case "${CLI_MODE,,}" in
        1|existing|exist|firefox|tsv|pt|pentest) IMPORT_MODE="existing" ;;
        2|team-csv|csv|list) IMPORT_MODE="team-csv" ;;
        "") f_subdomains_die "Non-interactive import requires --mode existing|team-csv." ;;
        *) f_subdomains_die "Invalid --mode. Use existing or team-csv." ;;
    esac
fi

for CMD in python3 dig; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        f_subdomains_die "$CMD is not installed. Run Discover update to install dependencies."
    fi
done

if [ "$SUBS_NONINTERACTIVE" -eq 1 ]; then
    DISCOVER_REPORT="$CLI_REPORT"
    f_subdomains_validate_report
else
    f_subdomains_read_report
fi

REPORT_DOMAIN=$(basename "$DISCOVER_REPORT")
TOOLS_DIR="$DISCOVER_REPORT/tools"
mkdir -p "$TOOLS_DIR" || f_subdomains_die "Could not create tools directory: $TOOLS_DIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

MERGED="$TMPDIR/subdomains.tsv"
EXISTING="$TOOLS_DIR/subdomains"
BATCH_HOSTS="$TOOLS_DIR/import-batch-hosts.txt"
CSV_CATS="$TMPDIR/csv-categories.tsv"

# ---------------------------------------------------------------------------
# Choice 2: CSV list (subdomain, IPv4, category)
# ---------------------------------------------------------------------------
if [ "$IMPORT_MODE" = "team-csv" ]; then
    if [ "$SUBS_NONINTERACTIVE" -eq 1 ]; then
        TEAM_CSV="${CLI_IMPORT:-}"
        TEAM_CSV="${TEAM_CSV//$'\r'/}"
        TEAM_CSV="${TEAM_CSV#"${TEAM_CSV%%[![:space:]]*}"}"
        TEAM_CSV="${TEAM_CSV%"${TEAM_CSV##*[![:space:]]}"}"
        TEAM_CSV="${TEAM_CSV/#\~/$HOME}"
        if [ -z "$TEAM_CSV" ] \
            || [ -d "$TEAM_CSV" ] \
            || [ ! -f "$TEAM_CSV" ] \
            || [ ! -r "$TEAM_CSV" ] \
            || [ ! -s "$TEAM_CSV" ]; then
            f_subdomains_die "Incorrect file path."
        fi
    else
        echo
        echo "CSV format: subdomain,ip,category  (header optional; one IPv4 per host)"
        echo "Category: Discover rules first; CSV used only when Discover has no match."
        echo "Hosts already in the report are skipped (not re-imported)."
        echo "Discover category patterns are never modified."
        echo
        echo -n "Enter path to CSV list: "
        read -r TEAM_CSV || f_subdomains_die "Incorrect file path."
        TEAM_CSV="${TEAM_CSV#"${TEAM_CSV%%[![:space:]]*}"}"
        TEAM_CSV="${TEAM_CSV%"${TEAM_CSV##*[![:space:]]}"}"
        TEAM_CSV="${TEAM_CSV/#\~/$HOME}"
        if [ -z "$TEAM_CSV" ] \
            || [ -d "$TEAM_CSV" ] \
            || [ ! -f "$TEAM_CSV" ] \
            || [ ! -r "$TEAM_CSV" ] \
            || [ ! -s "$TEAM_CSV" ]; then
            f_subdomains_die "Incorrect file path."
        fi
    fi

    SUBDOMAINS_SOURCE="$TEAM_CSV"
    SKIP_STATS="$TMPDIR/team-csv-skip.stats"

    if ! python3 - "$TEAM_CSV" "$REPORT_DOMAIN" "$MERGED" "$EXISTING" "$CSV_CATS" "$BATCH_HOSTS" "$SKIP_STATS" \
        >"$TMPDIR/import.out" 2>"$TMPDIR/import.err" <<'PY'
import csv
import re
import sys
from pathlib import Path

import_path = Path(sys.argv[1])
_domain = sys.argv[2].strip().lower()
out_path = Path(sys.argv[3])
existing_path = Path(sys.argv[4])
cats_path = Path(sys.argv[5])
batch_path = Path(sys.argv[6])
stats_path = Path(sys.argv[7])

IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
HOST_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
store = {}  # host -> {host, ip, csv_category}
existing_hosts = set()
new_csv_hosts = set()
skipped_existing = 0
csv_rows_seen = 0


def normalize_host(value):
    value = str(value or "").strip().lower()
    if value.startswith("www."):
        value = value[4:]
    return value


def normalize_ip(value):
    value = str(value or "").strip()
    if not value:
        return ""
    if not IPV4_RE.match(value):
        return ""
    parts = [int(x) for x in value.split(".")]
    if any(p > 255 for p in parts):
        return ""
    return value


def upsert_existing(host, ip=""):
    """Keep existing report rows as-is (IP/category not overwritten by CSV)."""
    host = normalize_host(host)
    if not host or not HOST_RE.fullmatch(host):
        return
    existing_hosts.add(host)
    ip = normalize_ip(ip)
    row = store.setdefault(host, {"host": host, "ip": "", "csv_category": ""})
    if ip and not row["ip"]:
        row["ip"] = ip
    elif ip:
        row["ip"] = ip  # keep report IP as currently stored


def add_new_from_csv(host, ip="", csv_category=""):
    global skipped_existing, csv_rows_seen
    host = normalize_host(host)
    if not host or not HOST_RE.fullmatch(host):
        return
    csv_rows_seen += 1
    # Already in the engagement report → do not import.
    if host in existing_hosts:
        skipped_existing += 1
        return
    ip = normalize_ip(ip)
    row = store.setdefault(host, {"host": host, "ip": "", "csv_category": ""})
    if ip:
        row["ip"] = ip
    if csv_category:
        row["csv_category"] = csv_category.strip()
    new_csv_hosts.add(host)


# Existing inventory first (authoritative for "already in report")
if existing_path.is_file():
    for raw in existing_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            parts = line.split("\t")
            host = parts[0] if parts else ""
            ip = parts[1] if len(parts) > 1 else ""
        else:
            parts = line.split()
            if not parts:
                continue
            host, ip = parts[0], ""
            if len(parts) >= 2 and IPV4_RE.match(parts[-1]):
                host, ip = " ".join(parts[:-1]), parts[-1]
            elif len(parts) >= 2:
                host, ip = parts[0], parts[1]
        upsert_existing(host, ip)


def looks_like_header(cells):
    joined = " ".join(c.lower() for c in cells)
    return "subdomain" in joined or "hostname" in joined or (
        cells and "host" in cells[0].lower() and len(cells) > 1
    )


text = import_path.read_text(encoding="utf-8", errors="replace")
sample = ""
for raw in text.splitlines():
    if raw.strip() and not raw.strip().startswith("#"):
        sample = raw
        break
delim = "," if sample.count(",") >= sample.count("\t") else "\t"

reader = csv.reader(text.splitlines(), delimiter=delim)
first = True
for cells in reader:
    if not cells:
        continue
    cells = [c.strip() for c in cells]
    if not any(cells):
        continue
    if cells[0].startswith("#"):
        continue
    if first:
        first = False
        if looks_like_header(cells):
            continue
    while len(cells) < 3:
        cells.append("")
    host, ip, cat = cells[0], cells[1], cells[2]
    if ip and not IPV4_RE.match(ip) and not cat:
        cat, ip = ip, ""
    add_new_from_csv(host, ip, cat)

if not new_csv_hosts and skipped_existing == 0:
    raise SystemExit("no subdomains found in CSV list")
if not new_csv_hosts and skipped_existing > 0:
    raise SystemExit(
        f"all {skipped_existing} CSV host(s) already in the report — nothing new to import"
    )

with out_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    for row in sorted(store.values(), key=lambda item: item["host"]):
        writer.writerow([row["host"], row["ip"]])

with cats_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    for host in sorted(new_csv_hosts):
        writer.writerow([host, store[host].get("csv_category") or ""])

with batch_path.open("w", encoding="utf-8") as handle:
    for host in sorted(new_csv_hosts):
        handle.write(host + "\n")

stats_path.write_text(
    f"csv_rows={csv_rows_seen}\n"
    f"new={len(new_csv_hosts)}\n"
    f"skipped_existing={skipped_existing}\n",
    encoding="utf-8",
)
print(
    f"[*] CSV list: {len(new_csv_hosts)} new, "
    f"{skipped_existing} already in report (skipped), "
    f"{csv_rows_seen} CSV data row(s).",
    flush=True,
)
PY
    then
        _err=$(head -n 8 "$TMPDIR/import.err" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')
        if [ -n "$_err" ]; then
            f_subdomains_die "Failed to parse CSV list: ${_err}"
        fi
        f_subdomains_die "Failed to parse CSV list."
    fi
    if [ -s "$TMPDIR/import.out" ]; then
        cat "$TMPDIR/import.out"
    fi
    if [ -f "$SKIP_STATS" ]; then
        TEAM_CSV_NEW=$(awk -F= '/^new=/ {print $2}' "$SKIP_STATS")
        TEAM_CSV_SKIP=$(awk -F= '/^skipped_existing=/ {print $2}' "$SKIP_STATS")
        TEAM_CSV_ROWS=$(awk -F= '/^csv_rows=/ {print $2}' "$SKIP_STATS")
        echo "[*] CSV list: ${TEAM_CSV_NEW:-0} new host(s); ${TEAM_CSV_SKIP:-0} already in report (skipped); ${TEAM_CSV_ROWS:-0} CSV row(s)."
    fi

# ---------------------------------------------------------------------------
# Choice 1: Existing sources
# ---------------------------------------------------------------------------
else
    if [ "$SUBS_NONINTERACTIVE" -eq 1 ]; then
        SUBDOMAINS_IMPORT="${CLI_IMPORT:-}"
        f_subdomains_set_import_path "$REPORT_DOMAIN"
    else
        f_subdomains_read_import "$REPORT_DOMAIN"
    fi

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

    if ! python3 - "$SUBDOMAINS_IMPORT" "$REPORT_DOMAIN" "$MERGED" "$EXISTING" \
        2>"$TMPDIR/import.err" <<'PY'
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


def split_host_ip(line):
    """Parse host + optional IPv4. tools/subdomains is host\\tip\\tcategory — only col 2 is IP."""
    line = line.strip()
    if not line:
        return "", ""
    if "\t" in line:
        parts = line.split("\t")
        host = parts[0].strip() if parts else ""
        ip = parts[1].strip() if len(parts) > 1 else ""
        return host, ip
    parts = line.split()
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    if IPV4_RE.match(parts[-1]):
        return " ".join(parts[:-1]), parts[-1]
    return parts[0], parts[1] if len(parts) > 1 else ""


def load_existing(path):
    if not path.is_file():
        return
    for raw in path.read_text().splitlines():
        host, ip = split_host_ip(raw)
        if host:
            upsert(host, ip)


def load_manual(path):
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        host, ip = split_host_ip(line)
        if host:
            upsert(host, ip, prefer=True)


def load_pentest_text(path):
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("=", "#", "Pentest-Tools", "Scan id", "Total", "Resolved", "Unresolved", "Subdomains")):
            continue
        if re.search(r"(?i)subdomain|hostname", line):
            continue
        host, ip = split_host_ip(line)
        if host:
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
        _err=$(head -n 8 "$TMPDIR/import.err" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')
        if [ -n "$_err" ]; then
            f_subdomains_die "Failed to parse import file: ${_err}"
        fi
        f_subdomains_die "Failed to parse import file."
    fi
fi

[ -f "$MERGED" ] || f_subdomains_die "Internal error: merge output missing."
[ -s "$MERGED" ] || f_subdomains_die "No subdomains to process after import."

RESOLVED="$TMPDIR/subdomains-resolved.tsv"
cp "$MERGED" "$RESOLVED" || f_subdomains_die "Could not stage resolved subdomains file."

MISSING=$(awk -F '\t' 'NF < 2 || $2 == "" { count++ } END { print count + 0 }' "$MERGED")
HAD_IP=$(awk -F '\t' 'NF >= 2 && $2 != "" { count++ } END { print count + 0 }' "$MERGED")
DIG_RESOLVED=0
DIG_FAILED=0

if [ "$MISSING" -gt 0 ]; then
    : > "$RESOLVED"
    CURRENT=0

    if [ "$SUBS_JSON" -eq 0 ]; then
        echo
        echo -e "${BLUE}[*] Resolving $MISSING subdomains without IPs using dig.${NC}"
    fi
    while IFS=$'\t' read -r HOST IP; do
        HOST="${HOST//$'\r'/}"
        IP="${IP//$'\r'/}"
        if [ -z "$IP" ]; then
            CURRENT=$((CURRENT + 1))
            if [ "$SUBS_JSON" -eq 0 ]; then
                echo -ne "\r    $CURRENT of $MISSING"
            fi
            # dig may return non-zero for NXDOMAIN — treat as empty IP, not script death.
            IP=$(dig +timeout=2 +tries=1 +short "$HOST" 2>/dev/null | grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -n 1 || true)
            if [ "$IP" = "1.1.1.1" ] || [ "$IP" = "127.0.0.53" ]; then
                IP=""
            fi
            if [ -n "$IP" ]; then
                DIG_RESOLVED=$((DIG_RESOLVED + 1))
            else
                DIG_FAILED=$((DIG_FAILED + 1))
            fi
        fi
        if [ -n "$IP" ]; then
            printf '%s\t%s\n' "$HOST" "$IP" >> "$RESOLVED"
        fi
    done < "$MERGED"
    if [ "$SUBS_JSON" -eq 0 ]; then
        echo
        echo "[*] dig: $DIG_RESOLVED of $MISSING resolved to IPv4 ($DIG_FAILED unresolved)."
    fi
else
    if [ "$SUBS_JSON" -eq 0 ]; then
        echo "[*] dig: not needed — all $HAD_IP host(s) already had IPv4 addresses."
    fi
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
PUBLIC_IPS_FILE="$TOOLS_DIR/public-ips"
PAGE="$DISCOVER_REPORT/pages/subdomains.htm"
REPORT_PAGE="$DISCOVER_REPORT/pages/passive.htm"
HOSTS_PAGE="$DISCOVER_REPORT/pages/hosts.htm"
RULES_FILE="${DISCOVER:-}/recon/subdomain-categories.tsv"

# Categorize: CSV list uses Discover rules first, then CSV fallback (never write rules).
if [ "$IMPORT_MODE" = "team-csv" ]; then
    if ! python3 - "$FILTERED" "$CSV_CATS" "$RULES_FILE" "$TMPDIR/subdomains-categorized.tsv" <<'PY'
import csv
import re
import sys
from pathlib import Path

# Inline categorize_host (same rules as recon/subdomain-categorize.py) — read-only rules file.
filtered_path = Path(sys.argv[1])
cats_path = Path(sys.argv[2])
rules_path = Path(sys.argv[3])
out_path = Path(sys.argv[4])

def load_rules(path):
    rules = []
    if not path.is_file():
        return rules
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            category, pattern = line.split("\t", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            category, pattern = parts
        category = category.strip()
        pattern = pattern.strip().lower()
        if category and pattern:
            rules.append((category, pattern))
    return rules

def label_matches(label, pattern):
    if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
        return pattern[1:-1] in label
    if pattern.startswith("*"):
        return label.endswith(pattern[1:])
    if pattern.endswith("*"):
        return label.startswith(pattern[:-1])
    if pattern.startswith("-"):
        return label.endswith(pattern)
    return label == pattern

def categorize_host(host, rules):
    host = host.strip().lower()
    labels = host.split(".")
    for category, pattern in rules:
        if "." in pattern:
            if pattern in host:
                return category
            continue
        for label in labels:
            if label_matches(label, pattern):
                return category
    return ""

csv_cats = {}
if cats_path.is_file():
    for raw in cats_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue
        parts = raw.split("\t")
        h = parts[0].strip().lower()
        c = parts[1].strip() if len(parts) > 1 else ""
        if h:
            csv_cats[h] = c

rules = load_rules(rules_path)
rows = []
for raw in filtered_path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw.strip()
    if not line:
        continue
    parts = line.split("\t")
    host = parts[0].strip()
    ip = parts[1].strip() if len(parts) > 1 else ""
    if not host or not ip:
        continue
    disc = categorize_host(host, rules)
    cat = disc if disc else (csv_cats.get(host.lower()) or "")
    rows.append((host, ip, cat))

rows.sort(key=lambda r: r[0].lower())
with out_path.open("w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    for row in rows:
        writer.writerow(row)
PY
    then
        f_subdomains_die "Failed to categorize CSV list import."
    fi
    [ -s "$TMPDIR/subdomains-categorized.tsv" ] \
        || f_subdomains_die "Categorize produced no output."
    cp "$TMPDIR/subdomains-categorized.tsv" "$SUBDOMAINS_FILE" \
        || f_subdomains_die "Could not write $SUBDOMAINS_FILE"
else
    if [ ! -f "$DISCOVER/recon/subdomain-categorize.py" ]; then
        f_subdomains_die "Missing categorizer: $DISCOVER/recon/subdomain-categorize.py"
    fi
    if ! python3 "$DISCOVER/recon/subdomain-categorize.py" \
        "$FILTERED" > "$TMPDIR/subdomains-categorized.tsv" 2>"$TMPDIR/cat.err"; then
        _err=$(head -n 5 "$TMPDIR/cat.err" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')
        f_subdomains_die "Failed to categorize subdomains${_err:+: $_err}"
    fi
    [ -s "$TMPDIR/subdomains-categorized.tsv" ] \
        || f_subdomains_die "Categorize produced no output."
    cp "$TMPDIR/subdomains-categorized.tsv" "$SUBDOMAINS_FILE" \
        || f_subdomains_die "Could not write $SUBDOMAINS_FILE"
    # existing path: no batch file
    : > "$BATCH_HOSTS"
fi

CATEGORIZED=$(awk -F '\t' 'NF >= 3 && $3 != "" { count++ } END { print count + 0 }' "$SUBDOMAINS_FILE")

awk -F'\t' 'NF >= 2 && $2 ~ /^10\./ { print }' "$SUBDOMAINS_FILE" > "$PRIVATE_FILE"
awk -F'\t' 'NF >= 2 && $2 ~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./ { print }' "$SUBDOMAINS_FILE" >> "$PRIVATE_FILE"
awk -F'\t' 'NF >= 2 && $2 ~ /^192\.168\./ { print }' "$SUBDOMAINS_FILE" >> "$PRIVATE_FILE"
sort -u -o "$PRIVATE_FILE" "$PRIVATE_FILE"

# Public batch hosts only (for Active import-batch)
if [ "$IMPORT_MODE" = "team-csv" ] && [ -f "$BATCH_HOSTS" ]; then
    python3 - "$SUBDOMAINS_FILE" "$BATCH_HOSTS" "$TMPDIR/batch-public.txt" <<'PY'
import re
import sys
from pathlib import Path

IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def is_private(ip):
    if not IPV4_RE.match(ip):
        return True
    o = [int(x) for x in ip.split(".")]
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    return False

sub_path, batch_path, out_path = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
host_ip = {}
for raw in sub_path.read_text(encoding="utf-8", errors="replace").splitlines():
    parts = raw.strip().split("\t")
    if len(parts) >= 2:
        host_ip[parts[0].strip().lower()] = parts[1].strip()
batch = []
if batch_path.is_file():
    for raw in batch_path.read_text(encoding="utf-8", errors="replace").splitlines():
        h = raw.strip().lower()
        if not h:
            continue
        ip = host_ip.get(h, "")
        if ip and not is_private(ip):
            batch.append(h)
out_path.write_text("\n".join(sorted(set(batch))) + ("\n" if batch else ""), encoding="utf-8")
PY
    cp "$TMPDIR/batch-public.txt" "$BATCH_HOSTS"
fi

if ! f_subdomains_write_report "$PRIVATE_FILE" "$SUBDOMAINS_FILE" "$PAGE"; then
    f_subdomains_die "Failed to update pages/subdomains.htm"
fi
# Passive summary is optional on some trees
if [ -f "$REPORT_PAGE" ]; then
    f_subdomains_update_report "$PRIVATE_FILE" "$SUBDOMAINS_FILE" "$REPORT_PAGE" \
        || f_subdomains_die "Failed to update pages/passive.htm"
fi
if ! f_subdomains_write_hosts_page "$SUBDOMAINS_FILE" "$PUBLIC_IPS_FILE" "$HOSTS_PAGE"; then
    f_subdomains_die "Failed to update pages/hosts.htm"
fi

PRIVATE_COUNT=$(wc -l < "$PRIVATE_FILE" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
PUBLIC_IP_COUNT=0
if [ -f "$PUBLIC_IPS_FILE" ]; then
    PUBLIC_IP_COUNT=$(wc -l < "$PUBLIC_IPS_FILE" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
fi
PUBLIC_IP_COUNT=${PUBLIC_IP_COUNT:-0}
BATCH_COUNT=0
if [ -f "$BATCH_HOSTS" ] && [ -s "$BATCH_HOSTS" ]; then
    BATCH_COUNT=$(grep -cve '^[[:space:]]*$' "$BATCH_HOSTS" || true)
fi
BATCH_COUNT=${BATCH_COUNT:-0}

if [ "$IMPORT_MODE" = "team-csv" ]; then
    AUDIT_ACTION="Imported CSV list subdomains ($FINAL_COUNT hosts, $BATCH_COUNT public in batch)"
else
    AUDIT_ACTION="Imported subdomains ($FINAL_COUNT hosts)"
fi
f_subdomains_write_audit_fallback "$AUDIT_ACTION"
f_subdomains_rebuild_audit

# Homepage date tracks last meaningful report change.
if [ -f "${DISCOVER:-}/recon/touch-report-date.py" ]; then
    python3 "${DISCOVER}/recon/touch-report-date.py" "$DISCOVER_REPORT" >/dev/null 2>&1 || true
fi

SUMMARY="$FINAL_COUNT subdomains in report ($PRIVATE_COUNT private, $CATEGORIZED categorized); $PUBLIC_IP_COUNT public IPv4"

# Offer Active on imported public hosts only (CSV list)
ACTIVE_RAN=0
if [ "$IMPORT_MODE" = "team-csv" ] && [ "${BATCH_COUNT:-0}" -gt 0 ]; then
    DO_ACTIVE=0
    if [ "$SUBS_NONINTERACTIVE" -eq 1 ]; then
        [ "$SUBS_RUN_ACTIVE" -eq 1 ] && DO_ACTIVE=1
    else
        echo "$MEDIUM"
        echo
        echo "[*] Subdomains import complete."
        echo "[*] $SUMMARY."
        if [ "$MISSING" -gt 0 ]; then
            echo "[*] dig: $DIG_RESOLVED of $MISSING host(s) resolved to IPv4 ($DIG_FAILED unresolved)."
        else
            echo "[*] dig: 0 lookups — all hosts already had IPv4 addresses."
        fi
        if [ "$OMITTED" -gt 0 ]; then
            echo "[*] $OMITTED host(s) without IPv4 were omitted from the report."
        fi
        echo
        echo -e "Merged data saved to ${YELLOW}$SUBDOMAINS_FILE${NC}"
        echo -e "Import source: ${YELLOW}$SUBDOMAINS_SOURCE${NC}"
        echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
        echo
        echo -n "Run Active recon on newly imported public hosts only ($BATCH_COUNT)? (y/N) "
        read -r RUN_ACTIVE
        RUN_ACTIVE="${RUN_ACTIVE//$'\r'/}"
        if [[ "$RUN_ACTIVE" =~ ^[Yy]$ ]]; then
            DO_ACTIVE=1
        fi
    fi
    if [ "$DO_ACTIVE" -eq 1 ]; then
        if [ -f "${DISCOVER:-}/recon/active.sh" ]; then
            export DISCOVER_REPORT
            export DISCOVER_ACTIVE_SCOPE=import-batch
            # shellcheck disable=SC1090
            bash "${DISCOVER}/recon/active.sh"
            unset DISCOVER_ACTIVE_SCOPE
            ACTIVE_RAN=1
        else
            if [ "$SUBS_JSON" -eq 0 ]; then
                echo "[!] active.sh not found — run Domain → Active manually."
            fi
        fi
    fi
    if [ "$SUBS_NONINTERACTIVE" -eq 0 ]; then
        echo
    fi
fi

if [ "$SUBS_JSON" -eq 1 ]; then
    python3 -c 'import json,sys; print(json.dumps({"ok":True,"summary":sys.argv[1],"total":int(sys.argv[2]),"private":int(sys.argv[3]),"categorized":int(sys.argv[4]),"public_ips":int(sys.argv[5]),"batch_public":int(sys.argv[6]),"mode":sys.argv[7],"source":sys.argv[8],"report":sys.argv[9],"active_ran":sys.argv[10]=="1"}))' \
        "$SUMMARY" "$FINAL_COUNT" "$PRIVATE_COUNT" "$CATEGORIZED" "$PUBLIC_IP_COUNT" "$BATCH_COUNT" "$IMPORT_MODE" "$SUBDOMAINS_SOURCE" "$DISCOVER_REPORT" "$ACTIVE_RAN"
    exit 0
fi

if [ "$SUBS_QUIET" -eq 0 ] && { [ "$IMPORT_MODE" != "team-csv" ] || [ "${BATCH_COUNT:-0}" -eq 0 ] || [ "$SUBS_NONINTERACTIVE" -eq 1 ]; }; then
    echo "$MEDIUM"
    echo
    echo "[*] Subdomains import complete."
    echo "[*] $SUMMARY."
    if [ "$MISSING" -gt 0 ]; then
        echo "[*] dig: $DIG_RESOLVED of $MISSING host(s) resolved to IPv4 ($DIG_FAILED unresolved)."
    else
        echo "[*] dig: 0 lookups — all hosts already had IPv4 addresses."
    fi
    if [ "$OMITTED" -gt 0 ]; then
        echo "[*] $OMITTED host(s) without IPv4 were omitted from the report."
    fi
    echo
    echo -e "Merged data saved to ${YELLOW}$SUBDOMAINS_FILE${NC}"
    echo -e "Import source: ${YELLOW}$SUBDOMAINS_SOURCE${NC}"
    echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
    echo
fi
