#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)
#
# Interactive (Domain menu legacy / CLI): prompts for report + manual TSV.
# Non-interactive (statusd / UI): --report <path> [--manual <path>] [--json]

# Colors when not launched from Discover menu.
RED=${RED:-'\033[1;31m'}
YELLOW=${YELLOW:-'\033[1;33m'}
BLUE=${BLUE:-'\033[1;34m'}
NC=${NC:-'\033[0m'}
SMALL=${SMALL:-'========================================'}
MEDIUM=${MEDIUM:-'=================================================================='}

NAMES_JSON=0
NAMES_QUIET=0
NAMES_NONINTERACTIVE=0
CLI_REPORT=""
CLI_MANUAL=""

f_names_usage(){
    echo "Usage: import-names.sh [--report <path>] [--manual <path>] [--json]"
    echo "  Interactive when --report is omitted. UI/statusd: pass --report (current engagement)."
}

f_names_json_fail(){
    local msg="$1"
    if [ "$NAMES_JSON" -eq 1 ]; then
        python3 -c 'import json,sys; print(json.dumps({"ok":False,"error":sys.argv[1]}))' "$msg"
    fi
}

f_names_die(){
    f_names_json_fail "$1"
    if [ "$NAMES_JSON" -eq 0 ]; then
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        echo -e "${RED}[!] $1${NC}"
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        [ "$NAMES_NONINTERACTIVE" -eq 0 ] && sleep 2
    fi
    exit 1
}

f_names_validate_report(){
    DISCOVER_REPORT="${DISCOVER_REPORT//$'\r'/}"
    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

    if [ -z "$DISCOVER_REPORT" ]; then
        f_names_die "No scan location provided."
    fi

    if [ -f "$DISCOVER_REPORT" ]; then
        case "$DISCOVER_REPORT" in
            */pages/*)
                DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")/.." && pwd)" || f_names_die "Passive scan not found."
                ;;
            *)
                DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")" && pwd)" || f_names_die "Passive scan not found."
                ;;
        esac
    fi

    if [ ! -d "$DISCOVER_REPORT" ] \
        || [ ! -r "$DISCOVER_REPORT" ] \
        || [ ! -x "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT/pages" ] \
        || [ ! -f "$DISCOVER_REPORT/pages/names.htm" ]; then
        f_names_die "Passive scan not found."
    fi
    DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)" || f_names_die "Passive scan not found."
}

f_names_read_report(){
    echo
    echo -n "Enter the location of a previous Discover scan: "
    read -r DISCOVER_REPORT
    f_names_validate_report
}

f_names_use_manual(){
    local default="$DISCOVER_REPORT/tools/names-manual.tsv"
    local create_ok="${1:-1}"

    NAMES_MANUAL="${NAMES_MANUAL//$'\r'/}"
    NAMES_MANUAL="${NAMES_MANUAL#"${NAMES_MANUAL%%[![:space:]]*}"}"
    NAMES_MANUAL="${NAMES_MANUAL%"${NAMES_MANUAL##*[![:space:]]}"}"
    NAMES_MANUAL="${NAMES_MANUAL/#\~/$HOME}"

    if [ -z "$NAMES_MANUAL" ]; then
        NAMES_MANUAL="$default"
    fi

    if [ ! -f "$NAMES_MANUAL" ]; then
        if [ "$create_ok" -eq 1 ] && [ "$NAMES_NONINTERACTIVE" -eq 0 ]; then
            mkdir -p "$DISCOVER_REPORT/tools"
            cat > "$NAMES_MANUAL" <<'EOF'
# Manual contacts — tab-separated: Name, Title, Phone
# Add one person per line, then re-run Import names.
EOF
            f_names_die "Manual contacts file created. Add entries, then run Import names again."
        fi
        f_names_die "Manual contacts file not found: $NAMES_MANUAL"
    fi

    if [ ! -s "$NAMES_MANUAL" ] || ! grep -qv '^[[:space:]]*#' "$NAMES_MANUAL" 2>/dev/null; then
        f_names_die "Manual contacts file is empty. Add tab-separated rows, then run Import names again."
    fi
}

f_names_read_manual(){
    local default="$DISCOVER_REPORT/tools/names-manual.tsv"

    echo
    echo "Add contacts to:"
    echo "  $default"
    echo
    echo "Format: Name<TAB>Title<TAB>Phone  (one person per line)"
    echo
    echo -n "Enter manual contacts file (or press Enter for default): "
    read -r NAMES_MANUAL
    f_names_use_manual 1
}

f_names_write_audit(){
    local action="$1"
    if declare -F f_audit_log >/dev/null 2>&1; then
        f_audit_log "$DISCOVER_REPORT" "$action" || true
        return 0
    fi
    mkdir -p "$DISCOVER_REPORT/tools/audit" 2>/dev/null || return 0
    local ts op
    ts=$(date -u +"%m/%d/%Y - %H:%M Z")
    op="Operator"
    if [ -f "$HOME/.discover/operator-name" ]; then
        op=$(tr -d '[:space:]' < "$HOME/.discover/operator-name" 2>/dev/null || true)
        [ -n "$op" ] || op="Operator"
    fi
    case "$action" in
        *.) ;;
        *) action="${action}." ;;
    esac
    # Names import: no operator egress IP on Audit (dash placeholder).
    printf '%s | %s | - | %s\n' "$ts" "$op" "$action" >> "$DISCOVER_REPORT/tools/audit/log.txt" 2>/dev/null || true
}

f_names_rebuild_audit(){
    local root="${DISCOVER:-}"
    if [ -z "$root" ] || [ ! -f "$root/recon/audit-build.py" ]; then
        root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
    if [ -f "$root/recon/audit-build.py" ] && [ -f "$root/report/pages/audit.htm" ]; then
        python3 "$root/recon/audit-build.py" "$DISCOVER_REPORT" "$root/report/pages/audit.htm" >/dev/null 2>&1 || true
    fi
}

f_names_merge(){
    local merged="$1"
    shift

    python3 - "$merged" "$@" <<'PY'
import csv
import html
import os
import re
import sys
from html.parser import HTMLParser

out_path = sys.argv[1]
sources = sys.argv[2:]

SKIP_RE = re.compile(
    r"(an exception|error message|failed to|found character|while scanning|projectdiscovery|^\^$)",
    re.I,
)


def normalize(value):
    return " ".join(str(value or "").split()).strip()


def merge_key(name):
    return normalize(name).lower()


def upsert(store, name, title="", phone="", prefer=False):
    name = normalize(name)
    if not name or not re.search(r"[A-Za-z]{2,}", name) or SKIP_RE.search(name):
        return

    key = merge_key(name)
    row = store.setdefault(key, {"name": name, "title": "", "phone": ""})
    title = normalize(title)
    phone = normalize(phone)

    if prefer or (title and (not row["title"] or len(title) >= len(row["title"]))):
        row["title"] = title
    elif title and not row["title"]:
        row["title"] = title

    if prefer or (phone and not row["phone"]):
        row["phone"] = phone


class TableParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_tbody = False
        self.in_row = False
        self.in_cell = False
        self.cells = []
        self.rows = []

    def handle_starttag(self, tag, attrs):
        if tag == "tbody":
            self.in_tbody = True
        elif self.in_tbody and tag == "tr":
            self.in_row = True
            self.cells = []
        elif self.in_row and tag == "td":
            self.in_cell = True
            self.cells.append("")

    def handle_endtag(self, tag):
        if tag == "tbody":
            self.in_tbody = False
        elif tag == "tr" and self.in_row:
            self.in_row = False
            if self.cells:
                self.rows.append(self.cells[:3])
        elif tag == "td":
            self.in_cell = False

    def handle_data(self, data):
        if self.in_cell and self.cells:
            self.cells[-1] += data


def load_tsv(path, prefer=False):
    store = {}
    if not os.path.isfile(path):
        return store
    with open(path, newline="") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "\t" not in line:
                upsert(store, line, prefer=prefer)
                continue
            row = next(csv.reader([line], delimiter="\t"))
            while len(row) < 3:
                row.append("")
            upsert(store, row[0], row[1], row[2], prefer=prefer)
    return store


def load_page(path):
    store = {}
    if not os.path.isfile(path):
        return store
    parser = TableParser()
    parser.feed(open(path).read())
    for cells in parser.rows:
        while len(cells) < 3:
            cells.append("")
        name, title, phone = [normalize(cell) for cell in cells[:3]]
        if not name or name.lower() == "no data found.":
            continue
        upsert(store, name, title, phone)
    return store


contacts = {}
for source in sources:
    prefer = source.endswith("names-manual.tsv")
    if source.endswith(".htm"):
        chunk = load_page(source)
    else:
        chunk = load_tsv(source, prefer=prefer)
    for row in chunk.values():
        upsert(contacts, row["name"], row["title"], row["phone"], prefer=prefer)

rows = sorted(contacts.values(), key=lambda row: row["name"].lower())
with open(out_path, "w", newline="") as handle:
    writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
    for row in rows:
        writer.writerow([row["name"], row["title"], row["phone"]])
PY
}

f_names_build_rows(){
    local RESULTS_FILE="$1"
    local ROWS_FILE="$2"

    if [ ! -s "$RESULTS_FILE" ]; then
        printf '                <tr><td colspan="3">No data found.</td></tr>\n' > "$ROWS_FILE"
        return 0
    fi

    python3 - "$RESULTS_FILE" "$ROWS_FILE" <<'PY'
import csv
import html
import sys

results_path, rows_path = sys.argv[1], sys.argv[2]
lines = []
with open(results_path, newline="") as handle:
    for row in csv.reader(handle, delimiter="\t"):
        while len(row) < 3:
            row.append("")
        name, title, phone = [cell.strip() for cell in row[:3]]
        if not name:
            continue
        lines.append(
            "                <tr>"
            f"<td>{html.escape(name)}</td>"
            f"<td>{html.escape(title)}</td>"
            f"<td>{html.escape(phone)}</td>"
            "</tr>"
        )

if not lines:
    lines.append('                <tr><td colspan="3">No data found.</td></tr>')

with open(rows_path, "w") as handle:
    handle.write("\n".join(lines) + "\n")
PY
}

f_names_patch_table(){
    local ROWS_FILE="$1"
    local TARGET_FILE="$2"

    [ -f "$TARGET_FILE" ] || return 0

    python3 - "$ROWS_FILE" "$TARGET_FILE" <<'PY'
import re
import sys

rows = open(sys.argv[1]).read()
path = sys.argv[2]
text = open(path).read()
new_text, count = re.subn(
    r"(<tbody>).*?(</tbody>)",
    r"\1\n" + rows + r"            \2",
    text,
    count=1,
    flags=re.S,
)
if count:
    open(path, "w").write(new_text)
PY
}

f_names_write_report(){
    local RESULTS_FILE="$1"
    local REPORT_PAGE="$2"
    local ROWS_FILE="$3"

    f_names_build_rows "$RESULTS_FILE" "$ROWS_FILE"
    f_names_patch_table "$ROWS_FILE" "$REPORT_PAGE"
}

f_names_update_report(){
    local NAMES_FILE="$1"
    local REPORT_PAGE="$2"

    [ -f "$REPORT_PAGE" ] || return 0

    python3 - "$REPORT_PAGE" "$NAMES_FILE" <<'PY'
import re
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
names_path = Path(sys.argv[2])
separator = "=" * 40

SUMMARY_LABEL = re.compile(r"^[A-Za-z][A-Za-z ]+\s+\d+$")
DETAIL_HEADER = re.compile(r"^[A-Za-z][A-Za-z ]+ \(\d+\)$")


def plain_line(line):
    return re.sub(r"<[^>]+>", "", line)


def report_heading(text):
    return f'<span class="inc-report-heading">{text}</span>'


def load_rows(path):
    if not path.is_file() or path.stat().st_size == 0:
        return []
    rows = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if line:
            rows.append(line)
    return rows


def replace_section(lines, section_name, count, body_lines):
    header = report_heading(f"{section_name} ({count})")
    for i, line in enumerate(lines):
        if re.fullmatch(rf"{re.escape(section_name)} \(\d+\)", plain_line(line)):
            j = i + 2
            while j < len(lines) and not DETAIL_HEADER.match(plain_line(lines[j])):
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


def insert_summary_count(lines, label, count):
    width = 22
    entry = f"{label:<{width}}{count}"
    for i, line in enumerate(lines):
        if plain_line(line).strip() == "Summary":
            j = i + 1
            while j < len(lines) and lines[j].strip() == "":
                j += 1
            if j < len(lines) and lines[j].startswith("="):
                j += 1
            lines.insert(j, entry)
            return True
    return False


def insert_detail_section(lines, section_name, count, body_lines):
    header = report_heading(f"{section_name} ({count})")
    block = ["", header, separator]
    if body_lines:
        block.extend(body_lines)
        block.append("")

    for i, line in enumerate(lines):
        if DETAIL_HEADER.match(plain_line(line)):
            lines[i:i] = block
            return True

    for i, line in enumerate(lines):
        if SUMMARY_LABEL.match(plain_line(line)):
            continue
        if line.strip() == "" and i + 1 < len(lines) and DETAIL_HEADER.match(plain_line(lines[i + 1])):
            lines[i + 1:i + 1] = block[1:]
            return True

    if lines and lines[-1].strip() != "":
        lines.append("")
    lines.extend(block[1:] if block[0] == "" else block)
    return True


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

name_rows = load_rows(names_path)
name_count = len(name_rows)

if not update_summary_count(lines, "Names", name_count):
    insert_summary_count(lines, "Names", name_count)

if not replace_section(lines, "Names", name_count, name_rows):
    insert_detail_section(lines, "Names", name_count, name_rows)

report_path.write_text(prefix + "\n".join(lines) + suffix)
PY
}

while [ $# -gt 0 ]; do
    case "$1" in
        --report)
            CLI_REPORT="${2:-}"
            shift 2
            ;;
        --manual)
            CLI_MANUAL="${2:-}"
            shift 2
            ;;
        --json)
            NAMES_JSON=1
            NAMES_NONINTERACTIVE=1
            shift
            ;;
        --quiet|-q)
            NAMES_QUIET=1
            shift
            ;;
        -h|--help)
            f_names_usage
            exit 0
            ;;
        *)
            f_names_die "Unknown option: $1"
            ;;
    esac
done

if [ -n "$CLI_REPORT" ]; then
    NAMES_NONINTERACTIVE=1
    DISCOVER_REPORT="$CLI_REPORT"
fi

if [ -z "${DISCOVER:-}" ] || [ ! -d "${DISCOVER:-/}/report/pages" ]; then
    _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -d "$_script_dir/../report/pages" ]; then
        DISCOVER="$(cd "$_script_dir/.." && pwd)"
    fi
    unset _script_dir
fi
export DISCOVER="${DISCOVER:-}"

if [ "$NAMES_NONINTERACTIVE" -eq 0 ]; then
    if declare -F f_banner >/dev/null 2>&1; then
        clear 2>/dev/null || true
        f_banner
    fi
    echo -e "${BLUE}Import names.${NC}"
fi

if ! command -v python3 >/dev/null 2>&1; then
    f_names_die "python3 is not installed. Run Discover update to install dependencies."
fi

if [ "$NAMES_NONINTERACTIVE" -eq 1 ]; then
    f_names_validate_report
    NAMES_MANUAL="${CLI_MANUAL:-}"
    f_names_use_manual 0
else
    f_names_read_report
    f_names_read_manual
fi

TOOLS_DIR="$DISCOVER_REPORT/tools"
mkdir -p "$TOOLS_DIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

MERGED="$TMPDIR/names.tsv"
AUTO="$TOOLS_DIR/names"
MANUAL="$NAMES_MANUAL"
PAGE="$DISCOVER_REPORT/pages/names.htm"
REPORT_PAGE="$DISCOVER_REPORT/pages/passive.htm"

f_names_merge "$MERGED" "$AUTO" "$PAGE" "$MANUAL"

TOTAL=$(wc -l < "$MERGED" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
if [ "${TOTAL:-0}" -eq 0 ]; then
    f_names_die "No names found after merge."
fi

cp "$MERGED" "$TOOLS_DIR/names"
ROWS_FILE="$TMPDIR/names-rows.html"
f_names_write_report "$MERGED" "$PAGE" "$ROWS_FILE"
f_names_update_report "$MERGED" "$REPORT_PAGE"

WITH_TITLE=$(awk -F '\t' 'NF > 1 && $2 != "" { count++ } END { print count + 0 }' "$MERGED")
WITH_PHONE=$(awk -F '\t' 'NF > 2 && $3 != "" { count++ } END { print count + 0 }' "$MERGED")

if [ -f "${DISCOVER:-}/recon/touch-report-date.py" ]; then
    python3 "${DISCOVER}/recon/touch-report-date.py" "$DISCOVER_REPORT" >/dev/null 2>&1 || true
fi

f_names_write_audit "Imported names ($TOTAL contacts)"
f_names_rebuild_audit

SUMMARY="$TOTAL contacts in report ($WITH_TITLE with title, $WITH_PHONE with phone)"

if [ "$NAMES_JSON" -eq 1 ]; then
    python3 -c 'import json,sys; print(json.dumps({"ok":True,"summary":sys.argv[1],"total":int(sys.argv[2]),"with_title":int(sys.argv[3]),"with_phone":int(sys.argv[4]),"manual":sys.argv[5],"report":sys.argv[6]}))' \
        "$SUMMARY" "$TOTAL" "$WITH_TITLE" "$WITH_PHONE" "$MANUAL" "$DISCOVER_REPORT"
    exit 0
fi

if [ "$NAMES_QUIET" -eq 0 ]; then
    echo "$MEDIUM"
    echo
    echo "[*] Names import complete."
    echo "[*] $SUMMARY."
    echo
    echo -e "Merged data saved to ${YELLOW}$TOOLS_DIR/names${NC}"
    echo -e "Manual entries file: ${YELLOW}$MANUAL${NC}"
    echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
    echo
fi
