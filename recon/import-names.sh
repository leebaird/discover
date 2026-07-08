#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_names_die(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $1${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
}

f_names_read_report(){
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
        || [ ! -f "$DISCOVER_REPORT/pages/names.htm" ]; then
        f_names_die "Passive scan not found."
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

    NAMES_MANUAL="${NAMES_MANUAL#"${NAMES_MANUAL%%[![:space:]]*}"}"
    NAMES_MANUAL="${NAMES_MANUAL%"${NAMES_MANUAL##*[![:space:]]}"}"
    NAMES_MANUAL="${NAMES_MANUAL/#\~/$HOME}"

    if [ -z "$NAMES_MANUAL" ]; then
        NAMES_MANUAL="$default"
    fi

    if [ ! -f "$NAMES_MANUAL" ]; then
        mkdir -p "$DISCOVER_REPORT/tools"
        cat > "$NAMES_MANUAL" <<'EOF'
# Manual contacts — tab-separated: Name, Title, Phone
# Add one person per line, then re-run Import names.
EOF
        f_names_die "Manual contacts file created. Add entries, then run Import names again."
    fi

    if [ ! -s "$NAMES_MANUAL" ] || ! grep -qv '^[[:space:]]*#' "$NAMES_MANUAL" 2>/dev/null; then
        f_names_die "Manual contacts file is empty. Add tab-separated rows, then run Import names again."
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

clear
f_banner

echo -e "${BLUE}Import names.${NC}"

if ! command -v python3 >/dev/null 2>&1; then
    f_names_die "python3 is not installed. Run Discover update to install dependencies."
fi

f_names_read_report
f_names_read_manual

TOOLS_DIR="$DISCOVER_REPORT/tools"
mkdir -p "$TOOLS_DIR"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

MERGED="$TMPDIR/names.tsv"
AUTO="$TOOLS_DIR/names"
MANUAL="$NAMES_MANUAL"
PAGE="$DISCOVER_REPORT/pages/names.htm"

f_names_merge "$MERGED" "$AUTO" "$PAGE" "$MANUAL"

TOTAL=$(wc -l < "$MERGED" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
if [ "${TOTAL:-0}" -eq 0 ]; then
    f_names_die "No names found after merge."
fi

cp "$MERGED" "$TOOLS_DIR/names"
ROWS_FILE="$TMPDIR/names-rows.html"
f_names_write_report "$MERGED" "$PAGE" "$ROWS_FILE"

WITH_TITLE=$(awk -F '\t' 'NF > 1 && $2 != "" { count++ } END { print count + 0 }' "$MERGED")
WITH_PHONE=$(awk -F '\t' 'NF > 2 && $3 != "" { count++ } END { print count + 0 }' "$MERGED")

echo "$MEDIUM"
echo
echo "[*] Names import complete."
echo "[*] $TOTAL contacts in report ($WITH_TITLE with title, $WITH_PHONE with phone)."
echo
echo -e "Merged data saved to ${YELLOW}$TOOLS_DIR/names${NC}"
echo -e "Manual entries file: ${YELLOW}$MANUAL${NC}"
echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
echo
