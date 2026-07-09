#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_nte_die(){
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

f_nte_read_source(){
    echo
    echo -n "Enter the location of the names file: "
    read -r NAMES_FILE

    NAMES_FILE="${NAMES_FILE#"${NAMES_FILE%%[![:space:]]*}"}"
    NAMES_FILE="${NAMES_FILE%"${NAMES_FILE##*[![:space:]]}"}"
    NAMES_FILE="${NAMES_FILE/#\~/$HOME}"

    if [ -z "$NAMES_FILE" ]; then
        f_nte_die "No names file provided."
    fi

    if [ ! -f "$NAMES_FILE" ] || [ ! -r "$NAMES_FILE" ]; then
        f_nte_die "Names file not found."
    fi
}

f_nte_read_report(){
    echo
    echo -n "Enter the location of your previous passive scan: "
    read -r DISCOVER_REPORT

    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

    if [ -z "$DISCOVER_REPORT" ]; then
        f_nte_die "No scan location provided."
    fi

    if [ -f "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT" ] \
        || [ ! -r "$DISCOVER_REPORT" ] \
        || [ ! -x "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT/pages" ] \
        || [ ! -f "$DISCOVER_REPORT/pages/names.htm" ]; then
        f_nte_die "Passive scan not found."
    fi
}

clear
f_banner

echo -e "${BLUE}Import names, titles, and emails.${NC}"

if ! command -v python3 >/dev/null 2>&1; then
    f_nte_die "python3 is not installed. Run Discover update to install dependencies."
fi

f_nte_read_source
f_nte_read_report

STATS_FILE=$(mktemp)
trap 'rm -f "$STATS_FILE"' EXIT

python3 - "$NAMES_FILE" "$DISCOVER_REPORT" "$STATS_FILE" <<'PY'
import csv
import html
import re
import subprocess
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
report_dir = Path(sys.argv[2])
stats_path = Path(sys.argv[3])
tools_dir = report_dir / "tools"
names_page = report_dir / "pages" / "names.htm"
report_page = report_dir / "pages" / "passive.htm"
names_file = tools_dir / "names"
emails_file = tools_dir / "emails"

SUMMARY_SEP = "=" * 40
DETAIL_SEP = "=" * 127

EMAIL_RE = re.compile(r"\s+(\S+@\S+)\s*$")
TITLE_START = re.compile(
    r"\b(VP|SVP|Director|Executive|Senior|Product|Sales|Agile|Lead|President|"
    r"Consultant|Manager|Coach|Owner)\b",
    re.I,
)
SUMMARY_LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9 ]+\s+\d+$")
DETAIL_HEADER = re.compile(r"^[A-Za-z][A-Za-z0-9 ]+ \(\d+\)$")


def plain_line(line):
    return re.sub(r"<[^>]+>", "", line)


def report_heading(text):
    return f'<span class="inc-report-heading">{text}</span>'


def normalize(value):
    return " ".join(str(value or "").split()).strip()


def merge_key(name):
    return normalize(name).lower()


def parse_source_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = EMAIL_RE.search(line)
    email = match.group(1) if match else ""
    rest = line[: match.start()].strip() if match else line

    parts = re.split(r"\s{2,}", rest)
    if len(parts) >= 2:
        name = parts[0].strip()
        title = " ".join(parts[1:]).strip()
    else:
        title_match = TITLE_START.search(rest)
        if title_match:
            name = rest[: title_match.start()].strip()
            title = rest[title_match.start() :].strip()
        else:
            name, title = rest, ""

    if not name:
        return None
    return {"name": name, "title": title, "email": normalize(email), "phone": ""}


def load_names_tsv(path):
    store = {}
    if not path.is_file():
        return store

    with path.open(newline="") as handle:
        for row in csv.reader(handle, delimiter="\t"):
            while len(row) < 4:
                row.append("")
            name, title, email, phone = [normalize(cell) for cell in row[:4]]
            if not name:
                continue
            store[merge_key(name)] = {
                "name": name,
                "title": title,
                "email": email,
                "phone": phone,
            }
    return store


def upsert(store, contact, prefer=False):
    key = merge_key(contact["name"])
    row = store.setdefault(
        key,
        {"name": contact["name"], "title": "", "email": "", "phone": ""},
    )
    row["name"] = contact["name"]

    title = contact.get("title", "")
    email = contact.get("email", "")
    phone = contact.get("phone", "")

    if prefer or (title and (not row["title"] or len(title) >= len(row["title"]))):
        row["title"] = title
    elif title and not row["title"]:
        row["title"] = title

    if prefer or (email and not row["email"]):
        row["email"] = email

    if prefer or (phone and not row["phone"]):
        row["phone"] = phone


def load_emails(path):
    emails = []
    seen = set()
    if not path.is_file():
        return emails
    for raw in path.read_text().splitlines():
        email = normalize(raw).lower()
        if email and email not in seen:
            seen.add(email)
            emails.append(email)
    return sorted(emails, key=str.lower)


def write_names_tsv(path, contacts):
    rows = sorted(contacts.values(), key=lambda row: row["name"].lower())
    with path.open("w", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        for row in rows:
            writer.writerow([row["name"], row["title"], row["email"], row["phone"]])


def write_emails_file(path, emails):
    path.write_text("\n".join(emails) + ("\n" if emails else ""))


def build_names_rows(contacts):
    lines = []
    for row in sorted(contacts.values(), key=lambda item: item["name"].lower()):
        lines.append(
            "                <tr>"
            f"<td>{html.escape(row['name'])}</td>"
            f"<td>{html.escape(row['title'])}</td>"
            f"<td>{html.escape(row['email'])}</td>"
            f"<td>{html.escape(row['phone'])}</td>"
            "</tr>"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def patch_table(page_path, rows_html):
    text = page_path.read_text()
    new_text, count = re.subn(
        r"(<tbody>).*?(</tbody>)",
        r"\1\n" + rows_html + r"            \2",
        text,
        count=1,
        flags=re.S,
    )
    if count:
        page_path.write_text(new_text)


def format_names_report_lines(contacts):
    rows = sorted(contacts.values(), key=lambda item: item["name"].lower())
    payload = "\n".join(
        f"{row['name']}\t{row['title']}" for row in rows if row["name"]
    )
    if not payload:
        return []
    result = subprocess.run(
        ["column", "-t", "-s", "\t"],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def update_summary_count(lines, label, count):
    width = 22
    pattern = re.compile(rf"^{re.escape(label)}\s+\d+$")
    for index, line in enumerate(lines):
        if pattern.match(line):
            lines[index] = f"{label:<{width}}{count}"
            return True
    return False


def replace_detail_section(lines, section_name, count, body_lines, separator):
    header = report_heading(f"{section_name} ({count})")
    for index, line in enumerate(lines):
        if re.fullmatch(rf"{re.escape(section_name)} \(\d+\)", plain_line(line)):
            end = index + 2
            while end < len(lines) and not DETAIL_HEADER.match(plain_line(lines[end])):
                end += 1
            block = [header, separator]
            if body_lines:
                block.extend(body_lines)
                block.append("")
            lines[index:end] = block
            return True
    return False


def update_report_page(contacts, emails):
    if not report_page.is_file():
        return

    marker_open = '<pre class="inc-pre">\n'
    marker_close = "</pre>"
    text = report_page.read_text()
    open_at = text.find(marker_open)
    if open_at == -1:
        return

    body_start = open_at + len(marker_open)
    close_at = text.find(marker_close, body_start)
    if close_at == -1:
        return

    lines = text[body_start:close_at].splitlines()
    name_lines = format_names_report_lines(contacts)
    email_lines = list(emails)

    update_summary_count(lines, "Names", len(contacts))
    update_summary_count(lines, "Emails", len(email_lines))
    replace_detail_section(lines, "Names", len(contacts), name_lines, DETAIL_SEP)
    replace_detail_section(lines, "Emails", len(email_lines), email_lines, DETAIL_SEP)

    report_page.write_text(text[:body_start] + "\n".join(lines) + text[close_at:])


contacts = load_names_tsv(names_file)
before_names = len(contacts)

for raw in source_path.read_text().splitlines():
    parsed = parse_source_line(raw)
    if parsed:
        upsert(contacts, parsed, prefer=True)

emails = set(load_emails(emails_file))
for row in contacts.values():
    if row["email"]:
        emails.add(row["email"].lower())
email_list = sorted(emails, key=str.lower)

tools_dir.mkdir(parents=True, exist_ok=True)
write_names_tsv(names_file, contacts)
write_emails_file(emails_file, email_list)
patch_table(names_page, build_names_rows(contacts))
update_report_page(contacts, email_list)

added_names = len(contacts) - before_names
stats_path.write_text(
    f"{before_names}\n{len(contacts)}\n{added_names}\n{len(email_list)}\n"
)
PY

BEFORE_NAMES=$(sed -n '1p' "$STATS_FILE")
TOTAL_NAMES=$(sed -n '2p' "$STATS_FILE")
ADDED_NAMES=$(sed -n '3p' "$STATS_FILE")
TOTAL_EMAILS=$(sed -n '4p' "$STATS_FILE")

echo "$MEDIUM"
echo
echo "[*] Names, titles, and emails import complete."
echo "[*] Names: $BEFORE_NAMES -> $TOTAL_NAMES (+$ADDED_NAMES)"
echo "[*] Emails: $TOTAL_EMAILS"
echo
echo -e "Source file: ${YELLOW}$NAMES_FILE${NC}"
echo -e "Merged data saved to ${YELLOW}$DISCOVER_REPORT/tools/names${NC}"
echo -e "HTML report updated: ${YELLOW}$DISCOVER_REPORT${NC}"
echo
