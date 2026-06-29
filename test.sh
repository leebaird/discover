#!/usr/bin/env bash

# Pentest-Tools Subdomain Finder preview (standalone)

API_BASE="https://app.pentest-tools.com/api/v2"
WEB_AUTH_BASE="https://pentest-tools.com/api/auth"
SCAN_TYPE="${SCAN_TYPE:-light}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"
MAX_WAIT="${MAX_WAIT:-1800}"
MODE="scan"
DOMAIN=""
SCAN_REF=""
COOKIE_FILE="${PENTEST_TOOLS_COOKIE_FILE:-$HOME/.theHarvester/pentest-tools-cookies.txt}"
IMPORT_FILE=""
LOCAL_FILE=""

usage() {
    echo "Usage:"
    echo "  $0 cnn.com                              Start a new light scan (default: tesla.com)"
    echo "  $0 --fetch SCAN_ID                      Download via API key"
    echo "  $0 --scrape SCAN_ID [DOMAIN]            Download via browser session (paid/app scans)"
    echo "  $0 --local FILE [SCAN_ID] [DOMAIN]      Export from Firefox localStorage (free scans)"
    echo "  $0 --firefox [SCAN_ID] [DOMAIN]         Pull pinia/scans from Firefox profile (free scans)"
    echo "  $0 --firefox-extract FILE               Write pinia/scans JSON from Firefox profile"
    echo "  $0 --import FILE [DOMAIN]               Parse copied hostname/IP lines"
    echo
    echo "Options:"
    echo "  --cookies FILE                          Netscape cookie jar for --scrape"
    echo
    echo "Free scan localStorage (Firefox):"
    echo "  Preferred: $0 --firefox cgi.com"
    echo "  Or Import subdomains -> enter 'firefox' at the file prompt"
    echo "  Manual export fallback:"
    echo "  1. Open your finished scan on pentest-tools.com"
    echo "  2. F12 -> Console, paste and run:"
    echo "     (()=>{const d=localStorage.getItem('pinia/scans');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([d],{type:'application/json'}));a.download='pinia-scans.json';a.click();})();"
    echo "  3. $0 --local /path/to/pinia-scans.json cgi.com"
    echo "     Do not hand-copy from Storage; large scans truncate in the clipboard."
    echo
    echo "Scrape setup (paid/app scans stored server-side):"
    echo "  1. Log in at https://app.pentest-tools.com"
    echo "  2. Open your finished scan in the browser"
    echo "  3. Export cookies for pentest-tools.com and app.pentest-tools.com"
    echo "     to $COOKIE_FILE (Netscape/cookies.txt format)"
    echo
    echo "Examples:"
    echo "  $0 cnn.com"
    echo "  $0 --fetch 0OT3tta9J6vXTZCD"
    echo "  $0 --scrape 0OT3tta9J6vXTZCD cnn.com"
    echo "  $0 --scrape 'https://pentest-tools.com/information-gathering/find-subdomains-of-domain/scans/0OT3tta9J6vXTZCD'"
    echo "  $0 --local /home/lee/pinia-scans.json cgi.com"
    echo "  $0 --firefox cgi.com"
    echo "  $0 --firefox-extract /home/lee/pinia-scans.json"
    echo "  $0 --import /tmp/cnn-subdomains.txt cnn.com"
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
    --fetch|-f)
        MODE="fetch"
        SCAN_REF="${2:-}"
        [ -n "$SCAN_REF" ] || usage
        shift 2
        ;;
    --scrape|-s)
        MODE="scrape"
        SCAN_REF="${2:-}"
        [ -n "$SCAN_REF" ] || usage
        shift 2
        ;;
    --import|-i)
        MODE="import"
        IMPORT_FILE="${2:-}"
        [ -n "$IMPORT_FILE" ] || usage
        shift 2
        ;;
    --local|-l)
        MODE="local"
        LOCAL_FILE="${2:-}"
        [ -n "$LOCAL_FILE" ] || usage
        shift 2
        ;;
    --firefox|-F)
        MODE="firefox"
        shift
        ;;
    --firefox-extract)
        MODE="firefox-extract"
        LOCAL_FILE="${2:-}"
        [ -n "$LOCAL_FILE" ] || usage
        shift 2
        ;;
    --cookies)
        COOKIE_FILE="${2:-}"
        [ -n "$COOKIE_FILE" ] || usage
        shift 2
        ;;
    -h|--help)
        usage
        ;;
    *)
        if [ "$MODE" = "scan" ]; then
            DOMAIN="$1"
        elif [ "$MODE" = "local" ]; then
            if [ -z "$SCAN_REF" ]; then
                SCAN_REF="$1"
            elif [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            fi
        elif [ "$MODE" = "firefox" ]; then
            if [ -z "$SCAN_REF" ]; then
                SCAN_REF="$1"
            elif [ -z "$DOMAIN" ]; then
                DOMAIN="$1"
            fi
        elif [ -z "$DOMAIN" ]; then
            DOMAIN="$1"
        fi
        shift
        ;;
    esac
done

if [ "$MODE" = "scan" ] && [ -z "$DOMAIN" ]; then
    DOMAIN="tesla.com"
fi

load_api_key() {
    API_KEY="${PENTEST_TOOLS_API_KEY:-}"

    if [ -z "$API_KEY" ] && [ -f "$HOME/.theHarvester/api-keys.yaml" ]; then
        API_KEY=$(python3 - "$HOME/.theHarvester/api-keys.yaml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    sys.exit(0)

lines = path.read_text().splitlines()
for idx, line in enumerate(lines):
    if line.strip() != "pentestTools:":
        continue
    for follow in lines[idx + 1: idx + 6]:
        stripped = follow.strip()
        if not stripped:
            continue
        if stripped.startswith("key:"):
            value = stripped.split(":", 1)[1].strip()
            if value:
                print(value)
            break
        break
PY
)
    fi

    if [ -z "$API_KEY" ]; then
        echo "[!] Pentest-Tools API key not found."
        echo "[*] Set PENTEST_TOOLS_API_KEY or add pentestTools.key to $HOME/.theHarvester/api-keys.yaml"
        echo "[*] Or use --scrape with a browser cookie file instead of an API key"
        echo "[*] Generate a key at https://app.pentest-tools.com/account/api"
        exit 1
    fi
}

api_post() {
    curl -fsS -X POST "${API_BASE}${2}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$1"
}

api_get() {
    curl -fsS "${API_BASE}${1}" \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Accept: application/json"
}

normalize_domain() {
    local value=$1
    value="${value#http://}"
    value="${value#https://}"
    value="${value#www.}"
    value="${value%%/*}"
    printf '%s' "$value"
}

extract_scan_id() {
    python3 - "$1" <<'PY'
import re
import sys

ref = sys.argv[1].strip().rstrip("/")
match = re.search(r"/scans/([^/?#]+)", ref)
print(match.group(1) if match else ref)
PY
}

save_results() {
    local domain=$1
    local scan_id=$2
    local payload_source=${3:-}
    local json_out="pentest-tools-${domain}.json"
    local text_out="pentest-tools.txt"
    local payload_file=""
    local payload_tmp=""

    if [ -n "$payload_source" ] && [ -f "$payload_source" ]; then
        payload_file=$payload_source
    else
        payload_tmp=$(mktemp)
        printf '%s' "$OUTPUT_RESPONSE" > "$payload_tmp"
        payload_file=$payload_tmp
    fi

    python3 - "$domain" "$scan_id" "$json_out" "$text_out" "$payload_file" <<'PY'
import json
import sys
from pathlib import Path

domain = sys.argv[1]
scan_id = sys.argv[2]
json_out = Path(sys.argv[3])
text_out = Path(sys.argv[4])
payload = json.loads(Path(sys.argv[5]).read_text())

if isinstance(payload, dict) and "data" in payload and len(payload) == 1:
    payload = payload["data"]

bundle = {
    "domain": domain,
    "scan_id": scan_id,
    "output": payload,
}
json_out.write_text(json.dumps(bundle, indent=2) + "\n")

output = bundle["output"]
rows = []

if output.get("output_type") == "subdomain_list":
    rows = (output.get("output_data") or {}).get("subdomains") or []
elif output.get("type") == "subdomains":
    rows = (output.get("data") or {}).get("subdomains") or []
elif isinstance(output.get("subdomains"), list):
    rows = output["subdomains"]

resolved = [row for row in rows if row.get("resolved") is not False and row.get("ip_address")]
unresolved = [row for row in rows if row not in resolved]

lines = []
lines.append(f"Pentest-Tools Subdomain Finder: {domain}")
lines.append("=" * 66)
lines.append(f"Scan id                   {scan_id}")
lines.append(f"Total subdomains          {len(rows)}")
lines.append(f"Resolved                  {len(resolved)}")
lines.append(f"Unresolved                {len(unresolved)}")
lines.append("")
lines.append(f"Subdomains ({len(rows)})")
lines.append("=" * 66)

if not rows:
    lines.append("(none)")
else:
    host_width = max(len(row.get("hostname") or "") for row in rows)
    host_width = max(host_width, len("hostname"))
    for row in sorted(rows, key=lambda item: (item.get("hostname") or "").lower()):
        host = row.get("hostname") or ""
        ip = row.get("ip_address") or ""
        lines.append(f"{host:<{host_width}}  {ip}")

text_out.write_text("\n".join(lines) + "\n")

print()
print("\n".join(lines[:8]))
if rows:
    print(f"... {len(rows)} subdomains written to {text_out.name}")
print(f"Raw JSON saved to {json_out.name}")
PY

    [ -n "$payload_tmp" ] && rm -f "$payload_tmp"
}

cleanup_cookie_jar() {
    [ -n "$COOKIE_JAR" ] && rm -f "$COOKIE_JAR"
}

load_cookie_jar() {
    COOKIE_JAR=$(mktemp)

    if [ ! -f "$COOKIE_FILE" ]; then
        echo "[!] Cookie file not found: $COOKIE_FILE"
        echo "[*] Export browser cookies while logged in and viewing your scan."
        echo "[*] Save Netscape-format cookies to the path above, or pass --cookies FILE"
        exit 1
    fi

    cp "$COOKIE_FILE" "$COOKIE_JAR"

    if ! curl -fsS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
        -X POST "${WEB_AUTH_BASE}/token" \
        -H "Content-Type: application/json" \
        -o /dev/null; then
        echo "[!] Failed to exchange browser cookies for a web session token."
        exit 1
    fi
}

web_get() {
    local path=$1
    local body
    local status

    body=$(curl -sS -w $'\n%{http_code}' "${WEB_AUTH_BASE}${path}" \
        -b "$COOKIE_JAR" \
        -H "Accept: application/json")

    status="${body##*$'\n'}"
    body="${body%$'\n'*}"

    if [ "$status" = "401" ] || [ "$status" = "403" ]; then
        echo "[!] Web session rejected (HTTP ${status}). Re-export cookies while logged in." >&2
        return 1
    fi

    if [ "$status" = "404" ]; then
        echo "[!] Scan not found server-side (HTTP 404)." >&2
        echo "[*] Free-tool scans are stored in browser localStorage, not on the server." >&2
        echo "[*] Use --local with the pinia/scans export instead of --scrape." >&2
        return 1
    fi

    if [ "$status" -lt 200 ] || [ "$status" -ge 300 ]; then
        echo "[!] Web request failed (HTTP ${status})." >&2
        printf '%s\n' "$body" >&2
        return 1
    fi

    printf '%s' "$body"
}

parse_import_file() {
    local file=$1
    local domain=$2
    local scan_id=${3:-manual-import}

    if [ ! -f "$file" ]; then
        echo "[!] Import file not found: $file"
        exit 1
    fi

    IMPORT_RESULT=$(python3 - "$file" "$domain" "$scan_id" <<'PY'
import json
import re
import sys
from pathlib import Path

source = Path(sys.argv[1])
domain = sys.argv[2]
scan_id = sys.argv[3]
rows = []
seen = set()

for raw in source.read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith(("#", "=", "-")):
        continue
    if re.search(r"(?i)subdomain|hostname|pentest-tools|scan id|total subdomains", line):
        continue

    if "\t" in line:
        parts = [part.strip() for part in line.split("\t") if part.strip()]
    else:
        parts = line.split()

    if len(parts) < 2:
        continue

    host = parts[0].lower()
    ip = parts[1]
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", host):
        continue
    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+", ip, re.I):
        continue
    if host in seen:
        continue
    seen.add(host)
    rows.append({"hostname": host, "ip_address": ip, "resolved": True})

if not domain and rows:
    suffixes = {}
    for row in rows:
        parts = row["hostname"].split(".")
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            suffixes[suffix] = suffixes.get(suffix, 0) + 1
    domain = max(suffixes, key=suffixes.get) if suffixes else "unknown"

payload = {
    "type": "subdomains",
    "data": {"subdomains": rows},
}
print(json.dumps({"domain": domain, "scan_id": scan_id, "output": payload}))
PY
)

    if [ -z "$IMPORT_RESULT" ]; then
        echo "[!] Failed to parse $file"
        exit 1
    fi

    local result_tmp payload_tmp
    result_tmp=$(mktemp)
    payload_tmp=$(mktemp)
    printf '%s' "$IMPORT_RESULT" > "$result_tmp"

    ROW_COUNT=$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(len((doc.get("output",{}).get("data",{}) or {}).get("subdomains",[])))' "$result_tmp")
    if [ "$ROW_COUNT" -eq 0 ]; then
        rm -f "$result_tmp" "$payload_tmp"
        echo "[!] No hostname/IP rows found in $file"
        exit 1
    fi

    DOMAIN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["domain"])' "$result_tmp")
    SCAN_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["scan_id"])' "$result_tmp")
    python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["output"], open(sys.argv[2],"w"))' "$result_tmp" "$payload_tmp"
    rm -f "$result_tmp"
    DOMAIN=$(normalize_domain "$DOMAIN")
    save_results "$DOMAIN" "$SCAN_ID" "$payload_tmp"
    rm -f "$payload_tmp"
}

require_snappy_decoder() {
    if python3 -c 'import cramjam' 2>/dev/null || python3 -c 'import snappy' 2>/dev/null; then
        return 0
    fi

    echo "[!] Snappy decoder not found (needed for Firefox localStorage)."
    echo "[*] Install one of:"
    echo "    pip install cramjam --break-system-packages"
    echo "    pip install python-snappy --break-system-packages"
    return 1
}

extract_firefox_pinia() {
    local outfile=$1

    require_snappy_decoder || return 1

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

parse_local_storage() {
    local file=$1
    local scan_id=$2
    local domain=$3

    if [ ! -f "$file" ]; then
        echo "[!] Local storage file not found: $file"
        exit 1
    fi

    local result_tmp payload_tmp
    result_tmp=$(mktemp)
    payload_tmp=$(mktemp)

    if ! python3 - "$file" "$scan_id" "$domain" >"$result_tmp" 2>&1 <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
scan_id = sys.argv[2].strip()
domain = sys.argv[3].strip().lower()
text = source.read_text().strip()
size = len(text)

if not text:
    print("empty file", file=sys.stderr)
    sys.exit(1)

def load_payload(raw):
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        start = raw.find("[")
        end = raw.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(raw[start:end + 1])
            except json.JSONDecodeError:
                pass
        print(f"invalid JSON in {source} ({size} bytes)", file=sys.stderr)
        if size < 50000:
            print("export looks truncated; use the browser download snippet from --help", file=sys.stderr)
        else:
            print(f"JSON error near column {exc.colno}: {exc.msg}", file=sys.stderr)
        sys.exit(1)

payload = load_payload(text)

scans = payload
if isinstance(payload, dict):
    if "scans" in payload and isinstance(payload["scans"], list):
        scans = payload["scans"]
    elif "data" in payload and isinstance(payload["data"], list):
        scans = payload["data"]
    elif "id" in payload:
        scans = [payload]

if not isinstance(scans, list):
    print("expected a JSON array of scans", file=sys.stderr)
    sys.exit(1)

def normalize_target(value):
    if isinstance(value, dict):
        for key in ("initial", "redirected", "description", "name"):
            item = value.get(key)
            if isinstance(item, str) and item.strip():
                return item.strip().lower()
    if isinstance(value, str):
        return value.strip().lower()
    return ""

def scan_ids(scan):
    ids = []
    if not isinstance(scan, dict):
        return ids
    for key in ("id",):
        value = scan.get(key)
        if value is not None:
            ids.append(str(value))
    info = scan.get("info") or {}
    if isinstance(info, dict):
        for key in ("id", "target_id"):
            value = info.get(key)
            if value is not None:
                ids.append(str(value))
    return ids

def rows_from_output(output):
    if isinstance(output, list):
        if output and isinstance(output[0], dict) and "hostname" in output[0]:
            return output
        return []
    if not isinstance(output, dict):
        return []
    if output.get("type") == "subdomains":
        return (output.get("data") or {}).get("subdomains") or []
    if output.get("output_type") == "subdomain_list":
        return (output.get("output_data") or {}).get("subdomains") or []
    if isinstance(output.get("subdomains"), list):
        return output["subdomains"]
    data = output.get("data")
    if isinstance(data, dict) and isinstance(data.get("subdomains"), list):
        return data["subdomains"]
    return []

def scan_summary(scan):
    target = normalize_target(scan.get("target"))
    ids = ", ".join(dict.fromkeys(scan_ids(scan)))
    status = scan.get("status") or (scan.get("info") or {}).get("status_name") or "unknown"
    count = len(rows_from_output(scan.get("output") or []))
    return f"id={ids} target={target or '?'} status={status} subdomains={count}"

valid_scans = [scan for scan in scans if isinstance(scan, dict)]
selected = None

if scan_id:
    for scan in valid_scans:
        if scan_id in scan_ids(scan):
            selected = scan
            break

if not selected and domain:
    matches = [scan for scan in valid_scans if normalize_target(scan.get("target")) == domain]
    if len(matches) == 1:
        selected = matches[0]
    elif len(matches) > 1:
        print("multiple scans match domain; available:", file=sys.stderr)
        for scan in matches:
            print(f"  - {scan_summary(scan)}", file=sys.stderr)
        sys.exit(1)

if not selected:
    finished = [
        scan for scan in valid_scans
        if (scan.get("status") == "finished" or (scan.get("info") or {}).get("status_name") == "finished")
        and rows_from_output(scan.get("output") or [])
    ]
    if len(finished) == 1:
        selected = finished[0]
    elif len(valid_scans) == 1:
        selected = valid_scans[0]
    elif finished:
        print("multiple finished scans found; available:", file=sys.stderr)
        for scan in finished:
            print(f"  - {scan_summary(scan)}", file=sys.stderr)
        sys.exit(1)
    else:
        print("could not determine which scan to use; available:", file=sys.stderr)
        for scan in valid_scans:
            print(f"  - {scan_summary(scan)}", file=sys.stderr)
        sys.exit(1)

scan_id = scan_id or scan_ids(selected)[0] or "local-storage"
rows = rows_from_output(selected.get("output") or [])
if not rows:
    print(f"selected scan has no subdomain output ({scan_summary(selected)})", file=sys.stderr)
    print("re-export pinia/scans after the scan status is finished", file=sys.stderr)
    sys.exit(1)

if not domain:
    domain = normalize_target(selected.get("target"))
if not domain and rows:
    suffixes = {}
    for row in rows:
        host = (row.get("hostname") or "").strip().lower()
        parts = host.split(".")
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            suffixes[suffix] = suffixes.get(suffix, 0) + 1
    domain = max(suffixes, key=suffixes.get) if suffixes else "unknown"

payload = {
    "type": "subdomains",
    "data": {"subdomains": rows},
}
print(json.dumps({"domain": domain, "scan_id": scan_id, "output": payload}))
PY
    then
        sed -n '1,6p' "$result_tmp" >&2
        rm -f "$result_tmp" "$payload_tmp"
        echo "[!] Failed to parse $file"
        exit 1
    fi

    if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$result_tmp" 2>/dev/null; then
        sed -n '1,6p' "$result_tmp" >&2
        rm -f "$result_tmp" "$payload_tmp"
        echo "[!] Failed to parse $file"
        exit 1
    fi

    ROW_COUNT=$(python3 -c 'import json,sys; doc=json.load(open(sys.argv[1])); print(len((doc.get("output",{}).get("data",{}) or {}).get("subdomains",[])))' "$result_tmp")
    if [ "$ROW_COUNT" -eq 0 ]; then
        rm -f "$result_tmp" "$payload_tmp"
        echo "[!] No subdomains found in local storage export"
        exit 1
    fi

    DOMAIN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["domain"])' "$result_tmp")
    SCAN_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["scan_id"])' "$result_tmp")
    python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["output"], open(sys.argv[2],"w"))' "$result_tmp" "$payload_tmp"
    rm -f "$result_tmp"
    DOMAIN=$(normalize_domain "$DOMAIN")
    save_results "$DOMAIN" "$SCAN_ID" "$payload_tmp"
    rm -f "$payload_tmp"
}

extract_domain_from_scan_info() {
    python3 -c 'import json,sys
doc=json.load(sys.stdin)
if isinstance(doc, dict) and "data" in doc:
    doc=doc["data"]
for item in doc.get("parameters") or []:
    label=(item.get("label") or "").strip().lower()
    if label in {"target", "domain", "hostname"}:
        value=(item.get("value") or "").strip()
        if value:
            print(value)
            break
' <<<"$1"
}

if [ "$MODE" = "import" ]; then
    DOMAIN=$(normalize_domain "$DOMAIN")
    echo
    echo "Importing copied Pentest-Tools rows from ${IMPORT_FILE}"
    echo
    parse_import_file "$IMPORT_FILE" "$DOMAIN"
    echo
    exit 0
fi

if [ "$MODE" = "firefox" ] || [ "$MODE" = "firefox-extract" ]; then
    SCAN_ID=""
    if [ -n "$SCAN_REF" ] && [[ "$SCAN_REF" == http* || "$SCAN_REF" == */* || "$SCAN_REF" =~ ^[0-9]+$ ]]; then
        SCAN_ID="$SCAN_REF"
    elif [ -n "$SCAN_REF" ] && [ -z "$DOMAIN" ]; then
        DOMAIN="$SCAN_REF"
    fi
    DOMAIN=$(normalize_domain "$DOMAIN")

    firefox_tmp=$(mktemp)

    if [ "$MODE" = "firefox" ]; then
        echo
        echo "Reading pinia/scans from Firefox localStorage"
        echo
    fi

    if ! extract_firefox_pinia "$firefox_tmp" >&2; then
        rm -f "$firefox_tmp"
        exit 1
    fi

    if [ "$MODE" = "firefox-extract" ]; then
        mkdir -p "$(dirname "$LOCAL_FILE")"
        mv "$firefox_tmp" "$LOCAL_FILE"
        if [ -z "${PENTEST_TOOLS_QUIET:-}" ]; then
            echo "[*] Wrote ${LOCAL_FILE}"
            echo
        fi
        exit 0
    fi

    echo
    [ -n "$SCAN_ID" ] && echo "Scan id: ${SCAN_ID}"
    [ -n "$DOMAIN" ] && echo "Domain: ${DOMAIN}"
    echo

    parse_local_storage "$firefox_tmp" "$SCAN_ID" "$DOMAIN"
    rm -f "$firefox_tmp"
    echo
    exit 0
fi

if [ "$MODE" = "local" ]; then
    SCAN_ID=""
    if [ -n "$SCAN_REF" ] && [[ "$SCAN_REF" == http* || "$SCAN_REF" == */* || "$SCAN_REF" =~ ^[A-Za-z0-9_-]{10,}$ ]]; then
        SCAN_ID=$(extract_scan_id "$SCAN_REF")
    elif [ -n "$SCAN_REF" ] && [ -z "$DOMAIN" ]; then
        DOMAIN="$SCAN_REF"
    fi
    DOMAIN=$(normalize_domain "$DOMAIN")

    echo
    echo "Loading Pentest-Tools scan from localStorage export: ${LOCAL_FILE}"
    [ -n "$SCAN_ID" ] && echo "Scan id: ${SCAN_ID}"
    echo

    parse_local_storage "$LOCAL_FILE" "$SCAN_ID" "$DOMAIN"
    echo
    exit 0
fi

if [ "$MODE" = "scrape" ]; then
    SCAN_ID=$(extract_scan_id "$SCAN_REF")

    echo
    echo "Scraping Pentest-Tools scan ${SCAN_ID} via browser session"
    echo

    load_cookie_jar
    trap cleanup_cookie_jar EXIT

    if ! SCAN_RESPONSE=$(web_get "/scans_internal/${SCAN_ID}"); then
        echo "[!] Failed to fetch scan metadata."
        exit 1
    fi

    if python3 -c 'import json,sys; json.load(sys.stdin)' <<<"$SCAN_RESPONSE" 2>/dev/null; then
        :
    else
        echo "[!] Session request failed. Re-export cookies while logged in."
        exit 1
    fi

    if [ -z "$DOMAIN" ]; then
        DOMAIN=$(extract_domain_from_scan_info "$SCAN_RESPONSE")
    fi
    DOMAIN=$(normalize_domain "$DOMAIN")

    if ! OUTPUT_RESPONSE=$(web_get "/scans_internal/${SCAN_ID}/output"); then
        echo "[!] Failed to fetch scan output."
        exit 1
    fi

    if [ -z "$DOMAIN" ] || [ "$DOMAIN" = "unknown" ]; then
        local infer_tmp
        infer_tmp=$(mktemp)
        printf '%s' "$OUTPUT_RESPONSE" > "$infer_tmp"
        DOMAIN=$(python3 - "$infer_tmp" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text())
if isinstance(payload, dict) and "data" in payload and len(payload) == 1:
    payload = payload["data"]

rows = []
if payload.get("type") == "subdomains":
    rows = (payload.get("data") or {}).get("subdomains") or []

suffixes = Counter()
for row in rows:
    host = (row.get("hostname") or "").strip().lower()
    parts = host.split(".")
    for i in range(len(parts) - 1):
        suffixes[".".join(parts[i:])] += 1

print(suffixes.most_common(1)[0][0] if suffixes else "unknown")
PY
)
        rm -f "$infer_tmp"
        DOMAIN=$(normalize_domain "$DOMAIN")
    fi

    local output_tmp
    output_tmp=$(mktemp)
    printf '%s' "$OUTPUT_RESPONSE" > "$output_tmp"
    save_results "$DOMAIN" "$SCAN_ID" "$output_tmp"
    rm -f "$output_tmp"
    echo
    exit 0
fi

if [ "$MODE" = "fetch" ]; then
    load_api_key
    SCAN_ID=$(extract_scan_id "$SCAN_REF")

    echo
    echo "Fetching Pentest-Tools scan ${SCAN_ID}"
    echo

    if ! SCAN_RESPONSE=$(api_get "/scans/${SCAN_ID}"); then
        echo "[!] Failed to fetch scan metadata."
        exit 1
    fi

    if python3 -c 'import json,sys; doc=json.load(sys.stdin); sys.exit(0 if "data" in doc else 1)' <<<"$SCAN_RESPONSE" 2>/dev/null; then
        :
    else
        echo "[!] API request failed."
        python3 -c 'import json,sys; print(json.load(sys.stdin).get("message","Unknown error"))' <<<"$SCAN_RESPONSE" 2>/dev/null || true
        exit 1
    fi

    DOMAIN=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"].get("target_name",""))' <<<"$SCAN_RESPONSE")
    DOMAIN=$(normalize_domain "$DOMAIN")

    if [ -z "$DOMAIN" ]; then
        echo "[!] Could not determine target domain from scan metadata."
        exit 1
    fi

    if ! OUTPUT_RESPONSE=$(api_get "/scans/${SCAN_ID}/output"); then
        echo "[!] Failed to fetch scan output."
        exit 1
    fi

    save_results "$DOMAIN" "$SCAN_ID"
    echo
    exit 0
fi

load_api_key

DOMAIN=$(normalize_domain "$DOMAIN")

if [ -z "$DOMAIN" ]; then
    echo "[!] Domain is required."
    exit 1
fi

echo
echo "Pentest-Tools Subdomain Finder: ${DOMAIN}"
echo "Scan type: ${SCAN_TYPE}"
echo

START_PAYLOAD=$(python3 - "$DOMAIN" "$SCAN_TYPE" <<'PY'
import json
import sys

domain, scan_type = sys.argv[1:3]
print(json.dumps({
    "tool_id": 20,
    "target_name": domain,
    "tool_params": {
        "scan_type": scan_type,
        "web_details": True,
        "whois": True,
        "unresolved_results": True,
    },
}))
PY
)

if ! START_RESPONSE=$(api_post "$START_PAYLOAD" "/scans"); then
    echo "[!] Failed to start scan."
    exit 1
fi

if ! python3 -c 'import json,sys; doc=json.load(sys.stdin); sys.exit(0 if "data" in doc else 1)' <<<"$START_RESPONSE" 2>/dev/null; then
    echo "[!] API request failed."
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("message","Unknown error"))' <<<"$START_RESPONSE" 2>/dev/null || true
    exit 1
fi

SCAN_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["created_id"])' <<<"$START_RESPONSE")

echo "Started scan ${SCAN_ID}"
echo "Waiting for results..."
echo

START_TIME=$(date +%s)

while true; do
    if ! SCAN_RESPONSE=$(api_get "/scans/${SCAN_ID}"); then
        echo "[!] Failed to fetch scan status."
        exit 1
    fi

    STATUS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"]["status_name"])' <<<"$SCAN_RESPONSE")
    PROGRESS=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["data"].get("progress", 0))' <<<"$SCAN_RESPONSE")

    echo -ne "\rStatus: ${STATUS} (${PROGRESS}%)   "

    case "$STATUS" in
        finished)
            echo
            break
            ;;
        stopped|failed\ to\ start|timed\ out|aborted|VPN\ connection\ error|auth\ failed|connection\ error)
            echo
            echo "[!] Scan ended with status: ${STATUS}"
            exit 1
            ;;
    esac

    if [ $(( $(date +%s) - START_TIME )) -ge "$MAX_WAIT" ]; then
        echo
        echo "[!] Timed out waiting for scan ${SCAN_ID}."
        exit 1
    fi

    sleep "$POLL_INTERVAL"
done

if ! OUTPUT_RESPONSE=$(api_get "/scans/${SCAN_ID}/output"); then
    echo "[!] Failed to fetch scan output."
    exit 1
fi

save_results "$DOMAIN" "$SCAN_ID"
echo