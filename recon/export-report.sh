#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Package a client-ready snapshot of a Discover engagement report.
# Live tree stays operator mode. Client packages omit assets/report-mode.json.

# Colors / separators: inherit from Discover when launched from the menu.
BLUE=${BLUE:-'\033[1;34m'}
YELLOW=${YELLOW:-'\033[1;33m'}
RED=${RED:-'\033[1;31m'}
NC=${NC:-'\033[0m'}
SMALL=${SMALL:-'========================================'}
MEDIUM=${MEDIUM:-'=================================================================='}

if ! declare -F f_banner >/dev/null 2>&1; then
    f_banner(){ echo; }
fi

f_export_report_die(){

    if [ "${QUIET:-0}" -eq 1 ]; then
        python3 -c 'import json,sys; print(json.dumps({"ok": False, "error": sys.argv[1]}))' "$1"
        exit 1
    fi

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

f_export_report_is_report_dir(){
    local dir="$1"

    [ -n "$dir" ] || return 1
    [ -d "$dir" ] || return 1
    [ -r "$dir" ] || return 1
    [ -x "$dir" ] || return 1
    [ -d "$dir/pages" ] || return 1
    [ -f "$dir/index.htm" ] || [ -f "$dir/pages/active.htm" ] || [ -f "$dir/pages/subdomains.htm" ] || [ -f "$dir/pages/passive.htm" ]
}

f_export_report_slug(){
    local raw="$1"
    # Keep alnum, dot, dash, underscore; collapse spaces to dash.
    printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed -e 's/[[:space:]]\+/-/g' -e 's/[^a-z0-9._-]//g' -e 's/-\+/-/g' -e 's/^-//' -e 's/-$//'
}

f_export_report_usage(){
    echo "Usage: export-report.sh --kind client|defender|operator --report <path> [--out-dir <path>]"
    echo "  Non-interactive packaging for Discover UI (statusd) or CLI."
}

# Filename stamp uses Config view timezone; audit/ledger stamps stay UTC.
f_export_report_stamps(){
    local cfg=""
    local out=""

    if [ -n "${DISCOVER:-}" ] && [ -f "$DISCOVER/recon/discover-config.py" ]; then
        cfg="$DISCOVER/recon/discover-config.py"
    elif [ -f "$(dirname "$0")/discover-config.py" ]; then
        cfg="$(dirname "$0")/discover-config.py"
    fi

    if [ -n "$cfg" ]; then
        out=$(python3 - "$cfg" <<'PY'
import importlib.util
import sys
from pathlib import Path

path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("discover_config", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
stamp, utc_disp, utc_iso, tz_id = mod.export_filename_stamp()
print(stamp)
print(utc_disp)
print(utc_iso)
print(tz_id)
PY
        ) || out=""
    fi

    if [ -n "$out" ]; then
        STAMP=$(printf '%s\n' "$out" | sed -n '1p')
        EXPORT_TS_UTC=$(printf '%s\n' "$out" | sed -n '2p')
        EXPORT_TS_ISO=$(printf '%s\n' "$out" | sed -n '3p')
        EXPORT_TZ=$(printf '%s\n' "$out" | sed -n '4p')
    fi

    [ -n "${STAMP:-}" ] || STAMP=$(date -u +"%Y%m%d-%H%M")
    [ -n "${EXPORT_TS_UTC:-}" ] || EXPORT_TS_UTC=$(date -u +"%m/%d/%Y - %H:%M Z")
    [ -n "${EXPORT_TS_ISO:-}" ] || EXPORT_TS_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    [ -n "${EXPORT_TZ:-}" ] || EXPORT_TZ=UTC
}

# --- Args (required for UI-driven export; no Domain menu prompts) ---
EXPORT_KIND=""
DISCOVER_REPORT="${DISCOVER_REPORT:-}"
OUT_DIR=""
QUIET=0
while [ $# -gt 0 ]; do
    case "$1" in
        --kind)
            EXPORT_KIND="${2:-}"
            shift 2
            ;;
        --report)
            DISCOVER_REPORT="${2:-}"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="${2:-}"
            shift 2
            ;;
        --quiet|-q)
            QUIET=1
            shift
            ;;
        -h|--help)
            f_export_report_usage
            exit 0
            ;;
        *)
            f_export_report_die "Unknown option: $1"
            ;;
    esac
done

if [ -z "$EXPORT_KIND" ] || [ -z "$DISCOVER_REPORT" ]; then
    f_export_report_usage
    f_export_report_die "Required: --kind and --report"
fi

EXPORT_KIND=$(printf '%s' "$EXPORT_KIND" | tr '[:upper:]' '[:lower:]')
INCLUDE_OPERATOR_IPS=0
EXPORT_LAUNCHES=0
case "$EXPORT_KIND" in
    defender|d)
        INCLUDE_OPERATOR_IPS=1
        EXPORT_LAUNCHES=0
        EXPORT_KIND=defender
        ;;
    operator|o)
        INCLUDE_OPERATOR_IPS=1
        EXPORT_LAUNCHES=1
        EXPORT_KIND=operator
        ;;
    client|c)
        INCLUDE_OPERATOR_IPS=1
        EXPORT_LAUNCHES=0
        EXPORT_KIND=client
        ;;
    *)
        f_export_report_die "Invalid --kind (use client, defender, or operator)."
        ;;
esac

DISCOVER_REPORT="${DISCOVER_REPORT//$'\r'/}"
DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

# If the user pointed at a page file, resolve to the report root.
if [ -f "$DISCOVER_REPORT" ]; then
    case "$DISCOVER_REPORT" in
        */pages/*)

            if ! DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")/.." && pwd)"; then
                f_export_report_die "Report not found."
            fi

            ;;
        *)

            if ! DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")" && pwd)"; then
                f_export_report_die "Report not found."
            fi

            ;;
    esac
fi

if ! f_export_report_is_report_dir "$DISCOVER_REPORT"; then
    f_export_report_die "Report not found."
fi

DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)" || f_export_report_die "Report not found."

BASE_NAME=$(basename "$DISCOVER_REPORT")
BASE_SLUG=$(f_export_report_slug "$BASE_NAME")
[ -n "$BASE_SLUG" ] || BASE_SLUG=report

f_export_report_stamps
case "$EXPORT_KIND" in
    defender)
        EXPORT_NAME="${BASE_SLUG}-defender-${STAMP}"
        ;;
    operator)
        EXPORT_NAME="${BASE_SLUG}-operator-${STAMP}"
        ;;
    *)
        EXPORT_NAME="${BASE_SLUG}-client-${STAMP}"
        ;;
esac

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$HOME/data"
fi

OUT_DIR="${OUT_DIR//$'\r'/}"
OUT_DIR="${OUT_DIR#"${OUT_DIR%%[![:space:]]*}"}"
OUT_DIR="${OUT_DIR%"${OUT_DIR##*[![:space:]]}"}"
OUT_DIR="${OUT_DIR/#\~/$HOME}"
mkdir -p "$OUT_DIR" || f_export_report_die "Could not create output directory: $OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

if [ "$QUIET" -eq 0 ]; then
    echo "[*] Export $EXPORT_KIND → $OUT_DIR"
fi

AUDIT_IP=$(curl -4 -fsS --connect-timeout 5 --max-time 10 http://ifconfig.me 2>/dev/null | tr -d '[:space:]')
[ -n "$AUDIT_IP" ] || AUDIT_IP=unknown

# --- Defender: audit log only (CSV) ---
# Action column matches Audit HTML (Started → tool command; Finished → duration).
if [ "$EXPORT_KIND" = "defender" ]; then
    LIVE_AUDIT="$DISCOVER_REPORT/tools/audit/log.txt"

    if [ ! -f "$LIVE_AUDIT" ] || [ ! -s "$LIVE_AUDIT" ]; then
        f_export_report_die "No audit log found at tools/audit/log.txt (nothing to export yet)."
    fi

    ARCHIVE="$OUT_DIR/${EXPORT_NAME}.csv"
    AUDIT_BUILD=""

    if [ -n "${DISCOVER:-}" ] && [ -f "$DISCOVER/recon/audit-build.py" ]; then
        AUDIT_BUILD="$DISCOVER/recon/audit-build.py"
    elif [ -f "$(dirname "$0")/audit-build.py" ]; then
        AUDIT_BUILD="$(dirname "$0")/audit-build.py"
    fi

    if [ -z "$AUDIT_BUILD" ]; then
        f_export_report_die "audit-build.py not found (needed for defender CSV)."
    fi

    python3 "$AUDIT_BUILD" --defender-csv "$DISCOVER_REPORT" "$ARCHIVE" \
        >/dev/null 2>&1 \
        || f_export_report_die "Could not write defender CSV."
    [ -f "$ARCHIVE" ] || f_export_report_die "Could not write defender CSV."

    mkdir -p "$DISCOVER_REPORT/tools/exports" "$DISCOVER_REPORT/tools/audit" 2>/dev/null || true
    LIVE_EXPORT_LOG="$DISCOVER_REPORT/tools/exports/log.jsonl"
    python3 - "$LIVE_EXPORT_LOG" "$EXPORT_TS_ISO" "$ARCHIVE" "$DISCOVER_REPORT" "defender" true <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
rec = {
    "exported_at_utc": sys.argv[2],
    "archive": sys.argv[3],
    "source": sys.argv[4],
    "kind": sys.argv[5],
    "include_operator_ips": sys.argv[6] == "true",
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
PY

    AUDIT_LOG="$DISCOVER_REPORT/tools/audit/log.txt"
    touch "$AUDIT_LOG" 2>/dev/null || true

    if [ -w "$AUDIT_LOG" ]; then
        if declare -F f_audit_log >/dev/null 2>&1; then
            f_audit_log "$DISCOVER_REPORT" "Exported defender audit CSV"
        else
            op=$(head -n 1 "${HOME}/.discover/operator-name" 2>/dev/null | tr -d '\r' | tr -cd "A-Za-z" | cut -c1-10)
            [ -n "$op" ] || op=unknown
            printf '%s | %s | %s | Exported defender audit CSV.\n' \
                "$EXPORT_TS_UTC" "$op" "$AUDIT_IP" >> "$AUDIT_LOG" 2>/dev/null || true
        fi
    fi

    if [ -n "${DISCOVER:-}" ] && [ -f "$DISCOVER/recon/audit-build.py" ]; then
        python3 "$DISCOVER/recon/audit-build.py" "$DISCOVER_REPORT" "$DISCOVER/report/pages/audit.htm" >/dev/null 2>&1 || true
    elif [ -f "$(dirname "$0")/audit-build.py" ]; then
        python3 "$(dirname "$0")/audit-build.py" "$DISCOVER_REPORT" >/dev/null 2>&1 || true
    fi

    if [ "$QUIET" -eq 0 ]; then
        echo
        echo "$MEDIUM"
        echo
        echo "[*] Defender audit CSV export complete."
        echo -e "File:    ${YELLOW}$ARCHIVE${NC}"
        echo -e "Source:  ${YELLOW}$DISCOVER_REPORT${NC}"
        echo -e "Columns: ${YELLOW}Time UTC, Operator, Operator IP, Target, Action${NC}"
        echo
    fi

    python3 -c 'import json,sys; print(json.dumps({"ok": True, "path": sys.argv[1], "kind": sys.argv[2]}))' \
        "$ARCHIVE" "defender"
    exit 0
fi

if ! command -v zip >/dev/null 2>&1 && ! command -v tar >/dev/null 2>&1; then
    f_export_report_die "Neither zip nor tar is installed."
fi

STAGE=$(mktemp -d) || f_export_report_die "Could not create temp directory."
cleanup(){
    rm -rf "$STAGE" 2>/dev/null
}
trap cleanup EXIT

STAGE_ROOT="$STAGE/$EXPORT_NAME"
mkdir -p "$STAGE_ROOT" || f_export_report_die "Could not create staging directory."

if [ "$QUIET" -eq 0 ]; then
    echo
    echo "[*] Copying report (this may take a moment)."
fi

# Copy engagement tree; skip bulky/irrelevant paths if present.
if command -v rsync >/dev/null 2>&1; then
    rsync -a \
        --exclude '.git/' \
        --exclude 'tools/gowitness/gowitness.db' \
        --exclude 'tools/gowitness/*.db' \
        "$DISCOVER_REPORT/" "$STAGE_ROOT/" || f_export_report_die "rsync copy failed."
else
    cp -a "$DISCOVER_REPORT/." "$STAGE_ROOT/" || f_export_report_die "copy failed."
    rm -f "$STAGE_ROOT/tools/gowitness/gowitness.db" "$STAGE_ROOT/tools/gowitness/"*.db 2>/dev/null || true
fi

# Client/defender packages must not include the engagement Google Sheet URL
# or the operator threat-intel alert store.
if [ "$EXPORT_KIND" != "operator" ]; then
    rm -f "$STAGE_ROOT/tools/op-notes-url" "$STAGE_ROOT/.env" 2>/dev/null || true
    rm -rf "$STAGE_ROOT/tools/threat-feed" 2>/dev/null || true
fi

# Client package: Yes links already point at the screenshot JPEGs.
# gowitness.jsonl is only used to rebuild those links.
if [ "$EXPORT_KIND" = "client" ]; then
    rm -f "$STAGE_ROOT/tools/gowitness/gowitness.jsonl"
fi

# Client Audit already lists exports in pages/audit.htm.
# tools/exports/log.jsonl stays on the live engagement.
if [ "$EXPORT_KIND" = "client" ]; then
    rm -rf "$STAGE_ROOT/tools/exports"
fi

# Raw Passive dumps (zsubfinder, zcrtsh, zarin-emails, and the rest).
# Pages are already built from the parsed tools files.
if [ "$EXPORT_KIND" = "client" ]; then
    if [ -d "$STAGE_ROOT/tools" ]; then
        find "$STAGE_ROOT/tools" -mindepth 1 -maxdepth 1 -name 'z*' -exec rm -f {} +
    fi
fi

# Operator export keeps the mode stamp. Client HTML does not read it.
mkdir -p "$STAGE_ROOT/assets"

if [ "$EXPORT_KIND" = "operator" ]; then
    cat > "$STAGE_ROOT/assets/report-mode.json" <<'EOF'
{
  "mode": "operator",
  "launches": true,
  "include_operator_ips": true
}
EOF
    chmod 644 "$STAGE_ROOT/assets/report-mode.json" 2>/dev/null || true
else
    rm -f "$STAGE_ROOT/assets/report-mode.json"

    # Client export keeps the Audit range on All and drops Scans per day / By operator.
    python3 - "$STAGE_ROOT/pages/audit.htm" <<'PY'
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit(0)
text = path.read_text(encoding="utf-8", errors="replace")
select_re = re.compile(
    r'<select id="inc-audit-metrics-range"[^>]*>.*?</select>',
    re.DOTALL,
)
match = select_re.search(text)
if match and 'value="all"' in match.group(0):
    block = re.sub(r"\s+selected(?=[\s>])", "", match.group(0))
    block = block.replace(
        '<option value="all">',
        '<option value="all" selected>',
        1,
    )
    text = text[: match.start()] + block + text[match.end() :]

    def fix_panel(panel):
        tag = panel.group(0)
        range_match = re.search(r'data-range="([^"]+)"', tag)
        if not range_match:
            return tag
        tag = re.sub(r"\s+hidden(?=[\s>])", "", tag)
        if range_match.group(1) != "all":
            tag = tag[:-1] + " hidden>"
        return tag

    text = re.sub(
        r'<div class="inc-audit-metrics-panel" data-range="[^"]*"(?: hidden)?>',
        fix_panel,
        text,
    )

def strip_full_width_charts(html):
    """Drop Scans per day and By operator. Other charts stay."""
    needle = '<div class="inc-audit-metrics-charts inc-audit-metrics-charts--1">'
    out = []
    i = 0
    while True:
        j = html.find(needle, i)
        if j < 0:
            out.append(html[i:])
            break
        out.append(html[i:j])
        depth = 0
        k = j
        end = None
        while k < len(html):
            if html.startswith("<div", k):
                depth += 1
                gt = html.find(">", k)
                if gt < 0:
                    break
                k = gt + 1
                continue
            if html.startswith("</div>", k):
                depth -= 1
                k += len("</div>")
                if depth == 0:
                    end = k
                    break
                continue
            k += 1
        if end is None:
            out.append(html[j:])
            break
        block = html[j:end]
        if "<h4>Scans per day</h4>" in block or "<h4>By operator</h4>" in block:
            if out and out[-1].endswith("\n"):
                out[-1] = out[-1][:-1]
            i = end
            if html[i:i + 1] == "\n":
                i += 1
        else:
            out.append(block)
            i = end
    return "".join(out)

text = strip_full_width_charts(text)
path.write_text(text, encoding="utf-8")
PY
fi

# Client export only: Subdomains tool menu without Run or the info button.
# The staged copy gets status.js and web.htm. The live operator report is not modified.
if [ "$EXPORT_KIND" = "client" ]; then
    RECON_DIR="$(cd "$(dirname "$0")" && pwd)"
    python3 - "$STAGE_ROOT" "$RECON_DIR" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[2])
import write_web_links

write_web_links.prepare_client_subdomains(Path(sys.argv[1]))
PY
fi

# Client pages already contain this data. Host-scan JSON is read above
# while web.htm is written. Operator export keeps the source files.
if [ "$EXPORT_KIND" = "client" ]; then
    rm -f \
        "$STAGE_ROOT/tools/whatweb.json" \
        "$STAGE_ROOT/tools/httpx.jsonl" \
        "$STAGE_ROOT/tools/active-alive.tsv" \
        "$STAGE_ROOT/tools/active.txt" \
        "$STAGE_ROOT/tools/active-targets.txt" \
        "$STAGE_ROOT/tools/import-batch-hosts.txt" \
        "$STAGE_ROOT/tools/subdomains" \
        "$STAGE_ROOT/tools/subdomains-import.tsv" \
        "$STAGE_ROOT/tools/emails" \
        "$STAGE_ROOT/tools/names" \
        "$STAGE_ROOT/tools/names-phones.tsv" \
        "$STAGE_ROOT/tools/names-manual.tsv" \
        "$STAGE_ROOT/tools/hosts" \
        "$STAGE_ROOT/tools/public-ips" \
        "$STAGE_ROOT/tools/private-ips" \
        "$STAGE_ROOT/tools/private-subs" \
        "$STAGE_ROOT/tools/dns-private.tsv" \
        "$STAGE_ROOT/tools/squatting" \
        "$STAGE_ROOT/tools/records" \
        "$STAGE_ROOT/tools/whois-domain" \
        "$STAGE_ROOT/tools/whois-ip" \
        "$STAGE_ROOT/tools/passive-scan-date" \
        "$STAGE_ROOT/tools/shodan/summary.json" \
        "$STAGE_ROOT/tools/shodan/summary.tsv" \
        "$STAGE_ROOT/tools/shodan/index.json" \
        "$STAGE_ROOT/tools/audit/log.txt" \
        "$STAGE_ROOT/tools/audit"/log.txt.bak-*
    rmdir "$STAGE_ROOT/tools/audit" 2>/dev/null || true

    if [ -d "$STAGE_ROOT/tools/host-scans" ]; then
        find "$STAGE_ROOT/tools/host-scans" -type f \
            ! -name 'output.txt' \
            ! -name 'robots.txt' \
            ! -name 'nikto.htm' \
            ! -name 'transom.htm' \
            ! -name 'web.htm' \
            ! -name 'status.js' \
            -delete
    fi

    find "$STAGE_ROOT" -name '.DS_Store' -delete
fi

# Export metadata stays on the operator package. Client packages omit it.
# The live engagement still records the export in tools/exports/log.jsonl.
if [ "$EXPORT_KIND" != "client" ]; then
    LAUNCHES_JSON=false
    [ "$EXPORT_LAUNCHES" -eq 1 ] && LAUNCHES_JSON=true
    cat > "$STAGE_ROOT/export-meta.json" <<EOF
{
  "exported_at_utc": "$EXPORT_TS_ISO",
  "exported_at_display": "$EXPORT_TS_UTC",
  "filename_timezone": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$EXPORT_TZ"),
  "source": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$DISCOVER_REPORT"),
  "kind": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$EXPORT_KIND"),
  "mode": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$EXPORT_KIND"),
  "launches": $LAUNCHES_JSON,
  "include_operator_ips": $([ "$INCLUDE_OPERATOR_IPS" -eq 1 ] && echo true || echo false)
}
EOF
else
    rm -f "$STAGE_ROOT/export-meta.json"
fi

# Package
ARCHIVE=""

if command -v zip >/dev/null 2>&1; then
    ARCHIVE="$OUT_DIR/${EXPORT_NAME}.zip"
    (
        cd "$STAGE" || exit 1
        zip -rq "$ARCHIVE" "$EXPORT_NAME"
    ) || f_export_report_die "zip failed."
else
    ARCHIVE="$OUT_DIR/${EXPORT_NAME}.tar.gz"
    tar -C "$STAGE" -czf "$ARCHIVE" "$EXPORT_NAME" || f_export_report_die "tar failed."
fi

# Live engagement: export ledger + audit line (full egress IP on live only).
mkdir -p "$DISCOVER_REPORT/tools/exports" "$DISCOVER_REPORT/tools/audit" 2>/dev/null || true
LIVE_EXPORT_LOG="$DISCOVER_REPORT/tools/exports/log.jsonl"
python3 - "$LIVE_EXPORT_LOG" "$EXPORT_TS_ISO" "$ARCHIVE" "$DISCOVER_REPORT" "$EXPORT_KIND" \
    "$INCLUDE_OPERATOR_IPS" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
rec = {
    "exported_at_utc": sys.argv[2],
    "archive": sys.argv[3],
    "source": sys.argv[4],
    "kind": sys.argv[5],
    "include_operator_ips": sys.argv[6] == "1",
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
PY

AUDIT_LOG="$DISCOVER_REPORT/tools/audit/log.txt"
touch "$AUDIT_LOG" 2>/dev/null || true

if [ -w "$AUDIT_LOG" ]; then
    if declare -F f_audit_log >/dev/null 2>&1; then
        if [ "$EXPORT_KIND" = "operator" ]; then
            f_audit_log "$DISCOVER_REPORT" "Exported operator report"
        else
            f_audit_log "$DISCOVER_REPORT" "Exported client report"
        fi
    else
        op=$(head -n 1 "${HOME}/.discover/operator-name" 2>/dev/null | tr -d '\r' | tr -cd "A-Za-z" | cut -c1-10)
        [ -n "$op" ] || op=unknown

        if [ "$EXPORT_KIND" = "operator" ]; then
            printf '%s | %s | %s | Exported operator report.\n' \
                "$EXPORT_TS_UTC" "$op" "$AUDIT_IP" >> "$AUDIT_LOG" 2>/dev/null || true
        else
            printf '%s | %s | %s | Exported client report.\n' \
                "$EXPORT_TS_UTC" "$op" "$AUDIT_IP" >> "$AUDIT_LOG" 2>/dev/null || true
        fi
    fi
fi

# Keep live tree operator mode if someone had flipped it.
if [ -d "$DISCOVER_REPORT/assets" ]; then
    cat > "$DISCOVER_REPORT/assets/report-mode.json" <<'EOF'
{
  "mode": "operator",
  "launches": true
}
EOF
fi

# Refresh Audit page on the live engagement
if [ -n "${DISCOVER:-}" ] && [ -f "$DISCOVER/recon/audit-build.py" ]; then
    python3 "$DISCOVER/recon/audit-build.py" "$DISCOVER_REPORT" "$DISCOVER/report/pages/audit.htm" >/dev/null 2>&1 || true
elif [ -f "$(dirname "$0")/audit-build.py" ]; then
    python3 "$(dirname "$0")/audit-build.py" "$DISCOVER_REPORT" >/dev/null 2>&1 || true
fi

if [ "$QUIET" -eq 0 ]; then
    echo
    echo "$MEDIUM"
    echo
    echo "[*] Export complete."
    echo -e "Archive:  ${YELLOW}$ARCHIVE${NC}"
    echo -e "Source:   ${YELLOW}$DISCOVER_REPORT${NC} (still operator mode)"
    echo -e "Kind:     ${YELLOW}$EXPORT_KIND${NC}"
    echo -e "Audit IPs:${YELLOW} included${NC}"
    if [ "$EXPORT_KIND" = "operator" ]; then
        echo -e "Launches: ${YELLOW} enabled in package stamp${NC}"
    else
        echo -e "Launches: ${YELLOW} disabled${NC}"
    fi

    echo
    echo "Send the archive to the recipient. Continue testing from the live engagement."
    echo
fi

python3 -c 'import json,sys; print(json.dumps({"ok": True, "path": sys.argv[1], "kind": sys.argv[2]}))' \
    "$ARCHIVE" "$EXPORT_KIND"
exit 0
