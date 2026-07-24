#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Package a client-ready snapshot of a Discover engagement report.
# Live tree stays operator mode; only the export is stamped client/read-only.

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

clear
f_banner

echo -e "${BLUE}Export report.${NC}"
echo
echo "Package a snapshot of a Discover engagement for delivery."
echo "The live report stays in operator mode for continued testing."
echo "Exports never allow scan launches (client or defender)."
echo


# Prefer session engagement from Import report.
SESSION_FILE="${HOME}/.discover/current-report"
DEFAULT_REPORT=""
if [ -f "$SESSION_FILE" ]; then
    DEFAULT_REPORT=$(head -n 1 "$SESSION_FILE" 2>/dev/null)
    DEFAULT_REPORT="${DEFAULT_REPORT#"${DEFAULT_REPORT%%[![:space:]]*}"}"
    DEFAULT_REPORT="${DEFAULT_REPORT%"${DEFAULT_REPORT##*[![:space:]]}"}"
fi

if [ -n "$DEFAULT_REPORT" ] && f_export_report_is_report_dir "$DEFAULT_REPORT"; then
    echo -e "Current engagement: ${YELLOW}$DEFAULT_REPORT${NC}"
    echo -n "Use this report? (Y/n) "
    read -r USE_DEFAULT
    USE_DEFAULT="${USE_DEFAULT#"${USE_DEFAULT%%[![:space:]]*}"}"
    USE_DEFAULT="${USE_DEFAULT%"${USE_DEFAULT##*[![:space:]]}"}"
    if [ -z "$USE_DEFAULT" ] || [[ "$USE_DEFAULT" =~ ^[Yy] ]]; then
        DISCOVER_REPORT="$DEFAULT_REPORT"
    fi
fi

if [ -z "${DISCOVER_REPORT:-}" ]; then
    echo -n "Enter the location of your report: "
    read -r DISCOVER_REPORT
    DISCOVER_REPORT="${DISCOVER_REPORT//$'\r'/}"
    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"
fi

# Empty enter — same pattern as Active / Import names / Import report.
if [ -z "$DISCOVER_REPORT" ]; then
    f_export_report_die "No report location provided."
fi

# If the user pointed at a page file, resolve to the report root.
#   pages/*  → two levels up; index.htm / other files → one level up.
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

# Wrong path / not a Discover report — exit like other options.
if ! f_export_report_is_report_dir "$DISCOVER_REPORT"; then
    f_export_report_die "Report not found."
fi

DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)" || f_export_report_die "Report not found."

echo
echo "Package for:"
echo "  c) Client   — HTML report; audit log redacts operator egress IPs (default)"
echo "  d) Defender — HTML report; audit log keeps operator egress IPs"
echo "  a) Audit only (defenders) — plain-text audit log with operator IPs"
echo -n "Choice [c]: "
read -r PACKAGE_FOR
PACKAGE_FOR="${PACKAGE_FOR#"${PACKAGE_FOR%%[![:space:]]*}"}"
PACKAGE_FOR="${PACKAGE_FOR%"${PACKAGE_FOR##*[![:space:]]}"}"
PACKAGE_FOR=$(printf '%s' "$PACKAGE_FOR" | tr '[:upper:]' '[:lower:]')
if [ -z "$PACKAGE_FOR" ]; then
    PACKAGE_FOR=c
fi

INCLUDE_OPERATOR_IPS=0
EXPORT_KIND=client
case "$PACKAGE_FOR" in
    d|defender)
        INCLUDE_OPERATOR_IPS=1
        EXPORT_KIND=defender
        ;;
    a|audit)
        INCLUDE_OPERATOR_IPS=1
        EXPORT_KIND=audit-only
        ;;
    c|client)
        INCLUDE_OPERATOR_IPS=0
        EXPORT_KIND=client
        ;;
    *)
        f_export_report_die "Invalid package type. Use c, d, or a."
        ;;
esac

echo
echo -n "Export label (e.g. briefing, update) [briefing]: "
read -r EXPORT_LABEL
EXPORT_LABEL="${EXPORT_LABEL#"${EXPORT_LABEL%%[![:space:]]*}"}"
EXPORT_LABEL="${EXPORT_LABEL%"${EXPORT_LABEL##*[![:space:]]}"}"
if [ -z "$EXPORT_LABEL" ]; then
    EXPORT_LABEL=briefing
fi
LABEL_SLUG=$(f_export_report_slug "$EXPORT_LABEL")
[ -n "$LABEL_SLUG" ] || LABEL_SLUG=export

BASE_NAME=$(basename "$DISCOVER_REPORT")
BASE_SLUG=$(f_export_report_slug "$BASE_NAME")
[ -n "$BASE_SLUG" ] || BASE_SLUG=report

STAMP=$(date -u +"%Y%m%d-%H%M")
if [ "$EXPORT_KIND" = "audit-only" ]; then
    EXPORT_NAME="${BASE_SLUG}-audit-${LABEL_SLUG}-${STAMP}"
elif [ "$EXPORT_KIND" = "defender" ]; then
    EXPORT_NAME="${BASE_SLUG}-defender-${LABEL_SLUG}-${STAMP}"
else
    EXPORT_NAME="${BASE_SLUG}-${LABEL_SLUG}-${STAMP}"
fi

echo
echo -n "Output directory [$HOME/data]: "
read -r OUT_DIR
OUT_DIR="${OUT_DIR#"${OUT_DIR%%[![:space:]]*}"}"
OUT_DIR="${OUT_DIR%"${OUT_DIR##*[![:space:]]}"}"
OUT_DIR="${OUT_DIR/#\~/$HOME}"
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$HOME/data"
fi
mkdir -p "$OUT_DIR" || f_export_report_die "Could not create output directory: $OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

EXPORT_TS_UTC=$(date -u +"%m-%d-%Y Z - %H:%M")
EXPORT_TS_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
AUDIT_IP=$(curl -4 -fsS --connect-timeout 5 --max-time 10 http://ifconfig.me 2>/dev/null | tr -d '[:space:]')
[ -n "$AUDIT_IP" ] || AUDIT_IP=unknown

# --- Audit-only export for defenders (full operator IPs) ---
if [ "$EXPORT_KIND" = "audit-only" ]; then
    LIVE_AUDIT="$DISCOVER_REPORT/tools/audit/log.txt"
    if [ ! -f "$LIVE_AUDIT" ] || [ ! -s "$LIVE_AUDIT" ]; then
        f_export_report_die "No audit log found at tools/audit/log.txt (nothing to export yet)."
    fi

    ARCHIVE="$OUT_DIR/${EXPORT_NAME}.txt"
    {
        echo "# Discover audit log (defenders)"
        echo "# Source: $DISCOVER_REPORT"
        echo "# Label: $EXPORT_LABEL"
        echo "# Exported (UTC): $EXPORT_TS_UTC"
        echo "# Operator egress IPs: included"
        echo "# Format: mm-dd-yyyy Z - hh:mm | operator | egress_ip | action"
        echo "#"
        cat "$LIVE_AUDIT"
        echo
    } > "$ARCHIVE" || f_export_report_die "Could not write $ARCHIVE."

    mkdir -p "$DISCOVER_REPORT/tools/exports" "$DISCOVER_REPORT/tools/audit" 2>/dev/null || true
    LIVE_EXPORT_LOG="$DISCOVER_REPORT/tools/exports/log.jsonl"
    python3 - "$LIVE_EXPORT_LOG" "$EXPORT_LABEL" "$EXPORT_TS_ISO" "$ARCHIVE" "$DISCOVER_REPORT" "audit-only" true <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
rec = {
    "label": sys.argv[2],
    "exported_at_utc": sys.argv[3],
    "archive": sys.argv[4],
    "source": sys.argv[5],
    "kind": sys.argv[6],
    "include_operator_ips": sys.argv[7] == "true",
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
PY

    AUDIT_LOG="$DISCOVER_REPORT/tools/audit/log.txt"
    touch "$AUDIT_LOG" 2>/dev/null || true
    if [ -w "$AUDIT_LOG" ]; then
        if declare -F f_audit_log >/dev/null 2>&1; then
            f_audit_log "$DISCOVER_REPORT" \
                "Exported audit log for defenders (label: $EXPORT_LABEL; operator IPs included)"
        else
            op=$(head -n 1 "${HOME}/.discover/operator-name" 2>/dev/null | tr -d '\r' | tr -cd "A-Za-z" | cut -c1-10)
            [ -n "$op" ] || op=unknown
            printf '%s | %s | %s | Exported audit log for defenders (label: %s; operator IPs included).\n' \
                "$EXPORT_TS_UTC" "$op" "$AUDIT_IP" "$EXPORT_LABEL" >> "$AUDIT_LOG" 2>/dev/null || true
        fi
    fi

    echo
    echo "$MEDIUM"
    echo
    echo "[*] Defender audit export complete."
    echo -e "File:    ${YELLOW}$ARCHIVE${NC}"
    echo -e "Source:  ${YELLOW}$DISCOVER_REPORT${NC}"
    echo -e "IPs:     ${YELLOW}included${NC}"
    echo
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

echo
echo "[*] Copying report (this may take a moment)..."

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

# Stamp non-operator mode on the export only (no scan launches for recipients).
mkdir -p "$STAGE_ROOT/assets"
if [ "$EXPORT_KIND" = "defender" ]; then
    cat > "$STAGE_ROOT/assets/report-mode.json" <<'EOF'
{
  "mode": "defender",
  "launches": false,
  "include_operator_ips": true
}
EOF
else
    cat > "$STAGE_ROOT/assets/report-mode.json" <<'EOF'
{
  "mode": "client",
  "launches": false,
  "include_operator_ips": false
}
EOF
fi
chmod 644 "$STAGE_ROOT/assets/report-mode.json" 2>/dev/null || true

# Export metadata for Audit / provenance.
cat > "$STAGE_ROOT/export-meta.json" <<EOF
{
  "label": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$EXPORT_LABEL"),
  "exported_at_utc": "$EXPORT_TS_ISO",
  "exported_at_display": "$EXPORT_TS_UTC",
  "source": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$DISCOVER_REPORT"),
  "kind": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$EXPORT_KIND"),
  "mode": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$EXPORT_KIND"),
  "launches": false,
  "include_operator_ips": $([ "$INCLUDE_OPERATOR_IPS" -eq 1 ] && echo true || echo false)
}
EOF

# Also ship a standalone full audit copy for defenders (easy to hand off).
if [ "$INCLUDE_OPERATOR_IPS" -eq 1 ] && [ -f "$DISCOVER_REPORT/tools/audit/log.txt" ]; then
    mkdir -p "$STAGE_ROOT/tools/audit"
    {
        echo "# Discover audit log (defenders) — operator egress IPs included"
        echo "# Source: $DISCOVER_REPORT"
        echo "# Label: $EXPORT_LABEL"
        echo "# Exported (UTC): $EXPORT_TS_UTC"
        echo "# Format: mm-dd-yyyy Z - hh:mm | operator | egress_ip | action"
        echo "#"
        cat "$DISCOVER_REPORT/tools/audit/log.txt"
        echo
    } > "$STAGE_ROOT/tools/audit/log-with-operator-ips.txt"
fi

# Redact consultant egress IPs in shipped HTML audit log for client packages only.
if [ "$INCLUDE_OPERATOR_IPS" -eq 0 ] && [ -f "$STAGE_ROOT/tools/audit/log.txt" ]; then
    python3 - "$STAGE_ROOT/tools/audit/log.txt" <<'PY'
import re, sys
from pathlib import Path
path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8", errors="replace")
# New: mm-dd-yyyy Z - hh:mm | operator | IP | action
# Legacy: mm-dd-yyyy Z - hh:mm | IP | action
line_re4 = re.compile(
    r"^(\d{2}-\d{2}-\d{4} Z - \d{2}:\d{2}) \| ([^|]+) \| ([^|]+) \| (.*)$"
)
line_re3 = re.compile(
    r"^(\d{2}-\d{2}-\d{4} Z - \d{2}:\d{2}) \| ([^|]+) \| (.*)$"
)
out = []
for line in text.splitlines():
    m4 = line_re4.match(line)
    if m4:
        out.append(f"{m4.group(1)} | {m4.group(2).strip()} | redacted | {m4.group(4)}")
        continue
    m3 = line_re3.match(line)
    if m3:
        out.append(f"{m3.group(1)} | redacted | {m3.group(3)}")
    else:
        out.append(line)
path.write_text("\n".join(out) + ("\n" if out else ""), encoding="utf-8")
PY
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
python3 - "$LIVE_EXPORT_LOG" "$EXPORT_LABEL" "$EXPORT_TS_ISO" "$ARCHIVE" "$DISCOVER_REPORT" "$EXPORT_KIND" \
    "$INCLUDE_OPERATOR_IPS" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
rec = {
    "label": sys.argv[2],
    "exported_at_utc": sys.argv[3],
    "archive": sys.argv[4],
    "source": sys.argv[5],
    "kind": sys.argv[6],
    "include_operator_ips": sys.argv[7] == "1",
}
with path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
PY

AUDIT_LOG="$DISCOVER_REPORT/tools/audit/log.txt"
touch "$AUDIT_LOG" 2>/dev/null || true
if [ -w "$AUDIT_LOG" ]; then
    if declare -F f_audit_log >/dev/null 2>&1; then
        if [ "$INCLUDE_OPERATOR_IPS" -eq 1 ]; then
            f_audit_log "$DISCOVER_REPORT" \
                "Exported defender report (label: $EXPORT_LABEL; operator IPs included)"
        else
            f_audit_log "$DISCOVER_REPORT" \
                "Exported client report (label: $EXPORT_LABEL)"
        fi
    else
        op=$(head -n 1 "${HOME}/.discover/operator-name" 2>/dev/null | tr -d '\r' | tr -cd "A-Za-z" | cut -c1-10)
        [ -n "$op" ] || op=unknown
        if [ "$INCLUDE_OPERATOR_IPS" -eq 1 ]; then
            printf '%s | %s | %s | Exported defender report (label: %s; operator IPs included).\n' \
                "$EXPORT_TS_UTC" "$op" "$AUDIT_IP" "$EXPORT_LABEL" >> "$AUDIT_LOG" 2>/dev/null || true
        else
            printf '%s | %s | %s | Exported client report (label: %s).\n' \
                "$EXPORT_TS_UTC" "$op" "$AUDIT_IP" "$EXPORT_LABEL" >> "$AUDIT_LOG" 2>/dev/null || true
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

echo
echo "$MEDIUM"
echo
echo "[*] Export complete."
echo -e "Archive:  ${YELLOW}$ARCHIVE${NC}"
echo -e "Source:   ${YELLOW}$DISCOVER_REPORT${NC} (still operator mode)"
echo -e "Label:    ${YELLOW}$EXPORT_LABEL${NC}"
echo -e "Kind:     ${YELLOW}$EXPORT_KIND${NC}"
if [ "$INCLUDE_OPERATOR_IPS" -eq 1 ]; then
    echo -e "Audit IPs:${YELLOW} included (for defenders)${NC}"
else
    echo -e "Audit IPs:${YELLOW} redacted (client package)${NC}"
fi
echo
echo "Send the archive to the recipient. Continue testing from the live engagement."
echo
exit 0
