#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Operator host scan launcher (Red Team quiet defaults).
# Invoked via discover-scan: scheme or CLI:
#   run-host-scan.sh <tool> <url> [software] [report_root]
#
# Tools: nikto | nuclei | ffuf
# - Visible terminal (desktop entry uses Terminal=true)
# - One scan at a time (engagement lock)
# - Software-aware nuclei/ffuf profiles

set -euo pipefail

TOOL="${1:-}"
URL="${2:-}"
SOFTWARE="${3:-}"
REPORT_ROOT="${4:-}"

f_die(){
    echo
    echo "[!] $*"
    echo
    sleep 2
    exit 1
}

[[ "$TOOL" =~ ^(nikto|nuclei|ffuf)$ ]] || f_die "Tool must be nikto, nuclei, or ffuf."
[ -n "$URL" ] || f_die "URL is required."

# Resolve report root
if [ -z "$REPORT_ROOT" ] && [ -f "${HOME}/.discover/current-report" ]; then
    REPORT_ROOT=$(head -n 1 "${HOME}/.discover/current-report" 2>/dev/null || true)
fi
REPORT_ROOT="${REPORT_ROOT//$'\r'/}"
REPORT_ROOT="${REPORT_ROOT#"${REPORT_ROOT%%[![:space:]]*}"}"
REPORT_ROOT="${REPORT_ROOT%"${REPORT_ROOT##*[![:space:]]}"}"
REPORT_ROOT="${REPORT_ROOT/#\~/$HOME}"
[ -n "$REPORT_ROOT" ] || f_die "No engagement report (use Domain → Import report first)."
[ -d "$REPORT_ROOT" ] || f_die "Report not found: $REPORT_ROOT"
REPORT_ROOT="$(cd "$REPORT_ROOT" && pwd)"

MODE_FILE="$REPORT_ROOT/assets/report-mode.json"
if [ -f "$MODE_FILE" ]; then
    if python3 - "$MODE_FILE" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
if m.get("launches") is False or (m.get("mode") or "").lower() in {"client", "defender"}:
    sys.exit(1)
sys.exit(0)
PY
    then
        :
    else
        f_die "This report is not in operator mode (launches disabled)."
    fi
fi

# Validate URL
if [[ ! "$URL" =~ ^https?:// ]]; then
    f_die "URL must start with http:// or https://"
fi

HOST=$(python3 - "$URL" <<'PY'
from urllib.parse import urlparse
import sys
print((urlparse(sys.argv[1]).hostname or "").lower())
PY
)
[ -n "$HOST" ] || f_die "Could not parse host from URL."

# Host must appear in engagement httpx data when available
HTTPX_JSONL="$REPORT_ROOT/tools/httpx.jsonl"
if [ -f "$HTTPX_JSONL" ]; then
    if ! python3 - "$HTTPX_JSONL" "$HOST" <<'PY'
import json, sys
from urllib.parse import urlparse
path, want = sys.argv[1], sys.argv[2].lower()
with open(path, encoding="utf-8", errors="replace") as handle:
    for raw in handle:
        raw = raw.strip()
        if not raw:
            continue
        try:
            o = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for key in ("host", "input"):
            h = (o.get(key) or "").lower().split(":")[0]
            if h == want:
                sys.exit(0)
        for key in ("url",):
            u = o.get(key) or ""
            h = (urlparse(u).hostname or "").lower()
            if h == want:
                sys.exit(0)
sys.exit(1)
PY
    then
        f_die "Host $HOST is not in this engagement's httpx results."
    fi
fi

# Discover root for UA / wordlists
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DISCOVER_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
UA_FILE="$DISCOVER_ROOT/resource/user-agent.txt"
UA=""
if [ -f "$UA_FILE" ]; then
    UA=$(grep -v '^[[:space:]]*#' "$UA_FILE" | sed '/^[[:space:]]*$/d' | head -n 1)
fi
if [ -z "$UA" ]; then
    UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
fi

SCANS_DIR="$REPORT_ROOT/tools/host-scans"
LOCK="$SCANS_DIR/.lock"
mkdir -p "$SCANS_DIR"

if [ -f "$LOCK" ]; then
    LOCK_PID=$(cut -d' ' -f1 "$LOCK" 2>/dev/null || true)
    if [ -n "$LOCK_PID" ] && kill -0 "$LOCK_PID" 2>/dev/null; then
        f_die "Another host scan is already running (PID $LOCK_PID). One tool at a time."
    fi
    rm -f "$LOCK"
fi

STAMP=$(date -u +"%Y%m%dT%H%M%SZ")
STAMP_DISPLAY=$(date -u +"%m-%d-%Y Z - %H:%M")
RUN_DIR="$SCANS_DIR/$HOST/$TOOL/$STAMP"
mkdir -p "$RUN_DIR"
OUT_FILE="$RUN_DIR/output.txt"
META_FILE="$RUN_DIR/meta.json"
OUT_REL="tools/host-scans/$HOST/$TOOL/$STAMP/output.txt"

printf '%s %s\n' "$$" "$TOOL $HOST" > "$LOCK"

# Status helpers
f_write_status(){
    local running_flag="$1"
    python3 - "$SCANS_DIR" "$HOST" "$TOOL" "$running_flag" "$STAMP_DISPLAY" "$OUT_REL" "$SOFTWARE" "$URL" <<'PY'
import json, sys
from pathlib import Path
base = Path(sys.argv[1])
host, tool, running, finished, out_rel, software, url = sys.argv[2:9]
status_path = base / "status.json"
try:
    status = json.loads(status_path.read_text(encoding="utf-8"))
except Exception:
    status = {}
hosts = status.setdefault("hosts", {})
h = hosts.setdefault(host, {})
entry = {
    "status": "running" if running == "1" else "done",
    "finished": None if running == "1" else finished,
    "finished_display": None if running == "1" else finished,
    "output": out_rel,
    "output_rel": out_rel,
    "software": software or "",
    "url": url,
}
h[tool] = entry
status["running"] = running == "1"
if running == "1":
    status["current"] = {"host": host, "tool": tool, "url": url}
else:
    status["current"] = None
status_path.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
latest = base / host / tool / "latest.json"
latest.parent.mkdir(parents=True, exist_ok=True)
latest.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
PY
}

f_audit(){
    local action="$1"
    local audit_dir="$REPORT_ROOT/tools/audit"
    local audit_log="$audit_dir/log.txt"
    mkdir -p "$audit_dir"
    local ts ip
    ts=$(date -u +"%m-%d-%Y Z - %H:%M")
    ip=$(curl -4 -fsS --connect-timeout 5 --max-time 10 http://ifconfig.me 2>/dev/null | tr -d '[:space:]')
    [ -n "$ip" ] || ip=unknown
    case "$action" in *.) ;; *) action="${action}." ;; esac
    printf '%s | %s | %s\n' "$ts" "$ip" "$action" >> "$audit_log"
}

# Software-aware nuclei tags
f_nuclei_args(){
    local soft_lc
    soft_lc=$(printf '%s' "$SOFTWARE" | tr '[:upper:]' '[:lower:]')
    NUCLEI_EXTRA=()
    if [[ "$soft_lc" == drupal* ]]; then
        NUCLEI_EXTRA=(-tags drupal -c 5 -rl 25)
    elif [[ "$soft_lc" == wordpress* || "$soft_lc" == wp* || "$soft_lc" == jquery* && "$soft_lc" == *wordpress* ]]; then
        NUCLEI_EXTRA=(-tags wordpress -c 5 -rl 25)
    elif [[ "$soft_lc" == joomla* ]]; then
        NUCLEI_EXTRA=(-tags joomla -c 5 -rl 25)
    elif [[ "$soft_lc" == grafana* ]]; then
        NUCLEI_EXTRA=(-tags grafana -c 5 -rl 25)
    elif [[ "$soft_lc" == apache* ]]; then
        NUCLEI_EXTRA=(-tags apache -c 5 -rl 25)
    elif [[ "$soft_lc" == nginx* ]]; then
        NUCLEI_EXTRA=(-tags nginx -c 5 -rl 25)
    else
        # Quiet generic: tech detection / low noise only — not full CVE farm
        NUCLEI_EXTRA=(-tags tech -c 5 -rl 20)
    fi
}

# Quiet ffuf wordlist
f_ffuf_wordlist(){
    local soft_lc
    soft_lc=$(printf '%s' "$SOFTWARE" | tr '[:upper:]' '[:lower:]')
    FFUF_WL=""
    for candidate in \
        /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
        /usr/share/seclists/Discovery/Web-Content/common.txt \
        /usr/share/wordlists/dirb/common.txt
    do
        if [ -f "$candidate" ]; then
            FFUF_WL="$candidate"
            break
        fi
    done
    [ -n "$FFUF_WL" ] || f_die "No small wordlist found (SecLists common.txt). Run Discover Update."
}

cleanup(){
    local code=$?
    rm -f "$LOCK" 2>/dev/null || true
    if [ "${SCAN_STARTED:-0}" -eq 1 ]; then
        f_write_status 0
        # rebuild audit page if possible
        if [ -f "$DISCOVER_ROOT/recon/audit-build.py" ]; then
            python3 "$DISCOVER_ROOT/recon/audit-build.py" "$REPORT_ROOT" \
                "$DISCOVER_ROOT/report/pages/audit.htm" >/dev/null 2>&1 || true
        fi
    fi
    exit "$code"
}
trap cleanup EXIT INT TERM

command -v "$TOOL" >/dev/null 2>&1 || f_die "$TOOL is not installed. Run Discover Update."

SOFT_NOTE=""
[ -n "$SOFTWARE" ] && SOFT_NOTE=" (software: $SOFTWARE)"

f_write_status 1
SCAN_STARTED=1
f_audit "Started $TOOL on $URL$SOFT_NOTE"

cat > "$META_FILE" <<EOF
{
  "tool": "$TOOL",
  "host": "$HOST",
  "url": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$URL"),
  "software": $(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$SOFTWARE"),
  "started_display": "$STAMP_DISPLAY",
  "started_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "output": "$OUT_REL",
  "status": "running"
}
EOF

# Shell-quote a single argument for a reproducible Command: line.
f_shell_quote(){
    python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"
}

# Write Started timestamp + exact Command: header (tools append after this).
f_write_run_header(){
    local cmd="$1"
    {
        echo "Started: $STAMP_DISPLAY"
        echo
        echo "Command:"
        echo "$cmd"
        echo
        echo
    } > "$OUT_FILE"
}

# Nikto 2.1.x has no CLI -useragent; set USERAGENT= via a per-run config.
f_nikto_write_config(){
    local conf_path="$1"
    local ua="$2"
    python3 - "$conf_path" "$ua" <<'PY'
import sys
from pathlib import Path

out = Path(sys.argv[1])
ua = sys.argv[2]
base = ""
for candidate in (Path("/etc/nikto/config.txt"), Path("/etc/nikto.conf")):
    if candidate.is_file():
        base = candidate.read_text(encoding="utf-8", errors="replace")
        break
lines = base.splitlines() if base else []
found = False
new_lines = []
for line in lines:
    if line.startswith("USERAGENT=") or line.startswith("#USERAGENT="):
        new_lines.append("USERAGENT=" + ua)
        found = True
    else:
        new_lines.append(line)
if not found:
    new_lines.append("USERAGENT=" + ua)
out.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
PY
}

echo
echo "============================================================"
echo " Discover host scan (quiet / Red Team defaults)"
echo " Tool:     $TOOL"
echo " Target:   $URL"
echo " Software: ${SOFTWARE:-—}"
echo " Report:   $REPORT_ROOT"
echo " Output:   $OUT_FILE"
echo " UA:       $UA"
echo "============================================================"
echo
echo "[*] OPSEC: single host, one tool, low rate. Ctrl+C to abort."
echo

EXIT_CODE=0
case "$TOOL" in
    nikto)
        # Quiet-ish profile; HTML report is a sidecar so output.txt keeps the header.
        # Nikto 2.1.x: User-Agent via config USERAGENT= (no CLI -useragent).
        NIKTO_HTM="$RUN_DIR/nikto.htm"
        NIKTO_CONF="$RUN_DIR/nikto.conf"
        f_nikto_write_config "$NIKTO_CONF" "$UA"
        NIKTO_CMD="nikto -config $(f_shell_quote "$NIKTO_CONF") -h $(f_shell_quote "$URL") -no404 -maxtime 15m -Format htm -output $(f_shell_quote "$NIKTO_HTM")"
        f_write_run_header "$NIKTO_CMD"
        set +e
        nikto -config "$NIKTO_CONF" -h "$URL" -no404 -maxtime 15m \
            -Format htm -output "$NIKTO_HTM" \
            2>&1 | tee -a "$OUT_FILE"
        EXIT_CODE=${PIPESTATUS[0]}
        set -e
        if [ -f "$NIKTO_HTM" ]; then
            echo "" >> "$OUT_FILE"
            echo "HTML report: $NIKTO_HTM" >> "$OUT_FILE"
        fi
        ;;
    nuclei)
        # Quiet: findings only, no color, no template-update chatter.
        f_nuclei_args
        NUCLEI_OUT="$RUN_DIR/nuclei.txt"
        NUCLEI_CMD="nuclei -u $(f_shell_quote "$URL") -H $(f_shell_quote "User-Agent: $UA")"
        # Extra flags are simple tokens (-tags drupal -c 5 …); do not over-quote.
        if [ "${#NUCLEI_EXTRA[@]}" -gt 0 ]; then
            NUCLEI_CMD+=" ${NUCLEI_EXTRA[*]}"
        fi
        NUCLEI_CMD+=" -silent -nc -duc -o $(f_shell_quote "$NUCLEI_OUT")"
        f_write_run_header "$NUCLEI_CMD"
        set +e
        nuclei -u "$URL" -H "User-Agent: $UA" "${NUCLEI_EXTRA[@]}" \
            -silent -nc -duc \
            -o "$NUCLEI_OUT" 2>&1 | tee -a "$OUT_FILE"
        EXIT_CODE=${PIPESTATUS[0]}
        set -e
        # findings already streamed via -silent; note sidecar path if present
        if [ -f "$NUCLEI_OUT" ] && [ -s "$NUCLEI_OUT" ]; then
            echo "" >> "$OUT_FILE"
            echo "Findings file: $NUCLEI_OUT" >> "$OUT_FILE"
        fi
        ;;
    ffuf)
        f_ffuf_wordlist
        # Ensure URL has FUZZ path
        FFUF_URL="$URL"
        if [[ "$FFUF_URL" != *FUZZ* ]]; then
            FFUF_URL="${FFUF_URL%/}/FUZZ"
        fi
        FFUF_JSON="$RUN_DIR/ffuf.json"
        FFUF_CMD="ffuf -u $(f_shell_quote "$FFUF_URL") -w $(f_shell_quote "$FFUF_WL") -t 8 -rate 20 -H $(f_shell_quote "User-Agent: $UA") -of json -o $(f_shell_quote "$FFUF_JSON") -mc 200,204,301,302,307,401,403"
        f_write_run_header "$FFUF_CMD"
        set +e
        ffuf -u "$FFUF_URL" -w "$FFUF_WL" -t 8 -rate 20 \
            -H "User-Agent: $UA" \
            -of json -o "$FFUF_JSON" \
            -mc 200,204,301,302,307,401,403 \
            2>&1 | tee -a "$OUT_FILE"
        EXIT_CODE=${PIPESTATUS[0]}
        set -e
        if [ -f "$FFUF_JSON" ]; then
            echo "" >> "$OUT_FILE"
            echo "JSON results: $FFUF_JSON" >> "$OUT_FILE"
        fi
        ;;
esac

FINISHED=$(date -u +"%m-%d-%Y Z - %H:%M")
python3 - "$META_FILE" "$FINISHED" "$EXIT_CODE" <<'PY'
import json, sys
path, finished, code = sys.argv[1], sys.argv[2], int(sys.argv[3])
meta = json.load(open(path, encoding="utf-8"))
meta["status"] = "done" if code == 0 else "failed"
meta["finished_display"] = finished
from datetime import datetime, timezone
meta["finished_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
meta["exit_code"] = code
json.dump(meta, open(path, "w", encoding="utf-8"), indent=2)
open(path, "a", encoding="utf-8").write("\n")
PY

f_write_status 0
f_audit "Finished $TOOL on $URL (exit $EXIT_CODE)$SOFT_NOTE"

# Rebuild audit page
if [ -f "$DISCOVER_ROOT/recon/audit-build.py" ]; then
    python3 "$DISCOVER_ROOT/recon/audit-build.py" "$REPORT_ROOT" \
        "$DISCOVER_ROOT/report/pages/audit.htm" >/dev/null 2>&1 || true
fi

echo
echo "============================================================"
echo "[*] Done. Exit code: $EXIT_CODE"
echo "[*] Output: $OUT_FILE"
echo "============================================================"
echo
echo "Press Enter to close this terminal."
read -r _
exit "$EXIT_CODE"
