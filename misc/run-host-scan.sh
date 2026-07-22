#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Operator host scan launcher (Red Team quiet defaults).
# Invoked via discover-scan: scheme or CLI:
#   run-host-scan.sh <tool> <url> [software] [report_root]
#
# Tools: nuclei | droopescan | wpscan | nikto | ffuf  (quietest → loudest)
# - Visible terminal (desktop entry uses Terminal=true)
# - One scan at a time (engagement lock)
# - Software-aware nuclei/ffuf/droopescan/wpscan profiles
# - Nuclei is two-pass auto: (1) software tags recon, (2) CVE/KEV IDs
# - droopescan only when software is a supported CMS (Drupal, WP, …)
# - wpscan only when software is WordPress

set -euo pipefail

# Prefer user pipx (Python 3.14-patched) over a broken system install.
export PATH="${HOME}/.local/bin:/usr/local/bin:${PATH:-/usr/bin:/bin}"

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

[[ "$TOOL" =~ ^(nikto|nuclei|ffuf|droopescan|wpscan)$ ]] || f_die "Tool must be nuclei, droopescan, wpscan, nikto, or ffuf."
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

# Software-aware nuclei tags (pass-1 recon / fingerprint)
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

# Pass-2: CVE/KEV template IDs that nuclei can actually run.
# Sources (priority):
#   1) Engagement software-cves-cache (KEV first, then high CVSS) ∩ local templates
#   2) Local nuclei-templates CVE YAML tagged/named for this product (fills NVD gaps)
# Prints: "ID1,ID2,...|kev_count|total|note" or empty if nothing runnable.
f_nuclei_pass2_ids(){
    python3 - "$REPORT_ROOT" "$SOFTWARE" "$DISCOVER_ROOT" <<'PY'
import json
import re
import sys
from pathlib import Path

report_root = Path(sys.argv[1])
software = (sys.argv[2] or "").strip()
discover_root = Path(sys.argv[3])
max_ids = 30
min_score = 7.0

if not software:
    sys.exit(0)

label = software
product, version = "", ""
m = re.match(r"^([^:\[]+)\[(.+)\]$", label)
if m:
    product, version = m.group(1).strip(), m.group(2).strip()
elif ":" in label:
    product, version = [p.strip() for p in label.split(":", 1)]
else:
    product, version = label, ""

prod_key = re.sub(r"[-_\s]+", " ", product.lower()).strip()
if not prod_key:
    sys.exit(0)
cache_key = f"{prod_key}|{version}" if version else prod_key

# --- local nuclei templates (only IDs that can actually run) ---
def find_templates_root() -> Path | None:
    env = (Path.home() / "nuclei-templates")
    candidates = [
        Path.home() / "nuclei-templates",
        Path.home() / ".local" / "nuclei-templates",
        Path.home() / ".local" / "share" / "nuclei" / "templates",
        Path("/opt/nuclei-templates"),
        Path("/usr/share/nuclei-templates"),
    ]
    # config may point at custom dir
    cfg = Path.home() / ".config" / "nuclei" / "config.yaml"
    if cfg.is_file():
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("templates-directory:") or line.startswith("#templates-directory:"):
                    # skip comments unless value present after
                    if line.startswith("#"):
                        continue
                    val = line.split(":", 1)[1].strip().strip("'\"")
                    if val:
                        candidates.insert(0, Path(val).expanduser())
        except OSError:
            pass
    for c in candidates:
        if c.is_dir() and any(c.rglob("CVE-*.yaml")):
            return c
    return None


templates_root = find_templates_root()
template_ids: set[str] = set()
product_template_ids: list[str] = []
if templates_root is not None:
    for p in templates_root.rglob("CVE-*.yaml"):
        cid = p.stem.upper()
        if not cid.startswith("CVE-"):
            continue
        template_ids.add(cid)
        # Product-linked CVE templates (tags/body mention product)
        try:
            head = p.read_text(encoding="utf-8", errors="replace")[:4000].lower()
        except OSError:
            continue
        # require product token in tags line or metadata vendor/product
        if (
            f" {prod_key}" in f" {head.replace(',', ' ').replace(':', ' ')}"
            or f"tags:" in head
            and prod_key in head
        ):
            # tighter: tags/vendor/product fields
            if re.search(
                rf"(?m)^\s*(tags:|vendor:|product:).*{re.escape(prod_key)}",
                head,
            ) or re.search(
                rf"(?m)^\s*tags:.*\b{re.escape(prod_key)}\b",
                head,
            ):
                product_template_ids.append(cid)

    product_template_ids = sorted(set(product_template_ids))

# --- KEV catalog ---
kev_ids: set[str] = set()
kev_path = discover_root / "resource" / "known_exploited_vulnerabilities.json"
if kev_path.is_file():
    try:
        payload = json.loads(kev_path.read_text(encoding="utf-8"))
        for row in payload.get("vulnerabilities") or []:
            if not isinstance(row, dict):
                continue
            cid = (row.get("cveID") or row.get("cve_id") or "").strip().upper()
            if cid.startswith("CVE-"):
                kev_ids.add(cid)
    except (OSError, json.JSONDecodeError):
        pass

# --- engagement NVD cache ---
entry = None
cache_path = report_root / "tools" / "software-cves-cache.json"
if cache_path.is_file():
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        entries = cache.get("entries") or {}
        entry = entries.get(cache_key)
        if not isinstance(entry, dict):
            for k, v in entries.items():
                if isinstance(v, dict) and (k == prod_key or k.startswith(prod_key + "|")):
                    entry = v
                    break
    except (OSError, json.JSONDecodeError):
        entry = None

def sort_key(item: dict) -> tuple:
    return (item.get("score") is None, -(item.get("score") or 0), item.get("id") or "")

normalized: list[dict] = []
if isinstance(entry, dict):
    for row in entry.get("cves") or []:
        if not isinstance(row, dict):
            continue
        cid = (row.get("id") or "").strip().upper()
        if not cid.startswith("CVE-"):
            continue
        normalized.append(
            {"id": cid, "score": row.get("score"), "is_kev": cid in kev_ids}
        )

picked: list[str] = []
seen: set[str] = set()

def add(cid: str) -> None:
    cid = (cid or "").strip().upper()
    if not cid.startswith("CVE-") or cid in seen or len(picked) >= max_ids:
        return
    # Only IDs nuclei can load (when we know the catalog)
    if template_ids and cid not in template_ids:
        return
    seen.add(cid)
    picked.append(cid)

# 1) Cache KEV with templates
for c in sorted([c for c in normalized if c["is_kev"]], key=sort_key):
    add(c["id"])
# 2) Cache top_cve
if isinstance(entry, dict):
    add((entry.get("top_cve") or "").strip().upper())
# 3) Cache high CVSS with templates
for c in sorted(
    [
        c
        for c in normalized
        if not c["is_kev"]
        and c.get("score") is not None
        and float(c["score"]) >= min_score
    ],
    key=sort_key,
):
    add(c["id"])
# 4) Product CVE templates from local nuclei catalog (covers NVD gaps
#    e.g. CVE-2014-3704 for Drupal even when CPE cache is incomplete)
for cid in product_template_ids:
    # KEV product templates first
    if cid in kev_ids:
        add(cid)
for cid in product_template_ids:
    add(cid)

# 5) Fallback: any remaining cache IDs that have templates
if not picked:
    for c in sorted(normalized, key=sort_key):
        add(c["id"])

if not picked:
    sys.exit(0)

kev_n = sum(1 for cid in picked if cid in kev_ids)
# note for logs: how many cache IDs lacked templates
cache_ids = {c["id"] for c in normalized}
cache_with_tpl = sum(1 for cid in cache_ids if cid in template_ids) if template_ids else 0
note = f"templates={len(picked)};cache_cves={len(cache_ids)};cache_with_template={cache_with_tpl};product_tpl={len(product_template_ids)}"
print(f"{','.join(picked)}|{kev_n}|{len(picked)}|{note}")
PY
}

# If nuclei wrote no findings, leave a clear operator-facing message (not a blank file).
f_nuclei_ensure_findings_message(){
    local path="$1"
    if [ ! -f "$path" ] || [ ! -s "$path" ]; then
        printf '%s\n' "No vulnerabilities discovered." > "$path"
    fi
}

# Strip ANSI / progress junk (ffuf draws progress with ESC sequences that show as
# little boxes with stacked numbers in plain text viewers).
f_clean_scan_text(){
    python3 -c '
import re, sys
raw = sys.stdin.read()
# CSI / OSC / charset ANSI
raw = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", raw)
raw = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", raw)
raw = re.sub(r"\x1b[()][0-9A-B]", "", raw)
raw = re.sub(r"\x1b.", "", raw)
raw = raw.replace("\r\n", "\n").replace("\r", "\n")
out = []
prev_empty = False
for ln in raw.splitlines():
    s = ln.strip()
    # Drop live progress lines
    if re.match(r"^::\s*Progress:", s, re.I) or re.match(r"^Progress:", s, re.I):
        continue
    if re.search(r"\bReq/sec\b", s) and re.search(r"\bErrors\b", s, re.I):
        continue
    empty = not s
    if empty and prev_empty:
        continue
    # Drop per-hit timing only (keep Status, Size, Words, Lines)
    ln = re.sub(r",\s*Duration:\s*\d+ms", "", ln, flags=re.I)
    out.append(ln.rstrip())
    prev_empty = empty
sys.stdout.write("\n".join(out))
if out:
    sys.stdout.write("\n")
'
}

# Map Discover software label → droopescan CMS plugin (empty if unsupported).
f_droopescan_cms(){
    local soft_lc base
    soft_lc=$(printf '%s' "${SOFTWARE:-}" | tr '[:upper:]' '[:lower:]')
    soft_lc="${soft_lc%%[*}"
    base="${soft_lc%%:*}"
    base="${base// /}"
    case "$base" in
        drupal) printf '%s' "drupal" ;;
        wordpress|wp) printf '%s' "wordpress" ;;
        joomla) printf '%s' "joomla" ;;
        moodle) printf '%s' "moodle" ;;
        silverstripe|ss) printf '%s' "silverstripe" ;;
        *) printf '%s' "" ;;
    esac
}

# True when software filter is WordPress (for wpscan gating).
f_is_wordpress(){
    local soft_lc base
    soft_lc=$(printf '%s' "${SOFTWARE:-}" | tr '[:upper:]' '[:lower:]')
    soft_lc="${soft_lc%%[*}"
    base="${soft_lc%%:*}"
    base="${base// /}"
    case "$base" in
        wordpress|wp) return 0 ;;
        *) return 1 ;;
    esac
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

if [ "$TOOL" = "nikto" ]; then
    # GitHub install: wrapper and/or /opt/nikto/program/nikto.pl (see update.sh)
    if [ ! -x /usr/local/bin/nikto ] && [ ! -f /opt/nikto/program/nikto.pl ] \
        && ! command -v nikto >/dev/null 2>&1; then
        f_die "Nikto is not installed. Run Discover Update (GitHub sullo/nikto → /opt/nikto)."
    fi
else
    command -v "$TOOL" >/dev/null 2>&1 || f_die "$TOOL is not installed. Run Discover Update."
fi

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

# Resolve Nikto binary (GitHub install via update.sh → /usr/local/bin/nikto).
f_nikto_bin(){
    if [ -x /usr/local/bin/nikto ]; then
        echo /usr/local/bin/nikto
        return 0
    fi
    if [ -f /opt/nikto/program/nikto.pl ]; then
        echo /opt/nikto/program/nikto.pl
        return 0
    fi
    command -v nikto 2>/dev/null || true
}

# Per-run config: non-interactive, no telemetry/RFI, HTTP/1.1 + GET discovery.
# Base from GitHub install; UA is also passed as -useragent (Nikto 2.5+).
f_nikto_write_config(){
    local conf_path="$1"
    local ua="$2"
    python3 - "$conf_path" "$ua" <<'PY'
import sys
from pathlib import Path

out = Path(sys.argv[1])
ua = sys.argv[2]
base = ""
for candidate in (
    Path("/opt/nikto/program/nikto.conf"),
    Path("/opt/nikto/program/nikto.conf.default"),
    Path("/etc/nikto/config.txt"),
    Path("/etc/nikto.conf"),
):
    if candidate.is_file():
        base = candidate.read_text(encoding="utf-8", errors="replace")
        break

force = {
    "USERAGENT": ua,
    "PROMPTS": "no",
    "UPDATES": "no",
    "DEFAULTHTTPVER": "1.1",
    "CHECKMETHODS": "GET",
}
comment_keys = {"RFIURL"}

seen: set[str] = set()
new_lines: list[str] = []
for raw in base.splitlines() if base else []:
    stripped = raw.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        key = stripped.split("=", 1)[0].strip()
        if key in comment_keys:
            new_lines.append("#" + raw if not raw.lstrip().startswith("#") else raw)
            continue
        if key in force:
            if key not in seen:
                new_lines.append(f"{key}={force[key]}")
                seen.add(key)
            continue
        new_lines.append(raw)
        continue
    new_lines.append(raw)

for key, value in force.items():
    if key not in seen:
        new_lines.append(f"{key}={value}")

out.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
PY
}

# Pre-flight: can curl reach the URL with HTTP/1.1?
# Returns 0 = try Nikto, 1 = skip Nikto (unreachable / no HTTP response).
f_nikto_precheck(){
    local url="$1"
    local code time_total http10

    if ! command -v curl >/dev/null 2>&1; then
        echo "[*] curl not available — skipping pre-check."
        return 0
    fi

    echo "[*] Pre-check (curl HTTP/1.1 GET, 15s)…"
    code=$(curl -sS -k -o /dev/null -w "%{http_code}" \
        --http1.1 --connect-timeout 8 --max-time 15 \
        -A "$UA" \
        "$url" 2>/dev/null) || code="000"
    time_total=$(curl -sS -k -o /dev/null -w "%{time_total}" \
        --http1.1 --connect-timeout 8 --max-time 15 \
        -A "$UA" \
        "$url" 2>/dev/null) || time_total="?"

    if [ -z "$code" ] || [ "$code" = "000" ]; then
        echo "[!] Pre-check failed: no HTTP response from $url within 15s."
        echo "    Skipping Nikto. Verify the host is reachable from this network."
        return 1
    fi

    echo "[*] Pre-check OK: HTTP $code in ${time_total}s (HTTP/1.1)."

    http10=$(curl -sS -k -o /dev/null -w "%{http_code}" \
        --http1.0 --connect-timeout 5 --max-time 10 \
        -A "$UA" \
        "$url" 2>/dev/null) || http10="000"
    if [ "$http10" = "426" ]; then
        echo "[*] Note: HTTP/1.0 returns 426 Upgrade Required (common on Azure ALB)."
        echo "    Discover uses DEFAULTHTTPVER=1.1 and CHECKMETHODS=GET."
    fi

    return 0
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
        # GitHub Nikto 2.5+/2.6 (update.sh → /opt/nikto): TLS SNI in bundled LW2,
        # -useragent / -nointeractive / -nocheck; hard wall via timeout 16m.
        NIKTO_BIN=$(f_nikto_bin)
        if [ -z "$NIKTO_BIN" ]; then
            {
                echo "[!] Nikto not found. Run Discover Update (installs sullo/nikto to /opt/nikto)."
            } | tee -a "$OUT_FILE"
            EXIT_CODE=1
        else
            NIKTO_HTM="$RUN_DIR/nikto.htm"
            NIKTO_CONF="$RUN_DIR/nikto.conf"
            NIKTO_MAXTIME="15m"
            NIKTO_HARD_TIMEOUT="16m"
            # -ssl skips plain-HTTP probe on :443.
            NIKTO_SSL_FLAG=""
            if [[ "$URL" =~ ^https:// ]]; then
                NIKTO_SSL_FLAG="-ssl"
            fi
            f_nikto_write_config "$NIKTO_CONF" "$UA"
            NIKTO_CMD="$(f_shell_quote "$NIKTO_BIN") -config $(f_shell_quote "$NIKTO_CONF") -host $(f_shell_quote "$URL")${NIKTO_SSL_FLAG:+ $NIKTO_SSL_FLAG} -useragent $(f_shell_quote "$UA") -nointeractive -nocheck -maxtime $NIKTO_MAXTIME -Format htm -output $(f_shell_quote "$NIKTO_HTM")"
            f_write_run_header "$NIKTO_CMD"
            {
                echo "[*] Nikto: $NIKTO_BIN"
                echo "[*] Non-interactive (PROMPTS=no, UPDATES=no, -nointeractive -nocheck);"
                echo "    HTTP/1.1 + GET; maxtime ${NIKTO_MAXTIME}; hard stop ${NIKTO_HARD_TIMEOUT}."
                echo
            } | tee -a "$OUT_FILE"

            set +e
            PRECHECK_OUT=$(f_nikto_precheck "$URL" 2>&1)
            PRECHECK_RC=$?
            set -e
            printf '%s\n' "$PRECHECK_OUT" | tee -a "$OUT_FILE"
            echo | tee -a "$OUT_FILE"

            if [ "$PRECHECK_RC" -ne 0 ]; then
                {
                    echo "[!] Nikto skipped after failed pre-check."
                    echo "    Result: no scan (host not answering HTTP from this network)."
                } | tee -a "$OUT_FILE"
                EXIT_CODE=1
            else
                set +e
                # shellcheck disable=SC2086
                if command -v timeout >/dev/null 2>&1; then
                    timeout --foreground --signal=TERM --kill-after=45s "$NIKTO_HARD_TIMEOUT" \
                        "$NIKTO_BIN" -config "$NIKTO_CONF" -host "$URL" $NIKTO_SSL_FLAG \
                        -useragent "$UA" -nointeractive -nocheck \
                        -maxtime "$NIKTO_MAXTIME" \
                        -Format htm -output "$NIKTO_HTM" \
                        2>&1 | tee -a "$OUT_FILE"
                    EXIT_CODE=${PIPESTATUS[0]}
                else
                    "$NIKTO_BIN" -config "$NIKTO_CONF" -host "$URL" $NIKTO_SSL_FLAG \
                        -useragent "$UA" -nointeractive -nocheck \
                        -maxtime "$NIKTO_MAXTIME" \
                        -Format htm -output "$NIKTO_HTM" \
                        2>&1 | tee -a "$OUT_FILE"
                    EXIT_CODE=${PIPESTATUS[0]}
                fi
                set -e

                if [ "${EXIT_CODE:-0}" -eq 124 ]; then
                    {
                        echo
                        echo "[*] Discover hard stop: Nikto exceeded ${NIKTO_HARD_TIMEOUT} wall clock (maxtime ${NIKTO_MAXTIME} + grace)."
                        echo "    Scan stopped automatically — no operator input required."
                    } | tee -a "$OUT_FILE"
                    EXIT_CODE=0
                fi

                if grep -q 'No web server found on' "$OUT_FILE" 2>/dev/null; then
                    {
                        echo
                        echo "[!] Nikto host discovery failed: no web server found (0 hosts tested)."
                        echo "    Pre-check may still have seen HTTP. Treat as inconclusive;"
                        echo "    use nuclei/ffuf/manual review instead."
                        echo "    (Maxtime ERROR lines can appear even on short runs when discovery fails.)"
                    } | tee -a "$OUT_FILE"
                    EXIT_CODE=1
                fi
            fi

            if [ -f "$NIKTO_HTM" ]; then
                echo "" >> "$OUT_FILE"
                echo "HTML report: $NIKTO_HTM" >> "$OUT_FILE"
            fi
        fi
        ;;
    nuclei)
        # Pass 1: software-tagged recon. Pass 2: auto CVE/KEV from cache.
        # output.txt layout is fixed (Command → Results/Findings → paths); do not tee
        # live nuclei lines into the report file.
        f_nuclei_args
        NUCLEI_OUT="$RUN_DIR/nuclei.txt"
        NUCLEI_CMD="nuclei -u $(f_shell_quote "$URL") -H $(f_shell_quote "User-Agent: $UA")"
        if [ "${#NUCLEI_EXTRA[@]}" -gt 0 ]; then
            NUCLEI_CMD+=" ${NUCLEI_EXTRA[*]}"
        fi
        NUCLEI_CMD+=" -silent -nc -duc -o $(f_shell_quote "$NUCLEI_OUT")"

        {
            echo "Started: $STAMP_DISPLAY"
            echo
            echo "=== Pass 1: software recon tags ==="
            echo
            echo "Command:"
            echo "$NUCLEI_CMD"
            echo
        } > "$OUT_FILE"

        echo "[*] Pass 1: software recon (${NUCLEI_EXTRA[*]:-tags tech})"
        set +e
        # Findings go to -o only; keep terminal visible but keep output.txt structured.
        nuclei -u "$URL" -H "User-Agent: $UA" "${NUCLEI_EXTRA[@]}" \
            -silent -nc -duc \
            -o "$NUCLEI_OUT"
        PASS1_CODE=$?
        set -e
        EXIT_CODE=$PASS1_CODE
        f_nuclei_ensure_findings_message "$NUCLEI_OUT"
        {
            echo "Results:"
            cat "$NUCLEI_OUT"
            echo
            echo "Output:"
            echo "$NUCLEI_OUT"
            echo
        } >> "$OUT_FILE"

        # Pass 2: CVE/KEV IDs that exist as local nuclei templates (+ product CVE YAMLs).
        PASS2_META=$(f_nuclei_pass2_ids || true)
        PASS2_IDS=""
        PASS2_KEV_N=0
        PASS2_TOTAL=0
        PASS2_NOTE=""
        if [ -n "$PASS2_META" ]; then
            PASS2_IDS=$(printf '%s' "$PASS2_META" | cut -d'|' -f1)
            PASS2_KEV_N=$(printf '%s' "$PASS2_META" | cut -d'|' -f2)
            PASS2_TOTAL=$(printf '%s' "$PASS2_META" | cut -d'|' -f3)
            PASS2_NOTE=$(printf '%s' "$PASS2_META" | cut -d'|' -f4-)
        fi

        if [ -n "$PASS2_IDS" ]; then
            NUCLEI_PASS2_OUT="$RUN_DIR/nuclei-pass2.txt"
            NUCLEI_PASS2_CMD="nuclei -u $(f_shell_quote "$URL") -H $(f_shell_quote "User-Agent: $UA") -id $(f_shell_quote "$PASS2_IDS") -c 5 -rl 25 -timeout 15 -retries 1 -silent -nc -duc -o $(f_shell_quote "$NUCLEI_PASS2_OUT")"
            # Comma-space list for readability in the report
            PASS2_IDS_DISPLAY=$(printf '%s' "$PASS2_IDS" | sed 's/,/, /g')
            {
                echo "=== Pass 2: CVE and KEV templates ==="
                echo
                echo "Software:"
                echo "${SOFTWARE:-—}"
                echo
                echo "Templates (${PASS2_TOTAL:-?}, KEV ${PASS2_KEV_N:-?}):"
                echo "$PASS2_IDS_DISPLAY"
                echo
                echo "Selection:"
                echo "${PASS2_NOTE:-(none)}"
                echo
                echo "Command:"
                echo "$NUCLEI_PASS2_CMD"
                echo
            } >> "$OUT_FILE"
            echo
            echo "[*] Pass 2: CVE and KEV templates (${PASS2_TOTAL:-?} runnable, ${PASS2_KEV_N:-?} KEV)"
            # Do not audit pass-2 start/finish — covered by parent nuclei Started/Finished + Output.
            set +e
            nuclei -u "$URL" -H "User-Agent: $UA" \
                -id "$PASS2_IDS" \
                -c 5 -rl 25 \
                -timeout 15 -retries 1 \
                -silent -nc -duc \
                -o "$NUCLEI_PASS2_OUT"
            PASS2_CODE=$?
            set -e
            if [ "$PASS2_CODE" -ne 0 ] && [ "$EXIT_CODE" -eq 0 ]; then
                EXIT_CODE=$PASS2_CODE
            fi
            f_nuclei_ensure_findings_message "$NUCLEI_PASS2_OUT"
            {
                echo "Findings:"
                cat "$NUCLEI_PASS2_OUT"
                echo
            } >> "$OUT_FILE"
            # Do not audit "Finished nuclei pass-2 …" — redundant with parent Finished + Output.
            python3 - "$META_FILE" "$PASS2_IDS" "${PASS2_KEV_N:-0}" "${PASS2_TOTAL:-0}" "${PASS2_CODE:-1}" "${PASS2_NOTE:-}" <<'PY'
import json, sys
path, ids, kev_n, total, code, note = sys.argv[1:7]
try:
    meta = json.load(open(path, encoding="utf-8"))
except Exception:
    meta = {}
meta["pass2"] = {
    "ids": [x for x in ids.split(",") if x],
    "kev_count": int(kev_n) if str(kev_n).isdigit() else kev_n,
    "id_count": int(total) if str(total).isdigit() else total,
    "exit_code": int(code) if str(code).lstrip("-").isdigit() else code,
    "selection": note,
    "output": "nuclei-pass2.txt",
}
json.dump(meta, open(path, "w", encoding="utf-8"), indent=2)
open(path, "a", encoding="utf-8").write("\n")
PY
        else
            {
                echo "=== Pass 2: skipped ==="
                echo
                echo "No runnable CVE templates for software '${SOFTWARE:-—}'."
                echo "Need Active CVE cache and/or local nuclei-templates CVE YAML for this product."
                echo
            } >> "$OUT_FILE"
            echo "[*] Pass 2: skipped (no runnable CVE templates for this software)"
        fi
        ;;
    droopescan)
        CMS=$(f_droopescan_cms)
        [ -n "$CMS" ] || f_die "droopescan requires CMS software (Drupal, WordPress, Joomla, Moodle, Silverstripe). Got: ${SOFTWARE:-none}"
        command -v droopescan >/dev/null 2>&1 || f_die "droopescan is not installed (or not on PATH). Run Discover Update; prefer ~/.local/bin after Python 3.14 patch."
        DROOP_OUT="$RUN_DIR/droopescan.txt"
        # Quiet-ish: all enums, modest threads, standard text output.
        DROOP_CMD="droopescan scan $CMS -u $(f_shell_quote "$URL") -e a -t 4 -o standard"
        f_write_run_header "$DROOP_CMD"
        {
            echo "CMS: $CMS"
            echo "Software: ${SOFTWARE:-—}"
            echo
        } >> "$OUT_FILE"
        echo "[*] droopescan scan $CMS on $URL"
        set +e
        # Capture full text report (stdout+stderr); also keep a sidecar copy.
        droopescan scan "$CMS" -u "$URL" -e a -t 4 -o standard \
            2>&1 | tee "$DROOP_OUT" | tee -a "$OUT_FILE"
        EXIT_CODE=${PIPESTATUS[0]}
        set -e
        if [ ! -s "$DROOP_OUT" ]; then
            printf '%s\n' "No droopescan output captured." > "$DROOP_OUT"
        fi
        {
            echo
            echo "Output: $DROOP_OUT"
            echo
        } >> "$OUT_FILE"
        ;;
    wpscan)
        f_is_wordpress || f_die "wpscan requires WordPress software filter. Got: ${SOFTWARE:-none}"
        command -v wpscan >/dev/null 2>&1 || f_die "wpscan is not installed. Run Discover Update (gem install wpscan)."
        WPSCAN_OUT="$RUN_DIR/wpscan.txt"
        # Quiet-ish Red Team defaults: passive plugin detection + moderate enum.
        # Optional free API token: export WPSCAN_API_TOKEN=… (vuln DB lookups).
        WPSCAN_CMD="wpscan --url $(f_shell_quote "$URL") --random-user-agent --user-agent $(f_shell_quote "$UA") --disable-tls-checks --plugins-detection passive --enumerate vp,vt,tt,cb,dbe,u --format cli-no-colour --no-banner"
        if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
            WPSCAN_CMD+=" --api-token $(f_shell_quote "$WPSCAN_API_TOKEN")"
        fi
        f_write_run_header "$WPSCAN_CMD"
        {
            echo "Software: ${SOFTWARE:-—}"
            if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
                echo "API token: set (WPSCAN_API_TOKEN)"
            else
                echo "API token: not set (optional — free token improves vuln matching)"
            fi
            echo
        } >> "$OUT_FILE"
        echo "[*] wpscan on $URL"
        set +e
        if [ -n "${WPSCAN_API_TOKEN:-}" ]; then
            wpscan --url "$URL" \
                --random-user-agent --user-agent "$UA" \
                --disable-tls-checks \
                --plugins-detection passive \
                --enumerate vp,vt,tt,cb,dbe,u \
                --format cli-no-colour --no-banner \
                --api-token "$WPSCAN_API_TOKEN" \
                2>&1 | tee "$WPSCAN_OUT" | tee -a "$OUT_FILE"
        else
            wpscan --url "$URL" \
                --random-user-agent --user-agent "$UA" \
                --disable-tls-checks \
                --plugins-detection passive \
                --enumerate vp,vt,tt,cb,dbe,u \
                --format cli-no-colour --no-banner \
                2>&1 | tee "$WPSCAN_OUT" | tee -a "$OUT_FILE"
        fi
        EXIT_CODE=${PIPESTATUS[0]}
        set -e
        if [ ! -s "$WPSCAN_OUT" ]; then
            printf '%s\n' "No wpscan output captured." > "$WPSCAN_OUT"
        fi
        {
            echo
            echo "Output: $WPSCAN_OUT"
            echo
        } >> "$OUT_FILE"
        ;;
    ffuf)
        f_ffuf_wordlist
        # Ensure URL has FUZZ path
        FFUF_URL="$URL"
        if [[ "$FFUF_URL" != *FUZZ* ]]; then
            FFUF_URL="${FFUF_URL%/}/FUZZ"
        fi
        FFUF_JSON="$RUN_DIR/ffuf.json"
        # Quiet default: no custom -mc (use ffuf defaults: 2xx,301,302,307,500,…)
        # Filter noise with -fc. Keep 2xx + 500s (version banners). Drop auth/forbid,
        # empty, rate-limit, and redirects (301/302/307 are often real paths that still
        # aren't useful to open anonymously — clutter for operators).
        FFUF_FC="301,302,307,400,401,403,404,405,429"
        FFUF_CMD="ffuf -u $(f_shell_quote "$FFUF_URL") -w $(f_shell_quote "$FFUF_WL") -t 8 -rate 20 -H $(f_shell_quote "User-Agent: $UA") -of json -o $(f_shell_quote "$FFUF_JSON") -fc $FFUF_FC -noninteractive"
        f_write_run_header "$FFUF_CMD"
        FFUF_RAW="$RUN_DIR/ffuf.raw.txt"
        set +e
        ffuf -u "$FFUF_URL" -w "$FFUF_WL" -t 8 -rate 20 \
            -H "User-Agent: $UA" \
            -of json -o "$FFUF_JSON" \
            -fc "$FFUF_FC" \
            -noninteractive \
            2>&1 | tee "$FFUF_RAW"
        EXIT_CODE=${PIPESTATUS[0]}
        set -e
        # Append cleaned text to operator report (no ESC boxes / progress spam).
        if [ -f "$FFUF_RAW" ]; then
            f_clean_scan_text < "$FFUF_RAW" >> "$OUT_FILE"
            rm -f "$FFUF_RAW"
        fi
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
# Omit "(exit 0)" — success is the default; keep non-zero exits visible.
if [ "${EXIT_CODE:-1}" -eq 0 ]; then
    f_audit "Finished $TOOL on $URL$SOFT_NOTE"
else
    f_audit "Finished $TOOL on $URL (exit $EXIT_CODE)$SOFT_NOTE"
fi

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
