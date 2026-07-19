#!/usr/bin/env bash

# Planning by Lee Baird (@discoverscripts)
# Coded by Grok (xAI)
#
# Enrich an engagement report with Shodan host-by-IP data (membership API).
# Requires SHODAN_API_KEY (shell export or private .env). Soft-skips without a key.
# Reads unique public IPs from tools/httpx.jsonl (run Active first).

BLUE=${BLUE:-'\033[1;34m'}
YELLOW=${YELLOW:-'\033[1;33m'}
RED=${RED:-'\033[1;31m'}
NC=${NC:-'\033[0m'}
SMALL=${SMALL:-'========================================'}
MEDIUM=${MEDIUM:-'=================================================================='}

if ! declare -F f_banner >/dev/null 2>&1; then
    f_banner(){ echo; }
fi

f_shodan_die(){
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

f_shodan_is_report_dir(){
    local dir="$1"

    [ -n "$dir" ] || return 1
    [ -d "$dir" ] || return 1
    [ -r "$dir" ] || return 1
    [ -x "$dir" ] || return 1
    [ -d "$dir/pages" ] || return 1
    [ -f "$dir/index.htm" ] || [ -f "$dir/pages/active.htm" ] || [ -f "$dir/pages/subdomains.htm" ] || [ -f "$dir/pages/passive.htm" ]
}

f_shodan_discover_root(){
    if [ -n "${DISCOVER:-}" ] && [ -d "$DISCOVER" ]; then
        printf '%s' "$DISCOVER"
        return 0
    fi
    if [ -f "$(dirname "$0")/../discover.sh" ]; then
        (cd "$(dirname "$0")/.." && pwd)
        return 0
    fi
    return 1
}

# Load private .env files without overriding non-empty shell exports.
f_shodan_load_env(){
    local env_file line key value root

    root="$(f_shodan_discover_root 2>/dev/null || true)"
    if [ -z "$root" ]; then
        root="$(cd "$(dirname "$0")/.." && pwd)"
    fi
    DISCOVER="${DISCOVER:-$root}"
    export DISCOVER

    for env_file in "$DISCOVER/.env" "$HOME/.discover/.env"; do
        [ -f "$env_file" ] || continue
        while IFS= read -r line || [ -n "$line" ]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            [ -z "$line" ] && continue
            case "$line" in
                \#*) continue ;;
            esac
            case "$line" in
                export\ *) line="${line#export }"
                    line="${line#"${line%%[![:space:]]*}"}"
                    ;;
            esac
            case "$line" in
                *=*) ;;
                *) continue ;;
            esac
            key="${line%%=*}"
            value="${line#*=}"
            key="${key%"${key##*[![:space:]]}"}"
            key="${key#"${key%%[![:space:]]*}"}"
            case "$key" in
                ''|*[!A-Za-z0-9_]*|[0-9]*) continue ;;
            esac
            value="${value#"${value%%[![:space:]]*}"}"
            value="${value%"${value##*[![:space:]]}"}"
            if [ "${#value}" -ge 2 ]; then
                if [ "${value:0:1}" = '"' ] && [ "${value: -1}" = '"' ]; then
                    value="${value:1:${#value}-2}"
                elif [ "${value:0:1}" = "'" ] && [ "${value: -1}" = "'" ]; then
                    value="${value:1:${#value}-2}"
                fi
            fi
            if [ -n "${!key:-}" ]; then
                continue
            fi
            export "$key=$value"
        done < "$env_file"
    done
}

clear
f_banner

echo -e "${BLUE}Enrich with Shodan.${NC}"
echo
echo "Look up public IPs from Active httpx output in the Shodan host database."
echo "Requires a membership (or higher) API key. IP lookups do not use query credits."
echo

f_shodan_load_env

# Prefer session engagement from Import report / Active.
SESSION_FILE="${HOME}/.discover/current-report"
DEFAULT_REPORT=""
if [ -f "$SESSION_FILE" ]; then
    DEFAULT_REPORT=$(head -n 1 "$SESSION_FILE" 2>/dev/null)
    DEFAULT_REPORT="${DEFAULT_REPORT#"${DEFAULT_REPORT%%[![:space:]]*}"}"
    DEFAULT_REPORT="${DEFAULT_REPORT%"${DEFAULT_REPORT##*[![:space:]]}"}"
fi

DISCOVER_REPORT=""
if [ -n "$DEFAULT_REPORT" ] && f_shodan_is_report_dir "$DEFAULT_REPORT"; then
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

if [ -z "$DISCOVER_REPORT" ]; then
    f_shodan_die "No report location provided."
fi

if [ -f "$DISCOVER_REPORT" ]; then
    case "$DISCOVER_REPORT" in
        */pages/*)
            if ! DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")/.." && pwd)"; then
                f_shodan_die "Report not found."
            fi
            ;;
        *)
            if ! DISCOVER_REPORT="$(cd "$(dirname "$DISCOVER_REPORT")" && pwd)"; then
                f_shodan_die "Report not found."
            fi
            ;;
    esac
fi

if ! f_shodan_is_report_dir "$DISCOVER_REPORT"; then
    f_shodan_die "Report not found."
fi

DISCOVER_REPORT="$(cd "$DISCOVER_REPORT" && pwd)" || f_shodan_die "Report not found."
export DISCOVER_REPORT

if [ ! -f "$DISCOVER_REPORT/tools/httpx.jsonl" ]; then
    f_shodan_die "No Active httpx data (tools/httpx.jsonl). Run Active recon first."
fi

if [ -z "${SHODAN_API_KEY:-}" ]; then
    echo
    echo -e "${YELLOW}[!] SHODAN_API_KEY not set — enrichment will be skipped.${NC}"
    echo "    export SHODAN_API_KEY=... or put it in \$DISCOVER/.env or ~/.discover/.env"
    echo "    Template: \$DISCOVER/.env.example"
    echo
fi

DISCOVER_ROOT=""
if DISCOVER_ROOT="$(f_shodan_discover_root)"; then
    :
else
    DISCOVER_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fi
export DISCOVER="${DISCOVER:-$DISCOVER_ROOT}"

PY="$DISCOVER_ROOT/recon/shodan-enrich.py"
if [ ! -f "$PY" ]; then
    f_shodan_die "Missing $PY"
fi

echo
echo -e "Report: ${YELLOW}$DISCOVER_REPORT${NC}"
echo

# --skip-audit: shell owns audit line (with real egress IP via f_audit_log).
set +e
python3 "$PY" "$DISCOVER_REPORT" --skip-audit
status=$?
set -e

if [ "$status" -ne 0 ]; then
    f_shodan_die "Shodan enrichment failed (exit $status)."
fi

# Soft-skip without key still exits 0 from Python; only log when artifacts exist.
if [ -d "$DISCOVER_REPORT/tools/shodan" ] && [ -f "$DISCOVER_REPORT/tools/shodan/summary.json" ]; then
    ACTION="Ran Shodan enrichment"
    if command -v python3 >/dev/null 2>&1; then
        DETAIL=$(python3 - "$DISCOVER_REPORT/tools/shodan/summary.json" <<'PY' 2>/dev/null || true
import json, sys
try:
    s = json.load(open(sys.argv[1]))
    st = s.get("stats") or {}
    print(
        f"{st.get('ok', 0)} with data, "
        f"{st.get('not_found', 0)} not in Shodan, "
        f"{st.get('error', 0)} errors; "
        f"{st.get('queried', 0)} queried, "
        f"{st.get('cached', 0)} cached"
    )
except Exception:
    pass
PY
)
        if [ -n "$DETAIL" ]; then
            ACTION="Ran Shodan enrichment ($DETAIL)"
        fi
    fi

    if declare -F f_audit_log >/dev/null 2>&1; then
        f_audit_log "$DISCOVER_REPORT" "$ACTION"
    else
        mkdir -p "$DISCOVER_REPORT/tools/audit" 2>/dev/null || true
        ts=$(date -u +"%m-%d-%Y Z - %H:%M")
        printf '%s | unknown | %s.\n' "$ts" "$ACTION" >> "$DISCOVER_REPORT/tools/audit/log.txt" 2>/dev/null || true
    fi

    if [ -f "$DISCOVER_ROOT/recon/audit-build.py" ]; then
        python3 "$DISCOVER_ROOT/recon/audit-build.py" \
            "$DISCOVER_REPORT" \
            "$DISCOVER_ROOT/report/pages/audit.htm" >/dev/null 2>&1 || true
    fi

    echo
    echo -e "Artifacts: ${YELLOW}$DISCOVER_REPORT/tools/shodan/${NC}"
fi

echo
echo -e "${BLUE}$MEDIUM${NC}"
echo
exit 0
