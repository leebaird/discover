# Open Redirect Scanner shared library — sourced by dev/open-redirect.sh

OPEN_REDIRECT_SCANNER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN_REDIRECT_SCANNER_ROOT="$(cd "${OPEN_REDIRECT_SCANNER_LIB_DIR}/../.." && pwd)"

OPEN_REDIRECT_SCAN_MODE="${OPEN_REDIRECT_SCAN_MODE:-full}"
OPEN_REDIRECT_URL="${OPEN_REDIRECT_URL:-}"
OPEN_REDIRECT_DOMAIN="${OPEN_REDIRECT_DOMAIN:-}"
OPEN_REDIRECT_FILE="${OPEN_REDIRECT_FILE:-}"
OPEN_REDIRECT_WORDLIST="${OPEN_REDIRECT_WORDLIST:-}"
OPEN_REDIRECT_SCAN_DIR="${OPEN_REDIRECT_SCAN_DIR:-}"
OPEN_REDIRECT_CANARY_HOST="${OPEN_REDIRECT_CANARY_HOST:-evil-canary.invalid}"
OPEN_REDIRECT_OUTPUT_DIR="${OPEN_REDIRECT_OUTPUT_DIR:-}"
OPEN_REDIRECT_RESUME_DIR="${OPEN_REDIRECT_RESUME_DIR:-}"
OPEN_REDIRECT_WORKERS="${OPEN_REDIRECT_WORKERS:-10}"
OPEN_REDIRECT_DELAY="${OPEN_REDIRECT_DELAY:-0}"
OPEN_REDIRECT_RPS="${OPEN_REDIRECT_RPS:-0}"
OPEN_REDIRECT_MAX_REQUESTS="${OPEN_REDIRECT_MAX_REQUESTS:-0}"
OPEN_REDIRECT_CRAWL="${OPEN_REDIRECT_CRAWL:-0}"
OPEN_REDIRECT_NO_CONFIRM="${OPEN_REDIRECT_NO_CONFIRM:-0}"
OPEN_REDIRECT_QUIET="${OPEN_REDIRECT_QUIET:-0}"
OPEN_REDIRECT_USE_MENU="${OPEN_REDIRECT_USE_MENU:-0}"
OPEN_REDIRECT_CLI_INVOKED="${OPEN_REDIRECT_CLI_INVOKED:-0}"

OPEN_REDIRECT_SCAN_LOG=""
OPEN_REDIRECT_CHECKPOINT_DIR=""
OPEN_REDIRECT_FINDINGS_FILE=""

f_openredirect_now(){
    date -Iseconds
}

f_openredirect_init_scan(){
    local resuming="${1:-0}"
    OPEN_REDIRECT_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    OPEN_REDIRECT_CHECKPOINT_DIR="${OUTPUT_DIR}/.checkpoint"
    OPEN_REDIRECT_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"

    mkdir -p "$OPEN_REDIRECT_CHECKPOINT_DIR" "${OUTPUT_DIR}/openredirect_engine"
    touch "$OPEN_REDIRECT_SCAN_LOG"

    if [ "$resuming" = "1" ] && [ -s "$OPEN_REDIRECT_FINDINGS_FILE" ]; then
        :
    else
        printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$OPEN_REDIRECT_FINDINGS_FILE"
    fi

    {
        echo "=== Open Redirect scan started $(f_openredirect_now) ==="
        echo "Mode: $OPEN_REDIRECT_SCAN_MODE"
        echo "Canary host: $OPEN_REDIRECT_CANARY_HOST"
        echo "URL: ${OPEN_REDIRECT_URL:-n/a}"
        echo "Domain: ${OPEN_REDIRECT_DOMAIN:-n/a}"
        echo "File: ${OPEN_REDIRECT_FILE:-n/a}"
        echo "Scan dir: ${OPEN_REDIRECT_SCAN_DIR:-n/a}"
        echo "Output: $OUTPUT_DIR"
    } >> "$OPEN_REDIRECT_SCAN_LOG"
}

f_openredirect_log(){
    echo "[$(f_openredirect_now)] $*" >> "$OPEN_REDIRECT_SCAN_LOG"
}

f_openredirect_mark_phase(){
    touch "${OPEN_REDIRECT_CHECKPOINT_DIR}/$1.done"
    f_openredirect_log "Phase completed: $1"
}

f_openredirect_record_finding(){
    local severity="$1" domain="$2" resource="$3" check="$4" detail="$5" evidence="$6"
    local lockfile="${OUTPUT_DIR}/.findings.lock"
    (
        flock -x 9
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$severity" "$domain" "$resource" "$check" "$detail" "$evidence" >> "$OPEN_REDIRECT_FINDINGS_FILE"
        echo "[$(f_openredirect_now)] FINDING [$severity] $domain/$resource — $check: $detail" >> "$OPEN_REDIRECT_SCAN_LOG"
    ) 9>"$lockfile"
}

f_openredirect_count_findings(){
    local severity="${1:-}" domain="${2:-}"
    awk -F'\t' -v sev="$severity" -v dom="$domain" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            if (dom != "" && $2 != dom) next
            n++
        }
        END { print n + 0 }
    ' "$OPEN_REDIRECT_FINDINGS_FILE"
}

f_openredirect_check_deps(){
    local missing=()
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v jq >/dev/null 2>&1 || missing+=("jq")
    if ! python3 -c 'import requests' >/dev/null 2>&1; then
        missing+=("python3-requests")
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Run Discover Update or: apt install python3-requests jq${NC}"
        exit 1
    fi
}

f_openredirect_setup_output(){
    if [ -n "$OPEN_REDIRECT_RESUME_DIR" ]; then
        OUTPUT_DIR="$OPEN_REDIRECT_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_openredirect_init_scan 1
        return 0
    fi

    if [ -n "$OPEN_REDIRECT_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$OPEN_REDIRECT_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/openredirect-scan_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    f_openredirect_init_scan 0
}

f_openredirect_write_findings_json(){
    local stamp="$1"
    local json_file="${OUTPUT_DIR}/findings.json"
    local findings crit high warn info total

    crit=$(f_openredirect_count_findings critical)
    high=$(f_openredirect_count_findings high)
    warn=$(f_openredirect_count_findings warning)
    info=$(f_openredirect_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$OPEN_REDIRECT_FINDINGS_FILE")

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$OPEN_REDIRECT_FINDINGS_FILE" | jq -R -s '
            split("\n") | map(select(length > 0)) | map(split("\t"))
            | map({severity:.[0],domain:.[1],resource:.[2],check:.[3],detail:.[4],evidence:(if length>5 then .[5] else "" end)})
        ')
    else
        findings='[]'
    fi

    jq -n \
        --arg scanner "open-redirect-scanner" \
        --arg generated "$stamp" \
        --arg mode "$OPEN_REDIRECT_SCAN_MODE" \
        --arg canary "$OPEN_REDIRECT_CANARY_HOST" \
        --arg url "${OPEN_REDIRECT_URL:-}" \
        --arg domain "${OPEN_REDIRECT_DOMAIN:-}" \
        --arg file "${OPEN_REDIRECT_FILE:-}" \
        --arg scan_dir "${OPEN_REDIRECT_SCAN_DIR:-}" \
        --arg output_dir "$OUTPUT_DIR" \
        --argjson critical "$crit" \
        --argjson high "$high" \
        --argjson warning "$warn" \
        --argjson info "$info" \
        --argjson total "$total" \
        --argjson findings "$findings" \
        '{scanner:$scanner,generated:$generated,mode:$mode,canary_host:$canary,url:$url,domain:$domain,file:$file,scan_dir:$scan_dir,output_dir:$output_dir,summary:{critical:$critical,high:$high,warning:$warning,info:$info,total:$total},findings:$findings}' \
        > "$json_file"
}

f_openredirect_generate_reports(){
    local stamp
    stamp=$(f_openredirect_now)
    local crit high warn info total
    crit=$(f_openredirect_count_findings critical)
    high=$(f_openredirect_count_findings high)
    warn=$(f_openredirect_count_findings warning)
    info=$(f_openredirect_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$OPEN_REDIRECT_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
Open Redirect Scanner Report
============================
Generated: $stamp
Mode:      $OPEN_REDIRECT_SCAN_MODE
Canary:    $OPEN_REDIRECT_CANARY_HOST
Output:    $OUTPUT_DIR

Finding counts
--------------
Critical: $crit
High:     $high
Warning:  $warn
Info:     $info
Total:    $total
EOF

    awk -F'\t' 'NR > 1 {
        printf "  [%s] %s — %s\n    Check: %s\n    Detail: %s\n", $1, $2, $3, $4, $5
        if ($6 != "") printf "    Evidence: %s\n", $6
        printf "\n"
    }' "$OPEN_REDIRECT_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# Open Redirect Scanner Report

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Mode | $OPEN_REDIRECT_SCAN_MODE |
| Canary host | \`$OPEN_REDIRECT_CANARY_HOST\` |
| Output | \`$OUTPUT_DIR\` |

## Summary

| Severity | Count |
|----------|------:|
| Critical | $crit |
| High | $high |
| Warning | $warn |
| Info | $info |
| **Total** | **$total** |

## Findings

EOF

    awk -F'\t' 'NR > 1 {
        printf "### [%s] %s — %s\n- **Domain:** %s\n- **Detail:** %s\n", $1, $3, $4, $2, $5
        if ($6 != "") printf "- **Evidence:** \`%s\`\n", $6
        printf "\n"
    }' "$OPEN_REDIRECT_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    echo "Engine results: \`openredirect_engine/results.json\`" >> "${OUTPUT_DIR}/report.md"
    echo "Scan log: \`scan.log\`" >> "${OUTPUT_DIR}/report.md"

    f_openredirect_write_findings_json "$stamp"
    f_openredirect_log "Reports written. Findings: $total"
}

f_openredirect_import_engine_results(){
    local results_file="${OUTPUT_DIR}/openredirect_engine/results.json"
    [ -f "$results_file" ] || return 0

    printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$OPEN_REDIRECT_FINDINGS_FILE"

    jq -c '.vulnerabilities[]?' "$results_file" 2>/dev/null | while read -r row; do
        local sev dom res chk det ev
        sev=$(jq -r '.severity // "high"' <<<"$row")
        dom=$(jq -r '.domain // "unknown"' <<<"$row")
        res=$(jq -r '.resource // "url"' <<<"$row")
        chk=$(jq -r '.check // "open_redirect"' <<<"$row")
        det=$(jq -r '.detail // ""' <<<"$row")
        ev=$(jq -r '.evidence // ""' <<<"$row")
        [ -n "$det" ] || continue
        f_openredirect_record_finding "$sev" "$dom" "$res" "$chk" "$det" "$ev"
    done
}

f_openredirect_has_target(){
    [ -n "$OPEN_REDIRECT_URL" ] || [ -n "$OPEN_REDIRECT_DOMAIN" ] || \
        [ -n "$OPEN_REDIRECT_FILE" ] || [ -n "$OPEN_REDIRECT_SCAN_DIR" ]
}

f_openredirect_run_engine(){
    local rc=0
    local -a cmd

    f_openredirect_has_target || { echo -e "${RED}[!] No scan target${NC}"; return 1; }

    echo -e "${BLUE}[*] Running open redirect engine (${OPEN_REDIRECT_SCAN_MODE} mode).${NC}"

    cmd=(
        python3 "${OPEN_REDIRECT_SCANNER_ROOT}/openredirect-scanner.py"
        --output-dir "$OUTPUT_DIR"
        --mode "$OPEN_REDIRECT_SCAN_MODE"
        --canary-host "$OPEN_REDIRECT_CANARY_HOST"
        --workers "$OPEN_REDIRECT_WORKERS"
        --delay "$OPEN_REDIRECT_DELAY"
        --rps "$OPEN_REDIRECT_RPS"
        --max-requests "$OPEN_REDIRECT_MAX_REQUESTS"
    )

    [ -n "$OPEN_REDIRECT_URL" ] && cmd+=(--url "$OPEN_REDIRECT_URL")
    [ -n "$OPEN_REDIRECT_DOMAIN" ] && cmd+=(--domain "$OPEN_REDIRECT_DOMAIN")
    [ -n "$OPEN_REDIRECT_FILE" ] && cmd+=(--file "$OPEN_REDIRECT_FILE")
    [ -n "$OPEN_REDIRECT_SCAN_DIR" ] && cmd+=(--scan-dir "$OPEN_REDIRECT_SCAN_DIR")
    [ -n "$OPEN_REDIRECT_WORDLIST" ] && cmd+=(--wordlist "$OPEN_REDIRECT_WORDLIST")
    [ "$OPEN_REDIRECT_CRAWL" = "1" ] && cmd+=(--crawl)
    [ "$OPEN_REDIRECT_NO_CONFIRM" = "1" ] && cmd+=(--no-confirm)
    [ "$OPEN_REDIRECT_QUIET" = "1" ] && cmd+=(--quiet)
    [ -n "$OPEN_REDIRECT_RESUME_DIR" ] && cmd+=(--resume)

    f_openredirect_log "Engine: ${cmd[*]}"
    "${cmd[@]}" || rc=$?

    f_openredirect_import_engine_results

    if [ -f "${OUTPUT_DIR}/openredirect_engine/checkpoint.json" ] && \
       jq -e '.completed == true' "${OUTPUT_DIR}/openredirect_engine/checkpoint.json" >/dev/null 2>&1; then
        f_openredirect_mark_phase scan
    fi

    if [ -f "${OUTPUT_DIR}/openredirect_engine/scan_summary.txt" ]; then
        cp "${OUTPUT_DIR}/openredirect_engine/scan_summary.txt" "${OUTPUT_DIR}/openredirect_security_report.txt"
    fi

    return "$rc"
}

f_openredirect_usage(){
    cat <<EOF
Usage: open-redirect.sh [options]

Options:
  --url URL               Scan a single URL
  --domain DOMAIN         Scan a domain (HTTP/HTTPS, with/without www)
  --file FILE             Scan URLs listed one per line
  --scan-dir DIR          Also use URLs from a prior Discover scan (api-scanner, etc.)
  --wordlist FILE         Extra redirect parameter names
  --canary-host HOST      External host for test payloads (default: evil-canary.invalid)
  --quick                 Reduced parameter/payload set
  --full                  Full fuzz including POST/header probes (default)
  --crawl                 Crawl links from seed URLs before fuzzing
  --workers N             Concurrent workers (default: 10)
  --delay SEC             Delay between requests
  --rps N                 Max requests per second
  --max-requests N        Stop after N tests (0 = unlimited)
  --no-confirm            Skip second-canary confirmation pass
  --quiet                 Suppress engine stdout (details in scan.log / engine.log)
  --output-dir DIR        Output directory
  --resume DIR            Resume prior scan directory (per-test checkpoint)
  --menu                  Interactive menu
  -h, --help              Show this help

Environment: OPEN_REDIRECT_OUTPUT_DIR, OPEN_REDIRECT_SCAN_MODE, OPEN_REDIRECT_CANARY_HOST
EOF
}

f_openredirect_parse_cli(){
    while [ $# -gt 0 ]; do
        case "$1" in
            --quick) OPEN_REDIRECT_SCAN_MODE="quick"; OPEN_REDIRECT_CLI_INVOKED=1; shift ;;
            --full) OPEN_REDIRECT_SCAN_MODE="full"; OPEN_REDIRECT_CLI_INVOKED=1; shift ;;
            --url) OPEN_REDIRECT_URL="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --domain) OPEN_REDIRECT_DOMAIN="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --file) OPEN_REDIRECT_FILE="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --scan-dir) OPEN_REDIRECT_SCAN_DIR="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --wordlist) OPEN_REDIRECT_WORDLIST="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --canary-host) OPEN_REDIRECT_CANARY_HOST="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --workers) OPEN_REDIRECT_WORKERS="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --delay) OPEN_REDIRECT_DELAY="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --rps) OPEN_REDIRECT_RPS="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --max-requests) OPEN_REDIRECT_MAX_REQUESTS="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --crawl) OPEN_REDIRECT_CRAWL=1; OPEN_REDIRECT_CLI_INVOKED=1; shift ;;
            --no-confirm) OPEN_REDIRECT_NO_CONFIRM=1; OPEN_REDIRECT_CLI_INVOKED=1; shift ;;
            --quiet) OPEN_REDIRECT_QUIET=1; OPEN_REDIRECT_CLI_INVOKED=1; shift ;;
            --output-dir) OPEN_REDIRECT_OUTPUT_DIR="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --resume) OPEN_REDIRECT_RESUME_DIR="$2"; OPEN_REDIRECT_CLI_INVOKED=1; shift 2 ;;
            --menu) OPEN_REDIRECT_USE_MENU=1; shift ;;
            -h|--help) f_openredirect_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_openredirect_usage; exit 1 ;;
        esac
    done
}

f_openredirect_normalize_url(){
    local target="$1"
    if [[ ! "$target" =~ ^https?:// ]]; then
        target="https://${target}"
    fi
    printf '%s' "$target"
}

f_openredirect_normalize_domain(){
    local d="$1"
    d="${d#https://}"
    d="${d#http://}"
    d="${d%%/*}"
    printf '%s' "$d"
}