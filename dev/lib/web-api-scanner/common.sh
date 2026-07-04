# Web/API Metasploit scanner shared library — sourced by dev/web-api-scanner.sh

WEBAPI_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBAPI_ROOT="$(cd "${WEBAPI_LIB_DIR}/../.." && pwd)"

WEBAPI_URL="${WEBAPI_URL:-}"
WEBAPI_TARGET_IP="${WEBAPI_TARGET_IP:-}"
WEBAPI_OUTPUT_DIR="${WEBAPI_OUTPUT_DIR:-}"
WEBAPI_RESUME_DIR="${WEBAPI_RESUME_DIR:-}"
WEBAPI_PASSIVE="${WEBAPI_PASSIVE:-0}"
WEBAPI_I_UNDERSTAND="${WEBAPI_I_UNDERSTAND:-0}"
WEBAPI_QUIET="${WEBAPI_QUIET:-0}"
WEBAPI_DRY_RUN="${WEBAPI_DRY_RUN:-0}"
WEBAPI_USE_MENU="${WEBAPI_USE_MENU:-0}"
WEBAPI_CLI_INVOKED="${WEBAPI_CLI_INVOKED:-0}"
WEBAPI_SKIP_MSF_DB="${WEBAPI_SKIP_MSF_DB:-0}"
WEBAPI_INSECURE="${WEBAPI_INSECURE:-0}"
WEBAPI_DELAY="${WEBAPI_DELAY:-0}"
WEBAPI_JITTER="${WEBAPI_JITTER:-0}"
WEBAPI_PROXY="${WEBAPI_PROXY:-}"
WEBAPI_MSF_DB_BOOTSTRAP="${WEBAPI_MSF_DB_BOOTSTRAP:-0}"
WEBAPI_KEEP_RESOURCES="${WEBAPI_KEEP_RESOURCES:-0}"
WEBAPI_TECH_MIN_SCORE="${WEBAPI_TECH_MIN_SCORE:-3}"
WEBAPI_TARGET_IS_IPV6="${WEBAPI_TARGET_IS_IPV6:-0}"
WEBAPI_BEARER_TOKEN="${WEBAPI_BEARER_TOKEN:-}"
WEBAPI_COOKIE_FILE="${WEBAPI_COOKIE_FILE:-}"
WEBAPI_PHASE_TIMEOUT="${WEBAPI_PHASE_TIMEOUT:-600}"
WEBAPI_MSF_THREADS="${WEBAPI_MSF_THREADS:-0}"

WEBAPI_SCAN_LOG=""
WEBAPI_HITS_JSONL=""
WEBAPI_FINDINGS_FILE=""
WEBAPI_FINDINGS_HASH_FILE=""
WEBAPI_RESULTS_FILE=""
WEBAPI_CHECKPOINT_FILE=""
WEBAPI_MSF_RESOURCE_DIR=""
WEBAPI_USER_AGENT="${USER_AGENT:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.86}"

f_webapi_now(){
    date -Iseconds
}

f_webapi_say(){
    [ "$WEBAPI_QUIET" = "1" ] && return 0
    printf '%b\n' "$*"
}

f_webapi_slug(){
    local s
    s=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | sed 's/^_\+//;s/_$//')
    [ -n "$s" ] || s="target"
    printf '%s' "$s"
}

f_webapi_normalize_url(){
    local u="$1"
    u="${u// /}"
    u="${u%%#*}"
    [[ "$u" =~ ^https?:// ]] || u="https://${u}"
    u="${u%/}"
    printf '%s' "$u"
}

f_webapi_domain_from_url(){
    local u="$1"
    printf '%s' "$u" | sed -E 's#^https?://([^/:]+).*#\1#'
}

f_webapi_authority_from_url(){
    local u="$1"
    printf '%s' "$u" | sed -E 's#^https?://([^/]+).*#\1#'
}

f_webapi_is_https(){
    [[ "$1" =~ ^https:// ]]
}

f_webapi_curl_opts(){
    WEBAPI_CURL_OPTS=(-sL -A "$WEBAPI_USER_AGENT" --connect-timeout 10 --max-time 25)
    [ "$WEBAPI_INSECURE" = "1" ] && WEBAPI_CURL_OPTS+=(-k)
    [ -n "$WEBAPI_PROXY" ] && WEBAPI_CURL_OPTS+=(--proxy "$WEBAPI_PROXY")
    [ -n "$WEBAPI_BEARER_TOKEN" ] && WEBAPI_CURL_OPTS+=(-H "Authorization: Bearer ${WEBAPI_BEARER_TOKEN}")
    [ -n "$WEBAPI_COOKIE_FILE" ] && [ -f "$WEBAPI_COOKIE_FILE" ] && WEBAPI_CURL_OPTS+=(-b "$WEBAPI_COOKIE_FILE")
}

f_webapi_sleep_between_phases(){
    local base=0 jitter=0 wait=0
    base="${WEBAPI_DELAY:-0}"
    jitter="${WEBAPI_JITTER:-0}"
    [ "$base" = "0" ] && [ "$jitter" = "0" ] && return 0
    wait="$base"
    if [ "$jitter" -gt 0 ] 2>/dev/null; then
        wait=$((base + RANDOM % (jitter + 1)))
    fi
    [ "$wait" -gt 0 ] && sleep "$wait"
}

f_webapi_msf_threads_for_tier(){
    if [ "${WEBAPI_MSF_THREADS:-0}" -gt 0 ] 2>/dev/null; then
        printf '%s' "$WEBAPI_MSF_THREADS"
        return 0
    fi
    f_webapi_resolve_tier
    case "$WEBAPI_TIER" in
        passive) echo 2 ;;
        standard) echo 3 ;;
        *) echo 5 ;;
    esac
}

f_webapi_is_ipv6(){
    [[ "$1" == *:* ]]
}

f_webapi_init_scan(){
    local resuming="${1:-0}"
    WEBAPI_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    WEBAPI_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"
    WEBAPI_FINDINGS_HASH_FILE="${OUTPUT_DIR}/.findings_hashes"
    WEBAPI_RESULTS_FILE="${OUTPUT_DIR}/scan_results.tsv"
    WEBAPI_CHECKPOINT_FILE="${OUTPUT_DIR}/msf_engine/checkpoint.json"
    WEBAPI_MSF_RESOURCE_DIR="${OUTPUT_DIR}/msf_engine/resources"

    mkdir -p "${OUTPUT_DIR}/msf_engine/spool" "$WEBAPI_MSF_RESOURCE_DIR"
    WEBAPI_HITS_JSONL="${OUTPUT_DIR}/msf_engine/hits.jsonl"
    touch "$WEBAPI_SCAN_LOG"
    if [ "$resuming" != "1" ]; then
        : > "$WEBAPI_HITS_JSONL"
    else
        touch "$WEBAPI_HITS_JSONL"
    fi

    if [ "$resuming" = "1" ] && [ -s "$WEBAPI_FINDINGS_FILE" ]; then
        touch "$WEBAPI_FINDINGS_HASH_FILE"
    else
        printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$WEBAPI_FINDINGS_FILE"
        : > "$WEBAPI_FINDINGS_HASH_FILE"
        printf '%s\n' 'phase	status	findings	timestamp' > "$WEBAPI_RESULTS_FILE"
        printf '%s\n' '{"completed":[],"updated":""}' > "$WEBAPI_CHECKPOINT_FILE"
    fi

    {
        echo "=== Web/API MSF scan started $(f_webapi_now) ==="
        echo "Target: ${WEBAPI_URL:-}"
        echo "Tier: ${WEBAPI_TIER:-}"
        echo "Passive: ${WEBAPI_PASSIVE:-0}"
        echo "Dry-run: ${WEBAPI_DRY_RUN:-0}"
        echo "Scan-dir: ${WEBAPI_SCAN_DIR:-}"
        echo "Output: $OUTPUT_DIR"
    } >> "$WEBAPI_SCAN_LOG"
}

f_webapi_log(){
    echo "[$(f_webapi_now)] $*" >> "$WEBAPI_SCAN_LOG"
}

f_webapi_setup_output(){
    if [ -n "$WEBAPI_RESUME_DIR" ]; then
        OUTPUT_DIR="$WEBAPI_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_webapi_init_scan 1
        return 0
    fi

    if [ -n "$WEBAPI_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$WEBAPI_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/web-api-scan_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    f_webapi_init_scan 0
}

f_webapi_finding_hash(){
    local domain="$1" resource="$2" check="$3" detail="$4"
    printf '%s|%s|%s|%s' "$domain" "$resource" "$check" "$detail" | sha256sum | awk '{print $1}'
}

f_webapi_finding_seen(){
    local hash="$1"
    [ -f "$WEBAPI_FINDINGS_HASH_FILE" ] && grep -qxF "$hash" "$WEBAPI_FINDINGS_HASH_FILE" 2>/dev/null
}

f_webapi_record_finding(){
    local severity="$1" domain="$2" resource="$3" check="$4" detail="$5" evidence="$6"
    local lockfile="${OUTPUT_DIR}/.findings.lock" fhash
    fhash=$(f_webapi_finding_hash "$domain" "$resource" "$check" "$detail")
    (
        flock -x 9
        f_webapi_finding_seen "$fhash" && exit 0
        printf '%s\n' "$fhash" >> "$WEBAPI_FINDINGS_HASH_FILE"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$severity" "$domain" "$resource" "$check" "$detail" "$evidence" >> "$WEBAPI_FINDINGS_FILE"
        echo "[$(f_webapi_now)] FINDING [$severity] $domain/$resource — $check: $detail" >> "$WEBAPI_SCAN_LOG"
    ) 9>"$lockfile"
}

f_webapi_count_findings(){
    local severity="${1:-}"
    awk -F'\t' -v sev="$severity" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            n++
        }
        END { print n + 0 }
    ' "$WEBAPI_FINDINGS_FILE"
}

f_webapi_append_phase_result(){
    local phase="$1" status="$2" findings="$3"
    printf '%s\t%s\t%s\t%s\n' "$phase" "$status" "$findings" "$(f_webapi_now)" >> "$WEBAPI_RESULTS_FILE"
}

f_webapi_checkpoint_load(){
    WEBAPI_CHECKPOINT_DONE=()
    [ -f "$WEBAPI_CHECKPOINT_FILE" ] || return 0
    while IFS= read -r line; do
        [ -n "$line" ] && WEBAPI_CHECKPOINT_DONE+=("$line")
    done < <(jq -r '.completed[]? // empty' "$WEBAPI_CHECKPOINT_FILE" 2>/dev/null)
}

f_webapi_checkpoint_is_done(){
    local phase="$1"
    local p
    for p in "${WEBAPI_CHECKPOINT_DONE[@]}"; do
        [ "$p" = "$phase" ] && return 0
    done
    return 1
}

f_webapi_checkpoint_mark(){
    local phase="$1"
    WEBAPI_CHECKPOINT_DONE+=("$phase")
    jq -n --arg now "$(f_webapi_now)" \
        --argjson completed "$(printf '%s\n' "${WEBAPI_CHECKPOINT_DONE[@]}" | jq -R -s 'split("\n")|map(select(length>0))')" \
        '{updated:$now,completed:$completed}' > "$WEBAPI_CHECKPOINT_FILE"
}

f_webapi_write_findings_json(){
    local stamp="$1"
    local crit high warn info total findings phases

    crit=$(f_webapi_count_findings critical)
    high=$(f_webapi_count_findings high)
    warn=$(f_webapi_count_findings warning)
    info=$(f_webapi_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$WEBAPI_FINDINGS_FILE")

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$WEBAPI_FINDINGS_FILE" | jq -R -s '
            split("\n") | map(select(length > 0)) | map(split("\t"))
            | map({severity:.[0],domain:.[1],resource:.[2],check:.[3],detail:.[4],evidence:(if length>5 then .[5] else "" end)})
        ')
    else
        findings='[]'
    fi

    if [ -s "${OUTPUT_DIR}/msf_engine/phases.json" ]; then
        phases=$(cat "${OUTPUT_DIR}/msf_engine/phases.json")
    else
        phases='[]'
    fi

    if [ -s "$WEBAPI_HITS_JSONL" ]; then
        hits=$(jq -s '.' "$WEBAPI_HITS_JSONL")
    else
        hits='[]'
    fi

    f_webapi_resolve_tier

    jq -n \
        --arg scanner "web-api-scanner" \
        --arg generated "$stamp" \
        --arg tier "${WEBAPI_TIER:-}" \
        --arg passive "$WEBAPI_PASSIVE" \
        --arg dry_run "$WEBAPI_DRY_RUN" \
        --arg target "${WEBAPI_URL:-}" \
        --arg output_dir "$OUTPUT_DIR" \
        --argjson waf_present "${WEBAPI_WAF_PRESENT:-0}" \
        --argjson critical "$crit" \
        --argjson high "$high" \
        --argjson warning "$warn" \
        --argjson info "$info" \
        --argjson total "$total" \
        --argjson findings "$findings" \
        --argjson phases "$phases" \
        --argjson hits "$hits" \
        '{scanner:$scanner,generated:$generated,tier:$tier,passive:($passive=="1"),dry_run:($dry_run=="1"),waf_present:($waf_present==1),target:$target,output_dir:$output_dir,summary:{critical:$critical,high:$high,warning:$warning,info:$info,total:$total},findings:$findings,phases:$phases,hits:$hits}' \
        > "${OUTPUT_DIR}/findings.json"
}

f_webapi_record_hit_from_parser(){
    local hit_json="$1"
    local severity domain resource check detail evidence
    severity=$(printf '%s' "$hit_json" | jq -r '.severity')
    domain=$(printf '%s' "$hit_json" | jq -r '.domain')
    resource=$(printf '%s' "$hit_json" | jq -r '.target')
    check=$(printf '%s' "$hit_json" | jq -r '.check')
    detail=$(printf '%s' "$hit_json" | jq -r '.detail')
    evidence=$(printf '%s' "$hit_json" | jq -r '.evidence')
    f_webapi_record_finding "$severity" "$domain" "$resource" "$check" "$detail" "$evidence"
}

f_webapi_generate_reports(){
    local stamp crit high warn info total
    stamp=$(f_webapi_now)
    crit=$(f_webapi_count_findings critical)
    high=$(f_webapi_count_findings high)
    warn=$(f_webapi_count_findings warning)
    info=$(f_webapi_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$WEBAPI_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
Web and API Security Scan Report
=================================
Authorized security testing only.

Generated: $stamp
Output:    $OUTPUT_DIR
Passive:   $WEBAPI_PASSIVE
Dry-run:   $WEBAPI_DRY_RUN
Target:    ${WEBAPI_URL:-}

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
    }' "$WEBAPI_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# Web and API Security Scan Report

> Authorized security testing only. **Passive mode** runs MSF recon modules only (version, headers, robots, SSL). **Active mode** adds directory brute force, auth testing, exploit checks, and SQLi/JWT modules.

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Output | \`$OUTPUT_DIR\` |
| Passive | $WEBAPI_PASSIVE |
| Target | ${WEBAPI_URL:-} |

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
    }' "$WEBAPI_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    f_webapi_write_findings_json "$stamp"
    f_webapi_log "Reports written. Findings: $total"
}

f_webapi_check_deps(){
    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq >/dev/null 2>&1 || missing+=("jq")
    command -v grep >/dev/null 2>&1 || missing+=("grep")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
        exit 1
    fi
    if [ "$WEBAPI_DRY_RUN" != "1" ]; then
        command -v msfconsole >/dev/null 2>&1 || {
            echo -e "${RED}[!] msfconsole required (install Metasploit via Discover Update)${NC}"
            exit 1
        }
    fi
}

f_webapi_msf_db_connected(){
    msfconsole -q -x "db_status; exit" 2>/dev/null | grep -qi "connected to"
}

f_webapi_try_msf_db_bootstrap(){
    if command -v pg_isready >/dev/null 2>&1 && ! pg_isready -q 2>/dev/null; then
        if command -v systemctl >/dev/null 2>&1; then
            systemctl start postgresql 2>/dev/null || true
            sleep 2
        elif command -v service >/dev/null 2>&1; then
            service postgresql start 2>/dev/null || true
            sleep 2
        fi
    fi
    if command -v msfdb >/dev/null 2>&1; then
        msfdb init 2>/dev/null || true
        sleep 2
    fi
}

f_webapi_try_msf_db_bootstrap_privileged(){
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl start postgresql 2>/dev/null || true
    elif command -v service >/dev/null 2>&1; then
        sudo service postgresql start 2>/dev/null || true
    fi
    sleep 2
    if command -v msfdb >/dev/null 2>&1; then
        msfdb init 2>/dev/null || sudo msfdb init 2>/dev/null || true
        sleep 2
    fi
}

f_webapi_ensure_msf_db(){
    [ "$WEBAPI_SKIP_MSF_DB" = "1" ] && return 0
    [ "$WEBAPI_DRY_RUN" = "1" ] && return 0
    f_webapi_msf_db_connected && return 0

    f_webapi_log "MSF DB not connected"
    if [ "$WEBAPI_MSF_DB_BOOTSTRAP" != "1" ]; then
        f_webapi_say "${YELLOW}[!] MSF database not connected. Scan continues without DB-backed modules.${NC}"
        f_webapi_say "${YELLOW}[*] Use --msf-db-bootstrap to attempt setup, or --skip-msf-db to silence.${NC}"
        return 0
    fi

    f_webapi_say "${BLUE}[*] Attempting MSF database bootstrap (non-privileged first).${NC}"
    f_webapi_try_msf_db_bootstrap
    f_webapi_msf_db_connected && return 0

    if [ -t 0 ] && [ -t 1 ]; then
        echo -n "Privileged PostgreSQL/msfdb bootstrap may be required. Continue with sudo? (y/n): "
        read -r ans
        if [[ "$ans" =~ ^[Yy] ]]; then
            f_webapi_try_msf_db_bootstrap_privileged
        fi
    else
        f_webapi_log "MSF DB bootstrap skipped in non-interactive mode (no sudo)"
    fi

    if ! f_webapi_msf_db_connected; then
        f_webapi_say "${YELLOW}[!] MSF database still not connected; scan continues without DB-backed modules.${NC}"
        f_webapi_log "MSF DB unavailable after bootstrap attempt"
    fi
}

f_webapi_cleanup_resources(){
    [ "$WEBAPI_KEEP_RESOURCES" = "1" ] && return 0
    [ -d "${WEBAPI_MSF_RESOURCE_DIR:-}" ] || return 0
    rm -rf "${WEBAPI_MSF_RESOURCE_DIR}"
    f_webapi_log "Removed generated MSF resource scripts"
}

f_webapi_resolve_ip(){
    local domain="$1"
    local ip=""

    WEBAPI_TARGET_IS_IPV6=0

    if [[ "$domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s' "$domain"
        return 0
    fi
    if f_webapi_is_ipv6 "$domain"; then
        WEBAPI_TARGET_IS_IPV6=1
        printf '%s' "$domain"
        return 0
    fi

    if command -v getent >/dev/null 2>&1; then
        ip=$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [ -z "$ip" ] && command -v host >/dev/null 2>&1; then
        ip=$(host -t A "$domain" 2>/dev/null | awk '/has address/ {print $4; exit}')
    fi
    if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
        ip=$(dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    fi

    if [ -n "$ip" ]; then
        printf '%s' "$ip"
        return 0
    fi

    if command -v getent >/dev/null 2>&1; then
        ip=$(getent ahostsv6 "$domain" 2>/dev/null | awk '{print $1; exit}')
    fi
    if [ -z "$ip" ] && command -v host >/dev/null 2>&1; then
        ip=$(host -t AAAA "$domain" 2>/dev/null | awk '/has IPv6 address/ {print $5; exit}')
    fi
    if [ -z "$ip" ] && command -v dig >/dev/null 2>&1; then
        ip=$(dig +short AAAA "$domain" 2>/dev/null | grep ':' | head -1)
    fi

    if [ -n "$ip" ]; then
        WEBAPI_TARGET_IS_IPV6=1
        printf '%s' "$ip"
        return 0
    fi

    printf '%s' ""
}

f_webapi_usage(){
    cat <<EOF
Usage: web-api-scanner.sh [options]

Options:
  --url URL               Target URL or hostname
  --file FILE             Targets file (text, CSV, JSON)
  --target-ip IP          Override resolved target IP for MSF RHOSTS
  --output-dir DIR        Output directory
  --resume DIR            Resume prior scan directory (checkpoint-aware)
  --scan-dir DIR          Prior api-scanner/waf output (endpoints + WAF context)
  --tier TIER             passive | standard | intrusive | exploit
  --quick                 Preset: standard tier (recon + tech scanners, no brute/exploit)
  --passive               Alias for --tier passive
  --phases LIST           Comma-separated phase allowlist
  --skip-phases LIST      Comma-separated phases to skip
  --i-understand          Acknowledge active tiers (required for intrusive/exploit)
  --dry-run               Build MSF session plan without running msfconsole
  --skip-msf-db           Skip PostgreSQL / msfdb checks
  --msf-db-bootstrap      Attempt MSF DB setup (sudo only if you confirm)
  --keep-resources        Keep generated MSF .rc files after scan
  --bearer-token TOKEN    Bearer token for curl + MSF HTTP modules
  --cookie-file FILE      Cookie jar for curl + MSF HTTP modules
  --proxy URL             Proxy for curl and MSF (setg Proxies)
  --insecure              Disable TLS verification
  --delay SEC             Base delay between MSF phases
  --jitter SEC            Random extra delay (0..N) added to --delay
  --phase-timeout SEC     Per-phase msfconsole timeout (default: 600)
  --max-targets N         Cap targets from --file
  --workers N             Parallel workers for --file (default: 1)
  --threads N             MSF THREADS override
  --no-waf-aware          Do not skip brute phases when WAF/CDN detected
  --quiet                 Suppress non-essential output
  --menu                  Interactive menu
  -h, --help              Show this help

Tiers:
  passive    MSF recon only
  standard   recon + tech-tuned scanners (no brute/exploit/SQLi)
  intrusive  standard + SQLi + auth brute force
  exploit    intrusive + exploit checks

Environment:
  WEBAPI_OUTPUT_DIR, WEBAPI_PASSIVE, WEBAPI_INSECURE, WEBAPI_PROXY
  WEBAPI_MSF_WORDLIST, WEBAPI_MSF_USERPASS, WEBAPI_MSF_PASSWORDS
  WEBAPI_TECH_MIN_SCORE, WEBAPI_KEEP_RESOURCES, WEBAPI_RUN_LIVE_MSF
EOF
}

f_webapi_parse_cli(){
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) WEBAPI_URL="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --file) WEBAPI_FILE="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --target-ip) WEBAPI_TARGET_IP="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --scan-dir) WEBAPI_SCAN_DIR="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --tier) WEBAPI_TIER="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --quick) WEBAPI_QUICK=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --phases) WEBAPI_PHASES="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --skip-phases) WEBAPI_SKIP_PHASES="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --bearer-token) WEBAPI_BEARER_TOKEN="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --cookie-file) WEBAPI_COOKIE_FILE="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --proxy) WEBAPI_PROXY="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --jitter) WEBAPI_JITTER="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --phase-timeout) WEBAPI_PHASE_TIMEOUT="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --max-targets) WEBAPI_MAX_TARGETS="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --workers) WEBAPI_WORKERS="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --threads) WEBAPI_MSF_THREADS="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --no-waf-aware) WEBAPI_WAF_AWARE=0; WEBAPI_CLI_INVOKED=1; shift ;;
            --output-dir) WEBAPI_OUTPUT_DIR="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --resume) WEBAPI_RESUME_DIR="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --passive) WEBAPI_PASSIVE=1; WEBAPI_TIER=passive; WEBAPI_CLI_INVOKED=1; shift ;;
            --i-understand) WEBAPI_I_UNDERSTAND=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --dry-run) WEBAPI_DRY_RUN=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --skip-msf-db) WEBAPI_SKIP_MSF_DB=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --msf-db-bootstrap) WEBAPI_MSF_DB_BOOTSTRAP=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --keep-resources) WEBAPI_KEEP_RESOURCES=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --insecure) WEBAPI_INSECURE=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --delay) WEBAPI_DELAY="$2"; WEBAPI_CLI_INVOKED=1; shift 2 ;;
            --quiet) WEBAPI_QUIET=1; WEBAPI_CLI_INVOKED=1; shift ;;
            --menu) WEBAPI_USE_MENU=1; shift ;;
            -h|--help) f_webapi_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_webapi_usage; exit 1 ;;
        esac
    done
}

# shellcheck disable=SC2034
declare -a WEBAPI_CHECKPOINT_DONE=()