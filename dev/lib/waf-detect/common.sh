# WAF Detection shared library — sourced by dev/waf-detect.sh

WAF_DETECT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_DETECT_ROOT="$(cd "${WAF_DETECT_LIB_DIR}/../.." && pwd)"

WAF_URL="${WAF_URL:-}"
WAF_FILE="${WAF_FILE:-}"
WAF_OUTPUT_DIR="${WAF_OUTPUT_DIR:-}"
WAF_RESUME_DIR="${WAF_RESUME_DIR:-}"
WAF_PASSIVE="${WAF_PASSIVE:-0}"
WAF_INSECURE="${WAF_INSECURE:-0}"
WAF_DELAY="${WAF_DELAY:-0}"
WAF_QUIET="${WAF_QUIET:-0}"
WAF_USE_MENU="${WAF_USE_MENU:-0}"
WAF_CLI_INVOKED="${WAF_CLI_INVOKED:-0}"
WAF_USE_WAFW00F="${WAF_USE_WAFW00F:-auto}"
WAF_SUPPLEMENTAL="${WAF_SUPPLEMENTAL:-auto}"
WAF_WAF_ONLY="${WAF_WAF_ONLY:-0}"
WAF_NO_REDIRECT="${WAF_NO_REDIRECT:-0}"
WAF_PROXY="${WAF_PROXY:-}"
WAF_MAX_TARGETS="${WAF_MAX_TARGETS:-0}"
WAF_WORKERS="${WAF_WORKERS:-1}"
WAF_INPUT_FORMAT="${WAF_INPUT_FORMAT:-}"
WAF_I_UNDERSTAND="${WAF_I_UNDERSTAND:-0}"

WAF_SCAN_LOG=""
WAF_FINDINGS_FILE=""
WAF_FINDINGS_HASH_FILE=""
WAF_RESULTS_FILE=""

f_waf_now(){
    date -Iseconds
}

f_waf_say(){
    [ "$WAF_QUIET" = "1" ] && return 0
    printf '%b\n' "$*"
}

f_waf_slug(){
    local s
    s=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | sed 's/^_\+//;s/_$//')
    [ -n "$s" ] || s="target"
    printf '%s' "$s"
}

f_waf_init_scan(){
    local resuming="${1:-0}"
    WAF_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    WAF_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"
    WAF_FINDINGS_HASH_FILE="${OUTPUT_DIR}/.findings_hashes"
    WAF_RESULTS_FILE="${OUTPUT_DIR}/waf_results.tsv"

    mkdir -p "${OUTPUT_DIR}/waf_engine"
    touch "$WAF_SCAN_LOG"

    if [ "$resuming" = "1" ] && [ -s "$WAF_FINDINGS_FILE" ]; then
        touch "$WAF_FINDINGS_HASH_FILE"
    else
        printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$WAF_FINDINGS_FILE"
        : > "$WAF_FINDINGS_HASH_FILE"
        printf '%s\n' 'target	detected	waf_names	status	timestamp' > "$WAF_RESULTS_FILE"
    fi

    {
        echo "=== WAF scan started $(f_waf_now) ==="
        echo "Passive: ${WAF_PASSIVE:-0}"
        echo "Insecure: ${WAF_INSECURE:-0}"
        echo "wafw00f: ${WAF_USE_WAFW00F:-auto}"
        echo "Supplemental: ${WAF_SUPPLEMENTAL:-auto}"
        echo "waf-only: ${WAF_WAF_ONLY:-0}"
        echo "Output: $OUTPUT_DIR"
    } >> "$WAF_SCAN_LOG"
}

f_waf_log(){
    echo "[$(f_waf_now)] $*" >> "$WAF_SCAN_LOG"
}

f_waf_finding_hash(){
    local domain="$1" resource="$2" check="$3" detail="$4"
    if [ "$check" = "waf_identified" ] || [ "$check" = "waf_possible" ] || [ "$check" = "cdn_present" ]; then
        local vendor="${detail%% |*}"
        printf '%s|%s|%s|%s' "$domain" "$resource" "$check" "$vendor" | sha256sum | awk '{print $1}'
        return 0
    fi
    printf '%s|%s|%s|%s' "$domain" "$resource" "$check" "$detail" | sha256sum | awk '{print $1}'
}

f_waf_finding_seen(){
    local hash="$1"
    [ -f "$WAF_FINDINGS_HASH_FILE" ] && grep -qxF "$hash" "$WAF_FINDINGS_HASH_FILE" 2>/dev/null
}

f_waf_record_finding(){
    local severity="$1" domain="$2" resource="$3" check="$4" detail="$5" evidence="$6"
    local lockfile="${OUTPUT_DIR}/.findings.lock" fhash
    fhash=$(f_waf_finding_hash "$domain" "$resource" "$check" "$detail")
    (
        flock -x 9
        f_waf_finding_seen "$fhash" && exit 0
        printf '%s\n' "$fhash" >> "$WAF_FINDINGS_HASH_FILE"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$severity" "$domain" "$resource" "$check" "$detail" "$evidence" >> "$WAF_FINDINGS_FILE"
        echo "[$(f_waf_now)] FINDING [$severity] $domain/$resource — $check: $detail" >> "$WAF_SCAN_LOG"
    ) 9>"$lockfile"
}

f_waf_count_findings(){
    local severity="${1:-}"
    awk -F'\t' -v sev="$severity" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            n++
        }
        END { print n + 0 }
    ' "$WAF_FINDINGS_FILE"
}

f_waf_normalize_url(){
    local u="$1"
    u="${u// /}"
    [[ "$u" =~ ^https?:// ]] || u="https://${u}"
    printf '%s' "$u"
}

f_waf_domain_from_url(){
    local u="$1"
    printf '%s' "$u" | sed -E 's#^https?://([^/]+).*#\1#'
}

f_waf_detect_input_format(){
    local path="$1"
    if [ -n "$WAF_INPUT_FORMAT" ]; then
        printf '%s' "$WAF_INPUT_FORMAT"
        return 0
    fi
    case "$path" in
        *.csv) echo csv ;;
        *.json) echo json ;;
        *) echo text ;;
    esac
}

f_waf_check_deps(){
    local missing=()
    command -v curl >/dev/null 2>&1 || missing+=("curl")
    command -v jq >/dev/null 2>&1 || missing+=("jq")
    command -v grep >/dev/null 2>&1 || missing+=("grep")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
        exit 1
    fi
    if [ "$WAF_PASSIVE" != "1" ] && [ "$WAF_USE_WAFW00F" != "none" ]; then
        command -v wafw00f >/dev/null 2>&1 || python3 -c 'import wafw00f' 2>/dev/null || {
            if [ "$WAF_USE_WAFW00F" = "auto" ]; then
                f_waf_log "wafw00f not found; passive/supplemental only"
            else
                echo -e "${RED}[!] wafw00f required (install via Discover Update)${NC}"
                exit 1
            fi
        }
    fi
}

f_waf_setup_output(){
    if [ -n "$WAF_RESUME_DIR" ]; then
        OUTPUT_DIR="$WAF_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_waf_init_scan 1
        return 0
    fi

    if [ -n "$WAF_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$WAF_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/waf-detection_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    f_waf_init_scan 0
}

f_waf_write_findings_json(){
    local stamp="$1"
    local crit high warn info total hits findings

    crit=$(f_waf_count_findings critical)
    high=$(f_waf_count_findings high)
    warn=$(f_waf_count_findings warning)
    info=$(f_waf_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$WAF_FINDINGS_FILE")

    if [ -s "${OUTPUT_DIR}/waf_engine/hits.jsonl" ]; then
        hits=$(jq -s '.' "${OUTPUT_DIR}/waf_engine/hits.jsonl")
    else
        hits='[]'
    fi

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$WAF_FINDINGS_FILE" | jq -R -s '
            split("\n") | map(select(length > 0)) | map(split("\t"))
            | map({severity:.[0],domain:.[1],resource:.[2],check:.[3],detail:.[4],evidence:(if length>5 then .[5] else "" end)})
        ')
    else
        findings='[]'
    fi

    jq -n \
        --arg scanner "waf-detect" \
        --arg generated "$stamp" \
        --arg passive "$WAF_PASSIVE" \
        --arg waf_only "$WAF_WAF_ONLY" \
        --arg output_dir "$OUTPUT_DIR" \
        --argjson critical "$crit" \
        --argjson high "$high" \
        --argjson warning "$warn" \
        --argjson info "$info" \
        --argjson total "$total" \
        --argjson findings "$findings" \
        --argjson hits "$hits" \
        '{scanner:$scanner,generated:$generated,passive:($passive=="1"),waf_only:($waf_only=="1"),output_dir:$output_dir,summary:{critical:$critical,high:$high,warning:$warning,info:$info,total:$total},findings:$findings,hits:$hits}' \
        > "${OUTPUT_DIR}/findings.json"
}

f_waf_generate_reports(){
    local stamp crit high warn info total
    stamp=$(f_waf_now)
    crit=$(f_waf_count_findings critical)
    high=$(f_waf_count_findings high)
    warn=$(f_waf_count_findings warning)
    info=$(f_waf_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$WAF_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
WAF Detection Report
====================
Authorized security testing only.

Generated: $stamp
Output:    $OUTPUT_DIR
Passive:   $WAF_PASSIVE
WAF-only:  $WAF_WAF_ONLY

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
    }' "$WAF_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# WAF Detection Report

> Authorized security testing only. **Passive mode** uses a normal HTTP GET and header signatures only — no wafw00f attack payloads.

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Output | \`$OUTPUT_DIR\` |
| Passive | $WAF_PASSIVE |
| WAF-only | $WAF_WAF_ONLY |

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
    }' "$WAF_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    f_waf_write_findings_json "$stamp"
    f_waf_log "Reports written. Findings: $total"
}

f_waf_append_result_row(){
    local target="$1" detected="$2" waf_names="$3" status="$4"
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$target" "$detected" "$waf_names" "$status" "$(f_waf_now)" >> "$WAF_RESULTS_FILE"
}

f_waf_load_targets(){
    local -n _out=$1
    local src="$2" fmt
    _out=()
    if [ -n "$WAF_URL" ]; then
        _out+=("$WAF_URL")
        return 0
    fi
    [ -n "$src" ] && [ -f "$src" ] || return 0
    fmt=$(f_waf_detect_input_format "$src")
    case "$fmt" in
        csv)
            while IFS= read -r line; do
                [ -n "$line" ] && _out+=("$line")
            done < <(awk -F',' 'NR==1{next} {print $1}' "$src" 2>/dev/null; \
                awk -F',' '$0 ~ /https?:\/\// {print $1}' "$src")
            if [ ${#_out[@]} -eq 0 ]; then
                while IFS= read -r u; do
                    [ -n "$u" ] && _out+=("$u")
                done < <(python3 - "$src" <<'PY'
import csv, sys
with open(sys.argv[1], newline='', encoding='utf-8', errors='replace') as fh:
    rows = list(csv.DictReader(fh))
    key = 'url' if rows and 'url' in rows[0] else list(rows[0].keys())[0] if rows else 'url'
    for r in rows:
        v = (r.get(key) or '').strip()
        if v: print(v)
PY
)
            fi
            ;;
        json)
            while IFS= read -r u; do
                [ -n "$u" ] && _out+=("$u")
            done < <(jq -r '.[] | .url // .target // .[]? // empty' "$src" 2>/dev/null; \
                jq -r '.url // .target // empty' "$src" 2>/dev/null)
            ;;
        *)
            while IFS= read -r line || [ -n "$line" ]; do
                line="${line%%#*}"
                line="${line// /}"
                [ -n "$line" ] || continue
                _out+=("$line")
            done < "$src"
            ;;
    esac
}

f_waf_require_active_consent(){
    [ "$WAF_PASSIVE" = "1" ] && return 0
    [ "$WAF_I_UNDERSTAND" = "1" ] && return 0
    if [ -t 0 ] && [ -t 1 ]; then
        echo -e "${YELLOW}Active mode sends benign WAF triggers (wafw00f + supplemental). Authorized testing only.${NC}"
        echo -n "Continue? (y/n): "
        read -r ans
        [[ "$ans" =~ ^[Yy] ]] || { echo "Aborted."; exit 1; }
        return 0
    fi
    echo -e "${RED}[!] Active scan requires --passive or --i-understand${NC}"
    exit 1
}

f_waf_usage(){
    cat <<EOF
Usage: waf-detect.sh [options]

Options:
  --url URL               Single target URL or hostname
  --file FILE             Targets file (text, CSV with url column, or JSON)
  --output-dir DIR        Output directory
  --resume DIR            Resume prior scan directory (checkpoint-aware)
  --passive               True passive: normal GET + header signatures only (no wafw00f)
  --i-understand          Acknowledge active mode sends WAF triggers (non-interactive)
  --waf-only              Report WAF hits only (CDN-only signals as info)
  --insecure              Disable TLS verification (wafw00f wrapper + curl)
  --no-redirect           Do not follow HTTP redirects
  --proxy URL             Proxy for wafw00f and curl
  --delay SEC             Delay between targets
  --max-targets N         Cap number of targets from file
  --workers N             Parallel workers (default: 1)
  --wafw00f MODE          auto (default), required, none
  --supplemental MODE     auto (default), always, never
  --input-format FMT      text, csv, or json (auto-detect from extension)
  --quiet                 Suppress non-essential output
  --menu                  Interactive menu
  -h, --help              Show this help

Environment: WAF_OUTPUT_DIR, WAF_PASSIVE, WAF_INSECURE
EOF
}

f_waf_parse_cli(){
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) WAF_URL="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --file) WAF_FILE="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --output-dir) WAF_OUTPUT_DIR="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --resume) WAF_RESUME_DIR="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --passive) WAF_PASSIVE=1; WAF_CLI_INVOKED=1; shift ;;
            --i-understand) WAF_I_UNDERSTAND=1; WAF_CLI_INVOKED=1; shift ;;
            --waf-only) WAF_WAF_ONLY=1; WAF_CLI_INVOKED=1; shift ;;
            --insecure) WAF_INSECURE=1; WAF_CLI_INVOKED=1; shift ;;
            --no-redirect) WAF_NO_REDIRECT=1; WAF_CLI_INVOKED=1; shift ;;
            --proxy) WAF_PROXY="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --delay) WAF_DELAY="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --max-targets) WAF_MAX_TARGETS="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --workers) WAF_WORKERS="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --wafw00f) WAF_USE_WAFW00F="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --supplemental) WAF_SUPPLEMENTAL="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --input-format) WAF_INPUT_FORMAT="$2"; WAF_CLI_INVOKED=1; shift 2 ;;
            --quiet) WAF_QUIET=1; WAF_CLI_INVOKED=1; shift ;;
            --menu) WAF_USE_MENU=1; shift ;;
            -h|--help) f_waf_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_waf_usage; exit 1 ;;
        esac
    done
}