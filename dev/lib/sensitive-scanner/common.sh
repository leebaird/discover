# Sensitive Scanner shared library — sourced by dev/sensitive-scanner.sh

SENSITIVE_SCANNER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENSITIVE_SCANNER_ROOT="$(cd "${SENSITIVE_SCANNER_LIB_DIR}/../.." && pwd)"

SENSITIVE_SCAN_MODE="${SENSITIVE_SCAN_MODE:-full}"
SENSITIVE_SCAN_TYPES="${SENSITIVE_SCAN_TYPES:-}"
SENSITIVE_PATH="${SENSITIVE_PATH:-}"
SENSITIVE_URL="${SENSITIVE_URL:-}"
SENSITIVE_SCAN_DIR="${SENSITIVE_SCAN_DIR:-}"
SENSITIVE_OUTPUT_DIR="${SENSITIVE_OUTPUT_DIR:-}"
SENSITIVE_RESUME_DIR="${SENSITIVE_RESUME_DIR:-}"
SENSITIVE_DELAY="${SENSITIVE_DELAY:-0}"
SENSITIVE_MAX_PATHS="${SENSITIVE_MAX_PATHS:-0}"
SENSITIVE_USE_MENU="${SENSITIVE_USE_MENU:-0}"
SENSITIVE_CLI_INVOKED="${SENSITIVE_CLI_INVOKED:-0}"
SENSITIVE_QUIET="${SENSITIVE_QUIET:-0}"
SENSITIVE_WORKERS="${SENSITIVE_WORKERS:-10}"
SENSITIVE_RPS="${SENSITIVE_RPS:-0}"
SENSITIVE_WORDLIST="${SENSITIVE_WORDLIST:-}"
SENSITIVE_BEARER_TOKEN="${SENSITIVE_BEARER_TOKEN:-}"
SENSITIVE_INSECURE="${SENSITIVE_INSECURE:-0}"
SENSITIVE_NO_STORE_CONTENT="${SENSITIVE_NO_STORE_CONTENT:-0}"
SENSITIVE_SHRED_CONTENT="${SENSITIVE_SHRED_CONTENT:-0}"
SENSITIVE_REDACT_EMAILS="${SENSITIVE_REDACT_EMAILS:-0}"
SENSITIVE_ENTROPY_MIN="${SENSITIVE_ENTROPY_MIN:-3.5}"
SENSITIVE_EXTERNAL="${SENSITIVE_EXTERNAL:-auto}"

SENSITIVE_SCAN_LOG=""
SENSITIVE_CHECKPOINT_DIR=""
SENSITIVE_FINDINGS_FILE=""
SENSITIVE_FINDINGS_HASH_FILE=""

SENSITIVE_GREP_EXCLUDES=(
    --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=vendor
    --exclude-dir=dist --exclude-dir=build --exclude-dir=.cache
    --exclude-dir=.venv --exclude-dir=__pycache__
    --binary-files=without-match
)

SENSITIVE_COMMON_INCLUDES=(
    --include="*.js" --include="*.jsx" --include="*.ts" --include="*.tsx"
    --include="*.php" --include="*.py" --include="*.rb" --include="*.java"
    --include="*.json" --include="*.xml" --include="*.yaml" --include="*.yml"
    --include="*.conf" --include="*.config" --include="*.env"
    --include="*.ini" --include="*.properties" --include="*.sh"
)

SENSITIVE_WEB_INCLUDES=(
    "${SENSITIVE_COMMON_INCLUDES[@]}"
    --include="*.html" --include="*.htm"
)

SENSITIVE_TOKEN_INCLUDES=(
    "${SENSITIVE_COMMON_INCLUDES[@]}"
    --include="*.log" --include="*.txt"
)

f_sensitive_now(){
    date -Iseconds
}

f_sensitive_init_scan(){
    local resuming="${1:-0}"
    SENSITIVE_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    SENSITIVE_CHECKPOINT_DIR="${OUTPUT_DIR}/.checkpoint"
    SENSITIVE_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"
    SENSITIVE_FINDINGS_HASH_FILE="${OUTPUT_DIR}/.findings_hashes"

    mkdir -p "$SENSITIVE_CHECKPOINT_DIR" "${OUTPUT_DIR}/sensitive_info" "${OUTPUT_DIR}/web_sensitive"
    touch "$SENSITIVE_SCAN_LOG"

    if [ "$resuming" = "1" ] && [ -s "$SENSITIVE_FINDINGS_FILE" ]; then
        touch "$SENSITIVE_FINDINGS_HASH_FILE"
    else
        printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$SENSITIVE_FINDINGS_FILE"
        : > "$SENSITIVE_FINDINGS_HASH_FILE"
    fi

    {
        echo "=== Sensitive scan started $(f_sensitive_now) ==="
        echo "Mode: $SENSITIVE_SCAN_MODE"
        echo "Types: ${SENSITIVE_SCAN_TYPES:-menu}"
        echo "Path: ${SENSITIVE_PATH:-n/a}"
        echo "URL: ${SENSITIVE_URL:-n/a}"
        echo "Scan dir: ${SENSITIVE_SCAN_DIR:-n/a}"
        echo "Output: $OUTPUT_DIR"
    } >> "$SENSITIVE_SCAN_LOG"
}

f_sensitive_log(){
    echo "[$(f_sensitive_now)] $*" >> "$SENSITIVE_SCAN_LOG"
}

f_sensitive_should_run_phase(){
    local phase="$1"
    [ -f "${SENSITIVE_CHECKPOINT_DIR}/${phase}.done" ] && return 1
    return 0
}

f_sensitive_mark_phase(){
    touch "${SENSITIVE_CHECKPOINT_DIR}/$1.done"
    f_sensitive_log "Phase completed: $1"
}

f_sensitive_say(){
    [ "$SENSITIVE_QUIET" = "1" ] && return 0
    printf '%b\n' "$*"
}

f_sensitive_redact(){
    local text="$1"
    if [ "$SENSITIVE_REDACT_EMAILS" = "1" ]; then
        text=$(printf '%s' "$text" | sed -E 's/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/[EMAIL_REDACTED]/g')
    fi
    printf '%s' "$text" | sed -E \
        -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/[JWT_REDACTED]/g' \
        -e 's/(aws[_-]?secret[_-]?access[_-]?key[[:space:]]*[=:][[:space:]]*)[^[:space:]'"'"']+/\1[REDACTED]/gi' \
        -e 's/([A-Za-z0-9_+=/]{6})[A-Za-z0-9_+=/]{10,}([A-Za-z0-9_+=/]{4})/\1[REDACTED]\2/g' \
        -e 's/([0-9]{4})[0-9]{4,}([0-9]{4})/\1[REDACTED]\2/g'
}

f_sensitive_finding_hash(){
    local domain="$1" resource="$2" check="$3" detail="$4"
    printf '%s|%s|%s|%s' "$domain" "$resource" "$check" "$detail" | sha256sum | awk '{print $1}'
}

f_sensitive_finding_seen(){
    local hash="$1"
    [ -f "$SENSITIVE_FINDINGS_HASH_FILE" ] && grep -qxF "$hash" "$SENSITIVE_FINDINGS_HASH_FILE" 2>/dev/null
}

f_sensitive_slug(){
    local s
    s=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | sed 's/^_\+//;s/_$//')
    [ -n "$s" ] || s="item"
    printf '%s' "$s"
}

f_sensitive_record_finding(){
    local severity="$1" domain="$2" resource="$3" check="$4" detail="$5" evidence="$6"
    local lockfile="${OUTPUT_DIR}/.findings.lock" fhash
    detail=$(f_sensitive_redact "$detail")
    fhash=$(f_sensitive_finding_hash "$domain" "$resource" "$check" "$detail")
    (
        flock -x 9
        f_sensitive_finding_seen "$fhash" && exit 0
        printf '%s\n' "$fhash" >> "$SENSITIVE_FINDINGS_HASH_FILE"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$severity" "$domain" "$resource" "$check" "$detail" "$evidence" >> "$SENSITIVE_FINDINGS_FILE"
        echo "[$(f_sensitive_now)] FINDING [$severity] $domain/$resource — $check: $detail" >> "$SENSITIVE_SCAN_LOG"
    ) 9>"$lockfile"
}

f_sensitive_import_jsonl(){
    local jsonl="$1"
    [ -s "$jsonl" ] || return 0
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        local severity domain resource check detail evidence
        severity=$(printf '%s' "$row" | jq -r '.severity // empty')
        domain=$(printf '%s' "$row" | jq -r '.domain // empty')
        resource=$(printf '%s' "$row" | jq -r '.resource // empty')
        check=$(printf '%s' "$row" | jq -r '.check // empty')
        detail=$(printf '%s' "$row" | jq -r '.detail // empty')
        evidence=$(printf '%s' "$row" | jq -r '.evidence // empty')
        [ -n "$severity" ] && [ -n "$check" ] || continue
        f_sensitive_record_finding "$severity" "${domain:-unknown}" "${resource:-unknown}" \
            "$check" "$detail" "${evidence:-}"
    done < "$jsonl"
}

f_sensitive_count_findings(){
    local severity="${1:-}" domain="${2:-}"
    awk -F'\t' -v sev="$severity" -v dom="$domain" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            if (dom != "" && $2 != dom) next
            n++
        }
        END { print n + 0 }
    ' "$SENSITIVE_FINDINGS_FILE"
}

f_sensitive_setup_output(){
    if [ -n "$SENSITIVE_RESUME_DIR" ]; then
        OUTPUT_DIR="$SENSITIVE_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_sensitive_init_scan 1
        return 0
    fi

    if [ -n "$SENSITIVE_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$SENSITIVE_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/sensitive-scan_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    f_sensitive_init_scan 0
}

f_sensitive_write_findings_json(){
    local stamp="$1"
    local crit high warn info total findings

    crit=$(f_sensitive_count_findings critical)
    high=$(f_sensitive_count_findings high)
    warn=$(f_sensitive_count_findings warning)
    info=$(f_sensitive_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$SENSITIVE_FINDINGS_FILE")

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$SENSITIVE_FINDINGS_FILE" | jq -R -s '
            split("\n") | map(select(length > 0)) | map(split("\t"))
            | map({severity:.[0],domain:.[1],resource:.[2],check:.[3],detail:.[4],evidence:(if length>5 then .[5] else "" end)})
        ')
    else
        findings='[]'
    fi

    jq -n \
        --arg scanner "sensitive-scanner" \
        --arg generated "$stamp" \
        --arg mode "$SENSITIVE_SCAN_MODE" \
        --arg scan_types "${SENSITIVE_SCAN_TYPES:-all}" \
        --arg path "${SENSITIVE_PATH:-}" \
        --arg url "${SENSITIVE_URL:-}" \
        --arg scan_dir "${SENSITIVE_SCAN_DIR:-}" \
        --arg output_dir "$OUTPUT_DIR" \
        --argjson critical "$crit" \
        --argjson high "$high" \
        --argjson warning "$warn" \
        --argjson info "$info" \
        --argjson total "$total" \
        --argjson findings "$findings" \
        '{scanner:$scanner,generated:$generated,mode:$mode,scan_types:$scan_types,path:$path,url:$url,scan_dir:$scan_dir,output_dir:$output_dir,summary:{critical:$critical,high:$high,warning:$warning,info:$info,total:$total},findings:$findings}' \
        > "${OUTPUT_DIR}/findings.json"
}

f_sensitive_generate_reports(){
    local stamp
    stamp=$(f_sensitive_now)
    local crit high warn info total
    crit=$(f_sensitive_count_findings critical)
    high=$(f_sensitive_count_findings high)
    warn=$(f_sensitive_count_findings warning)
    info=$(f_sensitive_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$SENSITIVE_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
Sensitive Information Scanner Report
====================================
AUTHORIZED SECURITY TESTING ONLY — handle findings as confidential.

Generated: $stamp
Mode:      $SENSITIVE_SCAN_MODE
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
    }' "$SENSITIVE_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# Sensitive Information Scanner Report

> **Authorized security testing only.** Stored artifacts may contain secrets; use \`--no-store-content\` or \`--shred-content\` when needed.

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Mode | $SENSITIVE_SCAN_MODE |
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
    }' "$SENSITIVE_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    echo "Scan log: \`scan.log\`" >> "${OUTPUT_DIR}/report.md"
    f_sensitive_write_findings_json "$stamp"
    f_sensitive_log "Reports written. Findings: $total"
}

f_sensitive_append_summary_section(){
    local title="$1" hits_file="$2" max="${3:-10}"
    echo "[$title]"
    if [ -s "$hits_file" ]; then
        local n
        n=$(wc -l < "$hits_file")
        echo "  Found $n match(es)"
        head -n "$max" "$hits_file" | while read -r line; do
            echo "  - $(f_sensitive_redact "$line")"
        done
        [ "$n" -gt "$max" ] && echo "  (More in $(basename "$hits_file"))"
    else
        echo "  None found."
    fi
    echo
}

f_sensitive_luhn_valid(){
    python3 - "$1" <<'PY'
import sys
def luhn(s):
    s = ''.join(c for c in s if c.isdigit())
    if len(s) < 13 or len(s) > 19:
        return False
    total = 0
    rev = s[::-1]
    for i, ch in enumerate(rev):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0
print('yes' if luhn(sys.argv[1]) else 'no')
PY
}

f_sensitive_tc_kimlik_valid(){
    python3 - "$1" <<'PY'
import sys
s = sys.argv[1].strip()
if len(s) != 11 or not s.isdigit() or s[0] == '0':
    print('no'); raise SystemExit
d = [int(x) for x in s]
if ((d[0]+d[2]+d[4]+d[6]+d[8])*7 - (d[1]+d[3]+d[5]+d[7])) % 10 != d[9]:
    print('no'); raise SystemExit
if sum(d[:10]) % 10 != d[10]:
    print('no'); raise SystemExit
print('yes')
PY
}

f_sensitive_import_grep_hits(){
    local hits_file="$1" severity="$2" check="$3" domain="$4"
    local ev_prefix="${5:-sensitive_info}"
    [ -s "$hits_file" ] || return 0
    local line resource detail ev_base
    ev_base=$(basename "$hits_file")
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        resource=$(printf '%s' "$line" | cut -d: -f1)
        resource=${resource:-unknown}
        detail=$(f_sensitive_redact "$line")
        f_sensitive_record_finding "$severity" "$domain" "$resource" "$check" "$detail" "${ev_prefix}/${ev_base}"
    done < "$hits_file"
}

f_sensitive_collect_extra_paths(){
    local list_file="$1"
    local base dir
    [ -n "$SENSITIVE_SCAN_DIR" ] && [ -d "$SENSITIVE_SCAN_DIR" ] || return 0
    base="$SENSITIVE_SCAN_DIR"
    for dir in \
        "$base/api_scanner/responses" \
        "$base/api_scanner/crawl" \
        "$base/sensitive_info"; do
        [ -d "$dir" ] || continue
        find "$dir" -type f -size -5M 2>/dev/null >> "$list_file"
    done
}

f_sensitive_usage(){
    cat <<EOF
Usage: sensitive-scanner.sh [options]

Options:
  --path PATH             Scan a file or directory locally
  --url URL               Probe a URL for exposed sensitive paths/content
  --scan-dir DIR          Also scan files from a prior Discover scan output
  --wordlist FILE         Custom web path wordlist
  --quick                 Reduced web paths and file patterns (patterns TSV)
  --full                  Full scan (default)
  --workers N             Parallel web workers (default: 10)
  --delay SEC             Delay between web path probes
  --rps N                 Max web requests per second (0 = unlimited)
  --max-paths N           Limit web paths checked (0 = unlimited)
  --bearer-token TOKEN    Bearer token for authenticated web probes
  --insecure              Disable TLS certificate verification (curl/requests)
  --no-store-content      Probe web paths without saving response bodies
  --shred-content         Delete downloaded web bodies after analysis
  --redact-emails         Redact email addresses in findings/reports
  --entropy-min N         Min Shannon entropy for generic key=value hits (default: 3.5)
  --external MODE         External scanners: auto, gitleaks, trufflehog, none
  --files                 File/path scan only
  --web                   URL scan only
  --all                   File + URL scan (needs --url and --path or --scan-dir)
  --output-dir DIR        Output directory
  --resume DIR            Resume prior scan directory
  --quiet                 Suppress non-essential output
  --menu                  Interactive menu
  -h, --help              Show this help

Environment: SENSITIVE_OUTPUT_DIR, SENSITIVE_SCAN_MODE, SENSITIVE_BEARER_TOKEN
EOF
}

f_sensitive_parse_cli(){
    SENSITIVE_SCAN_TYPES=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --quick) SENSITIVE_SCAN_MODE="quick"; SENSITIVE_CLI_INVOKED=1; shift ;;
            --full) SENSITIVE_SCAN_MODE="full"; SENSITIVE_CLI_INVOKED=1; shift ;;
            --path) SENSITIVE_PATH="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --url) SENSITIVE_URL="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --scan-dir) SENSITIVE_SCAN_DIR="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --delay) SENSITIVE_DELAY="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --max-paths) SENSITIVE_MAX_PATHS="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --workers) SENSITIVE_WORKERS="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --rps) SENSITIVE_RPS="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --wordlist) SENSITIVE_WORDLIST="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --bearer-token) SENSITIVE_BEARER_TOKEN="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --insecure) SENSITIVE_INSECURE=1; SENSITIVE_CLI_INVOKED=1; shift ;;
            --no-store-content) SENSITIVE_NO_STORE_CONTENT=1; SENSITIVE_CLI_INVOKED=1; shift ;;
            --shred-content) SENSITIVE_SHRED_CONTENT=1; SENSITIVE_CLI_INVOKED=1; shift ;;
            --redact-emails) SENSITIVE_REDACT_EMAILS=1; SENSITIVE_CLI_INVOKED=1; shift ;;
            --entropy-min) SENSITIVE_ENTROPY_MIN="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --external) SENSITIVE_EXTERNAL="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --quiet) SENSITIVE_QUIET=1; SENSITIVE_CLI_INVOKED=1; shift ;;
            --files) SENSITIVE_SCAN_TYPES="files"; SENSITIVE_CLI_INVOKED=1; shift ;;
            --web) SENSITIVE_SCAN_TYPES="web"; SENSITIVE_CLI_INVOKED=1; shift ;;
            --all) SENSITIVE_SCAN_TYPES="all"; SENSITIVE_CLI_INVOKED=1; shift ;;
            --output-dir) SENSITIVE_OUTPUT_DIR="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --resume) SENSITIVE_RESUME_DIR="$2"; SENSITIVE_CLI_INVOKED=1; shift 2 ;;
            --menu) SENSITIVE_USE_MENU=1; shift ;;
            -h|--help) f_sensitive_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_sensitive_usage; exit 1 ;;
        esac
    done

    if [ "$SENSITIVE_CLI_INVOKED" = "1" ] && [ -z "$SENSITIVE_SCAN_TYPES" ]; then
        if [ -n "$SENSITIVE_PATH" ] && [ -n "$SENSITIVE_URL" ]; then
            SENSITIVE_SCAN_TYPES="all"
        elif [ -n "$SENSITIVE_URL" ]; then
            SENSITIVE_SCAN_TYPES="web"
        elif [ -n "$SENSITIVE_PATH" ] || [ -n "$SENSITIVE_SCAN_DIR" ]; then
            SENSITIVE_SCAN_TYPES="files"
        fi
    fi
}

f_sensitive_normalize_url(){
    local u="$1"
    [[ "$u" =~ ^https?:// ]] || u="https://${u}"
    printf '%s' "$u"
}

f_sensitive_resolve_scan_roots(){
    local -n _out=$1
    _out=()
    if [ -n "$SENSITIVE_PATH" ]; then
        if [ -f "$SENSITIVE_PATH" ]; then
            _out+=("$SENSITIVE_PATH")
        elif [ -d "$SENSITIVE_PATH" ]; then
            _out+=("$SENSITIVE_PATH")
        fi
    fi
    if [ -n "$SENSITIVE_SCAN_DIR" ] && [ -d "$SENSITIVE_SCAN_DIR" ]; then
        local extra="${OUTPUT_DIR}/extra_scan_paths.txt"
        : > "$extra"
        f_sensitive_collect_extra_paths "$extra"
        while read -r p; do
            [ -n "$p" ] && _out+=("$p")
        done < "$extra"
    fi
}