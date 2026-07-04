# API Scanner shared library — sourced by dev/api-scanner.sh
#
# Output policy: all artifacts live under \$HOME/data/api-scan_*/api_scanner/.
# Never writes to Discover recon report paths (\$NAME, pages/*.htm, report.sh).

API_SCANNER_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
API_DATA_DIR="${API_SCANNER_SCRIPT_DIR}/data"

# Microsoft Edge UA — keep in sync with discover.sh; used by curl, ffuf, and feroxbuster
API_EDGE_USER_AGENT="${USER_AGENT:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.86}"
USER_AGENT="$API_EDGE_USER_AGENT"
export USER_AGENT

# Configurable defaults (override via env or CLI)
API_MAX_PARALLEL="${API_MAX_PARALLEL:-3}"
API_MAX_ENDPOINTS="${API_MAX_ENDPOINTS:-0}"
API_CONNECT_TIMEOUT="${API_CONNECT_TIMEOUT:-3}"
API_MAX_TIME="${API_MAX_TIME:-7}"
API_AGGRESSIVE_HTTP="${API_AGGRESSIVE_HTTP_METHODS:-0}"
API_AUTHORIZED="${API_AUTHORIZED:-0}"
API_SCAN_MODE="${API_SCAN_MODE:-full}"
API_SKIP_PHASES="${API_SKIP_PHASES:-}"
API_BEARER_TOKEN="${API_BEARER_TOKEN:-}"
API_COOKIE_FILE="${API_COOKIE_FILE:-}"
API_REQUEST_COUNT=0

f_api_check_deps(){
    local missing=()
    for cmd in curl jq; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required tools: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Run Discover update.sh to install dependencies.${NC}"
        exit 1
    fi
    if ! command -v ffuf >/dev/null 2>&1 && ! command -v feroxbuster >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] ffuf/feroxbuster not found; using sequential path probing only.${NC}"
    fi
}

f_api_init_scan(){
    local target="$1"
    local resuming="${2:-0}"
    API_SCAN_LOG="${OUTPUT_DIR}/api_scanner/scan.log"
    API_CHECKPOINT_DIR="${OUTPUT_DIR}/api_scanner/.checkpoint"
    API_FINDINGS_FILE="${OUTPUT_DIR}/api_scanner/findings_registry.tsv"
    API_VULN_URL_FILE="${OUTPUT_DIR}/api_scanner/vulnerable_urls.txt"
    API_TARGET_URL="$target"
    API_TARGET_AUTHORITY=$(f_url_authority "$target")
    API_TARGET_HOST="${API_TARGET_AUTHORITY%%:*}"

    mkdir -p "${OUTPUT_DIR}/api_scanner" "${API_CHECKPOINT_DIR}"
    touch "$API_SCAN_LOG"
    if [ "$resuming" = "1" ] && [ -s "$API_FINDINGS_FILE" ]; then
        touch "$API_VULN_URL_FILE"
    else
        echo -e "severity\tconfidence\tcategory\turl\tevidence\tdescription" > "$API_FINDINGS_FILE"
        : > "$API_VULN_URL_FILE"
    fi

    {
        echo "=== API Scan started $(date -Iseconds) ==="
        echo "Target: $target"
        echo "Mode: $API_SCAN_MODE"
        echo "Max parallel: $API_MAX_PARALLEL"
        echo "Max endpoints: ${API_MAX_ENDPOINTS:-unlimited}"
        echo "Authorized: $API_AUTHORIZED"
        echo "Bearer token: $([ -n "$API_BEARER_TOKEN" ] && echo set || echo none)"
        echo "Cookie file: ${API_COOKIE_FILE:-none}"
    } >> "$API_SCAN_LOG"
}

f_api_log(){
    echo "[$(date -Iseconds)] $*" >> "$API_SCAN_LOG"
}

f_api_should_run_phase(){
    local phase="$1"
    echo ",${API_SKIP_PHASES}," | grep -q ",${phase}," && return 1
    [ -f "${API_CHECKPOINT_DIR}/${phase}.done" ] && return 1
    return 0
}

f_api_mark_phase(){
    touch "${API_CHECKPOINT_DIR}/$1.done"
    f_api_log "Phase completed: $1"
}

f_url_authority(){
    local url="$1"
    if [[ "$url" =~ ^https?://([^/]+) ]]; then
        echo "${BASH_REMATCH[1]}"
    fi
}

f_url_normalize(){
    local url="$1"
    url="${url%%#*}"
    url="${url%/}"
    echo "$url"
}

f_graphql_introspection_ok(){
    local file="$1"
    command -v jq >/dev/null 2>&1 && jq -e '.data.__schema.queryType.name' "$file" >/dev/null 2>&1
}

f_graphql_has_data(){
    local file="$1"
    command -v jq >/dev/null 2>&1 && jq -e '.data != null and (.data | keys | length) > 0' "$file" >/dev/null 2>&1
}

f_merge_endpoint_lists(){
    local outfile="$1"
    shift
    local tmp
    tmp=$(mktemp)
    {
        for src in "$@"; do
            [ -f "$src" ] && cat "$src"
        done
    } | while read -r line; do
        line="${line%% *}"
        [ -n "$line" ] && f_url_normalize "$line"
    done | grep -v '^[[:space:]]*$' | sort -u > "$tmp"
    mv "$tmp" "$outfile"
}

f_record_vuln_url(){
    local url="$1"
    grep -Fxq "$url" "$API_VULN_URL_FILE" 2>/dev/null || echo "$url" >> "$API_VULN_URL_FILE"
}

f_api_record_finding(){
    local severity="$1" confidence="$2" category="$3" url="$4" evidence="$5" description="$6"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$severity" "$confidence" "$category" "$url" "$evidence" "$description" >> "$API_FINDINGS_FILE"
    f_record_vuln_url "$url"
    f_api_log "FINDING [$severity/$confidence] $category $url — $description (evidence: $evidence)"
}

f_api_curl_args(){
    local -n _out=$1
    _out=( -s -H "User-Agent: ${USER_AGENT}" --connect-timeout "$API_CONNECT_TIMEOUT" -m "$API_MAX_TIME" )
    [ -n "$API_BEARER_TOKEN" ] && _out+=( -H "Authorization: Bearer ${API_BEARER_TOKEN}" )
    [ -n "$API_COOKIE_FILE" ] && [ -f "$API_COOKIE_FILE" ] && _out+=( -b "$API_COOKIE_FILE" )
}

f_api_request(){
    local method="${1:-GET}" url="$2"
    shift 2
    local curl_args=()
    f_api_curl_args curl_args
    ((API_REQUEST_COUNT++))
    f_api_log "REQUEST #$API_REQUEST_COUNT $method $url $*"
    curl "${curl_args[@]}" -X "$method" "$url" "$@"
}

f_api_paths_file(){
    local dest="$1"
    if [ -f "${API_DATA_DIR}/api-paths.txt" ]; then
        grep -v '^[[:space:]]*#' "${API_DATA_DIR}/api-paths.txt" | grep -v '^[[:space:]]*$' > "$dest"
    else
        echo -e "${RED}[!] Missing ${API_DATA_DIR}/api-paths.txt${NC}"
        exit 1
    fi
}

f_api_swagger_paths(){
    [ -f "${API_DATA_DIR}/swagger-paths.txt" ] && \
        grep -v '^[[:space:]]*#' "${API_DATA_DIR}/swagger-paths.txt" | grep -v '^[[:space:]]*$'
}

f_api_build_cors_origins(){
    local host="$1" authority="$2" outfile="$3"
    local base="${host%%:*}"
    cat > "$outfile" <<EOF
null
https://evil.com
https://attacker.${base}
https://${base}.evil.com
https://subdomain.${authority}
https://not${base}
https://${authority}@${base}
https://${base}%60.evil.com
EOF
}

f_api_limit_endpoints(){
    local file="$1"
    [ "$API_MAX_ENDPOINTS" -gt 0 ] || return 0
    local tmp
    tmp=$(mktemp)
    head -n "$API_MAX_ENDPOINTS" "$file" > "$tmp"
    mv "$tmp" "$file"
}

f_api_jwt_decode_part(){
    local raw="$1"
    [ $((${#raw} % 4)) -eq 2 ] && raw="${raw}=="
    [ $((${#raw} % 4)) -eq 3 ] && raw="${raw}="
    raw=$(echo "$raw" | tr '_-' '/+')
    echo "$raw" | base64 -d 2>/dev/null
}

f_api_jwt_deep_check(){
    local token="$1" outdir="$2"
    local raw_h raw_p header payload exp now
    raw_h=$(echo "$token" | cut -d. -f1)
    raw_p=$(echo "$token" | cut -d. -f2)
    header=$(f_api_jwt_decode_part "$raw_h")
    payload=$(f_api_jwt_decode_part "$raw_p")
    local safe="${token:0:10}"
    echo "$header" | jq . > "${outdir}/jwt_header_${safe}.json" 2>/dev/null || echo "$header" > "${outdir}/jwt_header_${safe}.json"
    echo "$payload" | jq . > "${outdir}/jwt_payload_${safe}.json" 2>/dev/null || echo "$payload" > "${outdir}/jwt_payload_${safe}.json"

    if echo "$header" | grep -qE '"alg"\s*:\s*"none"'; then
        f_api_record_finding "critical" "confirmed" "jwt" "inline" "${outdir}/jwt_header_${safe}.json" "JWT uses alg:none"
    fi
    if echo "$payload" | grep -qE '"password"|"api_key"|"secret"|"private"'; then
        f_api_record_finding "high" "confirmed" "jwt" "inline" "${outdir}/jwt_payload_${safe}.json" "JWT payload contains sensitive fields"
    fi
    if ! echo "$payload" | grep -q '"exp"'; then
        f_api_record_finding "medium" "confirmed" "jwt" "inline" "${outdir}/jwt_payload_${safe}.json" "JWT missing exp claim"
    else
        exp=$(echo "$payload" | jq -r '.exp // empty' 2>/dev/null)
        now=$(date +%s)
        if [ -n "$exp" ] && [ "$exp" -lt "$now" ]; then
            f_api_record_finding "low" "confirmed" "jwt" "inline" "${outdir}/jwt_payload_${safe}.json" "JWT is expired"
        fi
    fi
    if ! echo "$payload" | grep -q '"iss"'; then
        f_api_record_finding "low" "likely" "jwt" "inline" "${outdir}/jwt_payload_${safe}.json" "JWT missing iss claim"
    fi
    if ! echo "$payload" | grep -q '"aud"'; then
        f_api_record_finding "low" "likely" "jwt" "inline" "${outdir}/jwt_payload_${safe}.json" "JWT missing aud claim"
    fi
}

f_api_count_findings(){
    local category="$1" confidence="${2:-}"
    local count
    if [ -n "$confidence" ]; then
        count=$(awk -F'\t' -v c="$category" -v cf="$confidence" '$3==c && $2==cf {n++} END{print n+0}' "$API_FINDINGS_FILE")
    else
        count=$(awk -F'\t' -v c="$category" '$3==c {n++} END{print n+0}' "$API_FINDINGS_FILE")
    fi
    echo "$count"
}