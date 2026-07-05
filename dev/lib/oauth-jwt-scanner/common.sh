# OAuth/JWT Scanner shared library — sourced by dev/oauth-jwt-scanner.sh

OAUTH_JWT_SCANNER_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OAUTH_JWT_SCAN_MODE="${OAUTH_JWT_SCAN_MODE:-full}"
OAUTH_JWT_SCAN_TYPES="${OAUTH_JWT_SCAN_TYPES:-}"
OAUTH_JWT_TARGET="${OAUTH_JWT_TARGET:-}"
OAUTH_JWT_TOKEN="${OAUTH_JWT_TOKEN:-}"
OAUTH_JWT_ENDPOINT="${OAUTH_JWT_ENDPOINT:-}"
OAUTH_JWT_CLIENT_ID="${OAUTH_JWT_CLIENT_ID:-client_id}"
OAUTH_JWT_REDIRECT_URI="${OAUTH_JWT_REDIRECT_URI:-https://example.com/callback}"
OAUTH_JWT_JWT_FILE="${OAUTH_JWT_JWT_FILE:-}"
OAUTH_JWT_API_SCAN_DIR="${OAUTH_JWT_API_SCAN_DIR:-}"
OAUTH_JWT_OUTPUT_DIR="${OAUTH_JWT_OUTPUT_DIR:-}"
OAUTH_JWT_RESUME_DIR="${OAUTH_JWT_RESUME_DIR:-}"
OAUTH_JWT_USE_MENU="${OAUTH_JWT_USE_MENU:-0}"
OAUTH_JWT_CLI_INVOKED="${OAUTH_JWT_CLI_INVOKED:-0}"

OAUTH_JWT_SCAN_LOG=""
OAUTH_JWT_CHECKPOINT_DIR=""
OAUTH_JWT_FINDINGS_FILE=""

OAUTH_JWT_SENSITIVE_CLAIMS='["password","passwd","secret","api_key","apikey","private_key","credential","ssn","credit_card","cvv","refresh_token","access_token"]'

f_oauth_jwt_now(){
    date -Iseconds
}

f_oauth_jwt_b64url_decode(){
    local seg="$1" padded
    seg=$(printf '%s' "$seg" | tr '_-' '/+')
    padded="$seg"
    while (( ${#padded} % 4 != 0 )); do padded="${padded}="; done
    printf '%s' "$padded" | base64 -d 2>/dev/null
}

f_oauth_jwt_b64url_encode(){
    base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
}

f_oauth_jwt_endpoint_file_id(){
    local endpoint="$1" hash
    hash=$(printf '%s' "$endpoint" | sha256sum | awk '{print substr($1,1,10)}')
    echo "${hash}_$(printf '%s' "$endpoint" | tr '/:' '_')"
}

f_oauth_jwt_slug(){
    local s
    s=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | sed 's/^_\+//;s/_$//')
    [ -n "$s" ] || s="probe"
    echo "$s"
}

f_oauth_jwt_valid_jwt(){
    [[ "$1" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?$ ]]
}

f_oauth_jwt_redact_token(){
    local jwt="$1"
    local h p s
    h=$(printf '%s' "$jwt" | cut -d. -f1)
    p=$(printf '%s' "$jwt" | cut -d. -f2)
    s=$(printf '%s' "$jwt" | cut -d. -f3-)
    if [ -n "$s" ]; then
        echo "${h}.${p}.[REDACTED_SIG]"
    else
        echo "${h}.${p}."
    fi
}

f_oauth_jwt_curl(){
    curl -s --connect-timeout 10 --max-time 20 "$@"
}

f_oauth_jwt_urlencode(){
    local raw="$1"
    local i c hex out=""
    for ((i = 0; i < ${#raw}; i++)); do
        c="${raw:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) printf -v hex '%%%02X' "'$c"; out+="$hex" ;;
        esac
    done
    printf '%s' "$out"
}

f_oauth_jwt_redirect_accepted(){
    local headers_file="$1" body_file="$2" evil_redirect="$3"
    local evil_host location

    evil_host=$(printf '%s' "$evil_redirect" | sed -E 's#^https?://([^/]+).*#\1#')
    location=$(grep -i '^location:' "$headers_file" 2>/dev/null | head -1 | cut -d' ' -f2- | tr -d '\r')

    if [ -n "$location" ]; then
        case "$location" in
            "$evil_redirect"*|"$evil_redirect/?"*)
                if ! printf '%s' "$location" | grep -qiE '[?&#]error='; then
                    return 0
                fi
                ;;
            *"$evil_host"*)
                if printf '%s' "$location" | grep -qiE '[?&#](code|access_token)=' && \
                   ! printf '%s' "$location" | grep -qiE '[?&#]error='; then
                    return 0
                fi
                ;;
        esac
    fi

    if [ -s "$body_file" ] && grep -qiE '[?&#](code|access_token)=' "$body_file" && \
       ! grep -qiE 'invalid_redirect|redirect_uri|unsupported_response_type|error=' "$body_file"; then
        return 0
    fi
    return 1
}

f_oauth_jwt_authorize_without_state(){
    local headers_file="$1" body_file="$2"

    if grep -qiE '^location:.*[?&#](code|access_token)=' "$headers_file" 2>/dev/null && \
       ! grep -qiE '^location:.*[?&#]error=' "$headers_file" 2>/dev/null; then
        return 0
    fi

    if [ -s "$body_file" ] && grep -qiE '[?&#](code|access_token)=' "$body_file" && \
       ! grep -qiE 'invalid_request|missing.*state|error=' "$body_file"; then
        return 0
    fi
    return 1
}

f_oauth_jwt_init_scan(){
    local resuming="${1:-0}"
    OAUTH_JWT_SCAN_LOG="${OUTPUT_DIR}/scan.log"
    OAUTH_JWT_CHECKPOINT_DIR="${OUTPUT_DIR}/.checkpoint"
    OAUTH_JWT_FINDINGS_FILE="${OUTPUT_DIR}/findings_registry.tsv"

    mkdir -p "$OAUTH_JWT_CHECKPOINT_DIR"
    touch "$OAUTH_JWT_SCAN_LOG"

    if [ "$resuming" = "1" ] && [ -s "$OAUTH_JWT_FINDINGS_FILE" ]; then
        :
    else
        printf '%s\n' 'severity	domain	resource	check	detail	evidence' > "$OAUTH_JWT_FINDINGS_FILE"
    fi

    {
        echo "=== OAuth/JWT scan started $(f_oauth_jwt_now) ==="
        echo "Mode: $OAUTH_JWT_SCAN_MODE"
        echo "Types: ${OAUTH_JWT_SCAN_TYPES:-menu}"
        echo "Target: ${OAUTH_JWT_TARGET:-n/a}"
        echo "JWT endpoint: ${OAUTH_JWT_ENDPOINT:-n/a}"
        echo "Output: $OUTPUT_DIR"
    } >> "$OAUTH_JWT_SCAN_LOG"
}

f_oauth_jwt_log(){
    echo "[$(f_oauth_jwt_now)] $*" >> "$OAUTH_JWT_SCAN_LOG"
}

f_oauth_jwt_should_run_phase(){
    local phase="$1"
    [ -f "${OAUTH_JWT_CHECKPOINT_DIR}/${phase}.done" ] && return 1
    return 0
}

f_oauth_jwt_mark_phase(){
    touch "${OAUTH_JWT_CHECKPOINT_DIR}/$1.done"
    f_oauth_jwt_log "Phase completed: $1"
}

f_oauth_jwt_record_finding(){
    local severity="$1" domain="$2" resource="$3" check="$4" detail="$5" evidence="$6"
    local lockfile="${OUTPUT_DIR}/.findings.lock"
    (
        flock -x 9
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$severity" "$domain" "$resource" "$check" "$detail" "$evidence" >> "$OAUTH_JWT_FINDINGS_FILE"
        echo "[$(f_oauth_jwt_now)] FINDING [$severity] $domain/$resource — $check: $detail" >> "$OAUTH_JWT_SCAN_LOG"
    ) 9>"$lockfile"
}

f_oauth_jwt_count_findings(){
    local severity="${1:-}" domain="${2:-}"
    awk -F'\t' -v sev="$severity" -v dom="$domain" '
        NR > 1 {
            if (sev != "" && $1 != sev) next
            if (dom != "" && $2 != dom) next
            n++
        }
        END { print n + 0 }
    ' "$OAUTH_JWT_FINDINGS_FILE"
}

f_oauth_jwt_setup_output(){
    if [ -n "$OAUTH_JWT_RESUME_DIR" ]; then
        OUTPUT_DIR="$OAUTH_JWT_RESUME_DIR"
        [ -d "$OUTPUT_DIR" ] || { echo -e "${RED}[!] Resume directory not found: $OUTPUT_DIR${NC}"; exit 1; }
        f_oauth_jwt_init_scan 1
        return 0
    fi

    if [ -n "$OAUTH_JWT_OUTPUT_DIR" ]; then
        OUTPUT_DIR="$OAUTH_JWT_OUTPUT_DIR"
    else
        OUTPUT_DIR="$HOME/data/oauth-jwt-scan_$(date +%Y%m%d-%H%M)"
    fi
    mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    f_oauth_jwt_init_scan 0
}

f_oauth_jwt_write_findings_json(){
    local stamp="$1"
    local json_file="${OUTPUT_DIR}/findings.json"
    local findings crit high warn info total

    crit=$(f_oauth_jwt_count_findings critical)
    high=$(f_oauth_jwt_count_findings high)
    warn=$(f_oauth_jwt_count_findings warning)
    info=$(f_oauth_jwt_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$OAUTH_JWT_FINDINGS_FILE")

    if [ "$total" -gt 0 ]; then
        findings=$(tail -n +2 "$OAUTH_JWT_FINDINGS_FILE" | jq -R -s '
            split("\n") | map(select(length > 0)) | map(split("\t"))
            | map({severity:.[0],domain:.[1],resource:.[2],check:.[3],detail:.[4],evidence:(if length>5 then .[5] else "" end)})
        ')
    else
        findings='[]'
    fi

    jq -n \
        --arg scanner "oauth-jwt-scanner" \
        --arg generated "$stamp" \
        --arg mode "$OAUTH_JWT_SCAN_MODE" \
        --arg scan_types "${OAUTH_JWT_SCAN_TYPES:-all}" \
        --arg target "${OAUTH_JWT_TARGET:-}" \
        --arg jwt_endpoint "${OAUTH_JWT_ENDPOINT:-}" \
        --arg output_dir "$OUTPUT_DIR" \
        --argjson critical "$crit" \
        --argjson high "$high" \
        --argjson warning "$warn" \
        --argjson info "$info" \
        --argjson total "$total" \
        --argjson findings "$findings" \
        '{scanner:$scanner,generated:$generated,mode:$mode,scan_types:$scan_types,target:$target,jwt_endpoint:$jwt_endpoint,output_dir:$output_dir,summary:{critical:$critical,high:$high,warning:$warning,info:$info,total:$total},findings:$findings}' \
        > "$json_file"
}

f_oauth_jwt_generate_reports(){
    local stamp
    stamp=$(f_oauth_jwt_now)
    local crit high warn info total
    crit=$(f_oauth_jwt_count_findings critical)
    high=$(f_oauth_jwt_count_findings high)
    warn=$(f_oauth_jwt_count_findings warning)
    info=$(f_oauth_jwt_count_findings info)
    total=$(awk 'NR > 1 { n++ } END { print n + 0 }' "$OAUTH_JWT_FINDINGS_FILE")

    cat > "${OUTPUT_DIR}/report.txt" <<EOF
OAuth/JWT Security Scanner Report
=================================
Generated: $stamp
Mode:      $OAUTH_JWT_SCAN_MODE
Target:    ${OAUTH_JWT_TARGET:-n/a}
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
    }' "$OAUTH_JWT_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.txt"

    cat > "${OUTPUT_DIR}/report.md" <<EOF
# OAuth/JWT Security Scanner Report

| Field | Value |
|-------|-------|
| Generated | $stamp |
| Mode | $OAUTH_JWT_SCAN_MODE |
| Target | ${OAUTH_JWT_TARGET:-n/a} |
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
    }' "$OAUTH_JWT_FINDINGS_FILE" >> "${OUTPUT_DIR}/report.md"

    echo "Scan log: \`scan.log\`" >> "${OUTPUT_DIR}/report.md"
    echo "Findings JSON: \`findings.json\`" >> "${OUTPUT_DIR}/report.md"

    f_oauth_jwt_write_findings_json "$stamp"
    f_oauth_jwt_log "Reports written. Findings: $total"
}

f_oauth_jwt_usage(){
    cat <<EOF
Usage: oauth-jwt-scanner.sh [options]

Options:
  --target URL            OAuth/OIDC scan target (base URL)
  --jwt TOKEN             Analyze a JWT offline
  --jwt-file FILE         Analyze JWTs listed one per line
  --api-scan-dir DIR      Also read jwt_found.txt from api-scanner output
  --jwt-endpoint URL      Live-test mutated tokens (Bearer) against API
  --client-id ID          OAuth client_id for probes (default: client_id)
  --redirect-uri URL      Registered redirect_uri for probes
  --quick                 Discovery + critical checks only
  --full                  All checks (default)
  --oauth                 OAuth scan only
  --jwt-only              JWT analysis only (requires --jwt or --jwt-file)
  --all                   OAuth scan then JWT analysis (needs --target and token source)
  --output-dir DIR        Output directory
  --resume DIR            Resume prior scan directory
  --menu                  Interactive menu
  -h, --help              Show this help

Environment: OAUTH_JWT_OUTPUT_DIR, OAUTH_JWT_SCAN_MODE, OAUTH_JWT_CLIENT_ID
EOF
}

f_oauth_jwt_parse_cli(){
    OAUTH_JWT_SCAN_TYPES=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --quick) OAUTH_JWT_SCAN_MODE="quick"; OAUTH_JWT_CLI_INVOKED=1; shift ;;
            --full) OAUTH_JWT_SCAN_MODE="full"; OAUTH_JWT_CLI_INVOKED=1; shift ;;
            --target) OAUTH_JWT_TARGET="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --jwt) OAUTH_JWT_TOKEN="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --jwt-file) OAUTH_JWT_JWT_FILE="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --api-scan-dir) OAUTH_JWT_API_SCAN_DIR="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --jwt-endpoint) OAUTH_JWT_ENDPOINT="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --client-id) OAUTH_JWT_CLIENT_ID="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --redirect-uri) OAUTH_JWT_REDIRECT_URI="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --output-dir) OAUTH_JWT_OUTPUT_DIR="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --resume) OAUTH_JWT_RESUME_DIR="$2"; OAUTH_JWT_CLI_INVOKED=1; shift 2 ;;
            --oauth) OAUTH_JWT_SCAN_TYPES="oauth"; OAUTH_JWT_CLI_INVOKED=1; shift ;;
            --jwt-only) OAUTH_JWT_SCAN_TYPES="jwt"; OAUTH_JWT_CLI_INVOKED=1; shift ;;
            --all) OAUTH_JWT_SCAN_TYPES="all"; OAUTH_JWT_CLI_INVOKED=1; shift ;;
            --menu) OAUTH_JWT_USE_MENU=1; shift ;;
            -h|--help) f_oauth_jwt_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_oauth_jwt_usage; exit 1 ;;
        esac
    done

    if [ "$OAUTH_JWT_CLI_INVOKED" = "1" ] && [ -z "$OAUTH_JWT_SCAN_TYPES" ]; then
        if [ -n "$OAUTH_JWT_TARGET" ] && { [ -n "$OAUTH_JWT_TOKEN" ] || [ -n "$OAUTH_JWT_JWT_FILE" ] || [ -n "$OAUTH_JWT_API_SCAN_DIR" ]; }; then
            OAUTH_JWT_SCAN_TYPES="all"
        elif [ -n "$OAUTH_JWT_TARGET" ]; then
            OAUTH_JWT_SCAN_TYPES="oauth"
        elif [ -n "$OAUTH_JWT_TOKEN" ] || [ -n "$OAUTH_JWT_JWT_FILE" ] || [ -n "$OAUTH_JWT_API_SCAN_DIR" ]; then
            OAUTH_JWT_SCAN_TYPES="jwt"
        fi
    fi
}

f_oauth_jwt_collect_jwt_list(){
    local list_file="$OUTPUT_DIR/jwt_tokens_to_scan.txt"
    : > "$list_file"
    if [ -n "$OAUTH_JWT_TOKEN" ]; then
        echo "$OAUTH_JWT_TOKEN" >> "$list_file"
    fi
    if [ -n "$OAUTH_JWT_JWT_FILE" ] && [ -f "$OAUTH_JWT_JWT_FILE" ]; then
        while read -r t; do
            [ -n "$t" ] && echo "$t" >> "$list_file"
        done < "$OAUTH_JWT_JWT_FILE"
    fi
    if [ -n "$OAUTH_JWT_API_SCAN_DIR" ] && [ -f "$OAUTH_JWT_API_SCAN_DIR/api_scanner/jwt_found.txt" ]; then
        while read -r t; do
            [ -n "$t" ] && echo "$t" >> "$list_file"
        done < "$OAUTH_JWT_API_SCAN_DIR/api_scanner/jwt_found.txt"
    fi
    sort -u "$list_file" -o "$list_file"
}