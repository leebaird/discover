# WAF/CDN awareness — skip brute phases when edge protection is likely

WEBAPI_WAF_PRESENT="${WEBAPI_WAF_PRESENT:-0}"
WEBAPI_SCAN_DIR="${WEBAPI_SCAN_DIR:-}"
WEBAPI_WAF_AWARE="${WEBAPI_WAF_AWARE:-1}"

f_webapi_waf_from_findings_json(){
    local f="$1"
    [ -f "$f" ] || return 1
    jq -e '
        ([.findings[]? | select(.check=="waf_identified" or .check=="cdn_present")] | length) > 0
        or ([.hits[]? | select(.type=="waf" or .type=="cdn" or .type=="both")] | length) > 0
    ' "$f" >/dev/null 2>&1
}

f_webapi_waf_from_signatures(){
    local target_url="$1"
    local sig_file="${WEBAPI_ROOT}/data/waf-signatures.tsv"
    local headers_file="${OUTPUT_DIR}/msf_engine/fingerprint/headers.txt"
    local body_file="${OUTPUT_DIR}/msf_engine/fingerprint/page.html"
    local name header_rx body_rx

    [ -s "$headers_file" ] || return 1
    while IFS=$'\t' read -r name header_rx body_rx; do
        [[ "$name" =~ ^# ]] && continue
        [ -n "$name" ] && [ -n "$header_rx" ] || continue
        if grep -qiE "$header_rx" "$headers_file" 2>/dev/null; then
            return 0
        fi
        if [ -n "${body_rx:-}" ] && [ -s "$body_file" ] && grep -qiE "$body_rx" "$body_file" 2>/dev/null; then
            return 0
        fi
    done < "$sig_file"
    return 1
}

f_webapi_detect_waf_context(){
    local target_url="$1"
    local candidate

    WEBAPI_WAF_PRESENT=0
    [ "$WEBAPI_WAF_AWARE" != "1" ] && return 0

    if [ -n "$WEBAPI_SCAN_DIR" ]; then
        for candidate in \
            "${WEBAPI_SCAN_DIR}/findings.json" \
            "${WEBAPI_SCAN_DIR}/waf_engine/hits.jsonl" \
            "${WEBAPI_SCAN_DIR}/../waf-detection_"*/findings.json; do
            [ -f "$candidate" ] || continue
            if f_webapi_waf_from_findings_json "$candidate"; then
                WEBAPI_WAF_PRESENT=1
                f_webapi_log "WAF/CDN detected from $candidate"
                return 0
            fi
        done
    fi

    if f_webapi_waf_from_signatures "$target_url"; then
        WEBAPI_WAF_PRESENT=1
        f_webapi_log "WAF/CDN detected from passive header signatures"
    fi
}