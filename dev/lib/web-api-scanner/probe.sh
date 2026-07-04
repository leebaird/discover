# Technology fingerprinting and scan orchestration

declare -A WEBAPI_TECH_SCORE=()

f_webapi_reset_tech_flags(){
    WEBAPI_TECH_SCORE=()
}

f_webapi_add_tech_score(){
    local tech="$1" weight="$2"
    WEBAPI_TECH_SCORE["$tech"]=$(( ${WEBAPI_TECH_SCORE[$tech]:-0} + weight ))
}

f_webapi_apply_tech_scores(){
    :
}

f_webapi_fetch_fingerprint(){
    local target_url="$1"
    local work="${OUTPUT_DIR}/msf_engine/fingerprint"
    mkdir -p "$work"
    WEBAPI_PAGE_FILE="${work}/page.html"
    WEBAPI_HEADERS_FILE="${work}/headers.txt"
    WEBAPI_HTTP_STATUS_FILE="${work}/http_status.txt"

    f_webapi_curl_opts
    local status
    status=$(curl "${WEBAPI_CURL_OPTS[@]}" -o "$WEBAPI_PAGE_FILE" -D "$WEBAPI_HEADERS_FILE" \
        -w '%{http_code}' "$target_url" 2>/dev/null || echo "000")
    printf '%s' "$status" > "$WEBAPI_HTTP_STATUS_FILE"
    [ -s "$WEBAPI_PAGE_FILE" ] || : > "$WEBAPI_PAGE_FILE"
    [ -s "$WEBAPI_HEADERS_FILE" ] || : > "$WEBAPI_HEADERS_FILE"
}

f_webapi_probe_path(){
    local target_url="$1" path="$2" match="$3"
    local work="${OUTPUT_DIR}/msf_engine/fingerprint"
    local slug body_file
    slug=$(printf '%s' "$path" | tr -c 'A-Za-z0-9' '_')
    body_file="${work}/path_${slug}.html"

    f_webapi_curl_opts
    curl "${WEBAPI_CURL_OPTS[@]}" -o "$body_file" "${target_url%/}${path}" >/dev/null 2>&1 || return 1
    [ -s "$body_file" ] || return 1
    if [ "$match" = "." ] || [ -z "$match" ]; then
        return 0
    fi
    grep -qiE "$match" "$body_file" 2>/dev/null
}

f_webapi_load_tech_signatures(){
    local target_url="$1"
    local sig_file="${WEBAPI_ROOT}/data/web-api-tech-signatures.tsv"
    local tech stype pattern match weight allow_path=0

    f_webapi_resolve_tier
    [ "$WEBAPI_TIER" != "passive" ] && allow_path=1

    f_webapi_reset_tech_flags

    while IFS=$'\t' read -r tech stype pattern match weight; do
        [[ "$tech" =~ ^# ]] && continue
        [ -n "$tech" ] && [ -n "$stype" ] && [ -n "$pattern" ] || continue
        [ -n "${weight:-}" ] || weight=1
        [ "$match" = "." ] && match=".*"

        case "$stype" in
            header)
                grep -qiE "$pattern" "$WEBAPI_HEADERS_FILE" 2>/dev/null && \
                    f_webapi_add_tech_score "$tech" "$weight"
                ;;
            body)
                grep -qiE "$pattern" "$WEBAPI_PAGE_FILE" 2>/dev/null && \
                    f_webapi_add_tech_score "$tech" "$weight"
                ;;
            path)
                [ "$allow_path" = "1" ] && f_webapi_probe_path "$target_url" "$pattern" "$match" && \
                    f_webapi_add_tech_score "$tech" "$weight"
                ;;
        esac
    done < "$sig_file"
}

f_webapi_detect_technologies(){
    local target_url="$1"
    f_webapi_load_tech_signatures "$target_url"
}

f_webapi_build_tech_scores_json(){
    local scores_json='{}' k
    for k in "${!WEBAPI_TECH_SCORE[@]}"; do
        scores_json=$(jq -n --argjson cur "$scores_json" --arg k "$k" \
            --argjson v "${WEBAPI_TECH_SCORE[$k]}" '$cur + {($k): $v}')
    done
    printf '%s' "$scores_json"
}

f_webapi_record_technologies(){
    local domain="$1" target_url="$2"
    local tech min="${WEBAPI_TECH_MIN_SCORE:-3}" scores_json

    for tech in "${!WEBAPI_TECH_SCORE[@]}"; do
        [ "${WEBAPI_TECH_SCORE[$tech]}" -ge "$min" ] || continue
        f_webapi_record_finding info "$domain" "$target_url" tech_detected \
            "Technology fingerprint: ${tech} (score=${WEBAPI_TECH_SCORE[$tech]})" "msf_engine/fingerprint"
    done

    scores_json=$(f_webapi_build_tech_scores_json)
    jq -n \
        --argjson min_score "$min" \
        --argjson scores "$scores_json" \
        '{min_score:$min_score,scores:$scores}' \
        > "${OUTPUT_DIR}/msf_engine/technologies.json"
}

f_webapi_write_phase_manifest(){
    local -n _phases=$1
    local arr='[]' phase label resource
    f_webapi_resolve_tier
    for phase in "${_phases[@]}"; do
        label=$(f_webapi_msf_phase_label "$phase")
        resource=$(f_webapi_msf_phase_resource "$phase" 2>/dev/null || echo "")
        arr=$(jq -n \
            --argjson cur "$arr" \
            --arg id "$phase" \
            --arg label "$label" \
            --arg resource "$resource" \
            --arg tier "$WEBAPI_TIER" \
            '$cur + [{id:$id,label:$label,resource:$resource,tier:$tier}]')
    done
    printf '%s\n' "$arr" > "${OUTPUT_DIR}/msf_engine/phases.json"
}

f_webapi_filter_checkpoint(){
    local -n _phases=$1
    local filtered=() p
    for p in "${_phases[@]}"; do
        f_webapi_checkpoint_is_done "$p" && { f_webapi_log "Skip checkpoint phase: $p"; continue; }
        filtered+=("$p")
    done
    _phases=("${filtered[@]}")
}

f_webapi_run_scan(){
    local raw_url="$1"
    local target_url domain target_ip phases=() rc=0

    WEBAPI_URL=$(f_webapi_normalize_url "$raw_url")
    target_url="$WEBAPI_URL"
    domain=$(f_webapi_domain_from_url "$target_url")
    WEBAPI_DOMAIN="$domain"

    if [ -n "$WEBAPI_TARGET_IP" ]; then
        target_ip="$WEBAPI_TARGET_IP"
        f_webapi_is_ipv6 "$target_ip" && WEBAPI_TARGET_IS_IPV6=1 || WEBAPI_TARGET_IS_IPV6=0
    else
        target_ip=$(f_webapi_resolve_ip "$domain")
    fi

    if [ -z "$target_ip" ]; then
        echo -e "${RED}[!] Could not resolve $domain to an IP address (IPv4 or IPv6). Use --target-ip.${NC}"
        return 1
    fi

    f_webapi_resolve_tier
    f_webapi_say "${BLUE}[*] Target: $target_url (${target_ip}) tier=${WEBAPI_TIER}${NC}"
    [ "$WEBAPI_TARGET_IS_IPV6" = "1" ] && f_webapi_log "Using IPv6 target address"
    f_webapi_log "Scan start url=$target_url ip=$target_ip tier=$WEBAPI_TIER dry_run=$WEBAPI_DRY_RUN"

    f_webapi_ensure_msf_db
    f_webapi_say "${BLUE}[*] Fingerprinting technologies.${NC}"
    f_webapi_fetch_fingerprint "$target_url"
    f_webapi_detect_technologies "$target_url"
    f_webapi_detect_waf_context "$target_url"
    [ "${WEBAPI_WAF_PRESENT:-0}" = "1" ] && f_webapi_say "${YELLOW}[*] WAF/CDN detected — brute phases skipped${NC}"

    f_webapi_msf_write_resources "$target_url" || return 1
    f_webapi_msf_write_master "$target_url" "$target_ip" "$domain"
    f_webapi_record_technologies "$domain" "$target_url"

    f_webapi_checkpoint_load
    f_webapi_build_phase_plan phases
    f_webapi_filter_checkpoint phases
    f_webapi_write_phase_manifest phases

    if [ ${#phases[@]} -eq 0 ]; then
        f_webapi_say "${YELLOW}[*] All phases already completed (checkpoint).${NC}"
        f_webapi_generate_reports
        f_webapi_cleanup_resources
        return 0
    fi

    f_webapi_msf_run_session "phases" "$domain" "$target_url" || rc=$?

    f_webapi_generate_reports
    f_webapi_cleanup_resources
    return "$rc"
}