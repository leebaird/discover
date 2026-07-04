# WAF probing — passive header scan OR wafw00f + supplemental checks

declare -A WAF_HIT_CONF=()
declare -A WAF_HIT_SOURCE=()
declare -A WAF_HIT_MFG=()
declare -A WAF_HIT_LABEL=()
declare -A WAF_HIT_NAME=()
declare -A WAF_HIT_TRIGGER=()
declare -A WAF_LABEL_MAP=()
declare -A WAF_ALIAS_TO_WAFW00F=()

WAF_HITS_JSONL=""
WAF_CHECKPOINT_FILE=""

WAF_BEHAVIORAL_CORROBORATION_RE='x-waf|x-web-application-firewall|x-protected-by|x-sucuri|incapsula|mod_security|modsecurity|cf-ray|akamai|imperva|barra_counter|f5-|fortiweb|ddos-guard|reblaze|wallarm|sucuri|cloudflare'

f_waf_curl_opts(){
    WAF_CURL_OPTS=(-s --connect-timeout 10 --max-time 20)
    [ "$WAF_NO_REDIRECT" != "1" ] && WAF_CURL_OPTS+=(-L)
    [ "$WAF_INSECURE" = "1" ] && WAF_CURL_OPTS+=(-k)
    [ -n "$WAF_PROXY" ] && WAF_CURL_OPTS+=(--proxy "$WAF_PROXY")
}

f_waf_reset_hits(){
    WAF_HIT_CONF=()
    WAF_HIT_SOURCE=()
    WAF_HIT_MFG=()
    WAF_HIT_LABEL=()
    WAF_HIT_NAME=()
    WAF_HIT_TRIGGER=()
}

f_waf_load_labels(){
    local label_file="${WAF_DETECT_ROOT}/data/waf-labels.tsv"
    WAF_LABEL_MAP=()
    while IFS=$'\t' read -r name ltype; do
        [[ "$name" =~ ^# ]] && continue
        [ -n "$name" ] && [ -n "$ltype" ] || continue
        WAF_LABEL_MAP["$name"]="$ltype"
    done < "$label_file"
}

f_waf_label_for(){
    local name="$1"
    printf '%s' "${WAF_LABEL_MAP[$name]:-waf}"
}

f_waf_load_aliases(){
    local alias_file="${WAF_DETECT_ROOT}/data/waf-aliases.tsv"
    WAF_ALIAS_TO_WAFW00F=()
    while IFS=$'\t' read -r w00f sig; do
        [[ "$w00f" =~ ^# ]] && continue
        [ -n "$w00f" ] && [ -n "$sig" ] || continue
        WAF_ALIAS_TO_WAFW00F["$sig"]="$w00f"
    done < "$alias_file"
}

f_waf_canonical_name(){
    local name="$1"
    local canonical="${WAF_ALIAS_TO_WAFW00F[$name]:-$name}"
    canonical="${canonical%% (Cloudflare Inc.)}"
    canonical="${canonical%% (F5 Networks)}"
    canonical="${canonical%% (Barracuda Networks)}"
    printf '%s' "$canonical"
}

f_waf_name_key(){
    f_waf_canonical_name "$1" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '_'
}

f_waf_hit_rank(){
    case "$1" in
        high) echo 3 ;;
        medium) echo 2 ;;
        low) echo 1 ;;
        *) echo 0 ;;
    esac
}

f_waf_add_hit(){
    local name="$1" confidence="$2" source="$3" manufacturer="${4:-}" label="${5:-}" trigger_url="${6:-}"
    local canonical key existing_rank new_rank
    canonical=$(f_waf_canonical_name "$name")
    key=$(f_waf_name_key "$canonical")
    [ -n "$key" ] || return 0
    [ "$canonical" = "None" ] && return 0
    [ "$canonical" = "WAF Header Indicator" ] && return 0

    new_rank=$(f_waf_hit_rank "$confidence")
    existing_rank=$(f_waf_hit_rank "${WAF_HIT_CONF[$key]:-}")

    if [ -n "${WAF_HIT_CONF[$key]:-}" ] && [ "$new_rank" -le "$existing_rank" ]; then
        return 0
    fi

    WAF_HIT_CONF[$key]="$confidence"
    WAF_HIT_SOURCE[$key]="$source"
    WAF_HIT_MFG[$key]="${manufacturer:-}"
    WAF_HIT_LABEL[$key]="${label:-$(f_waf_label_for "$canonical")}"
    WAF_HIT_NAME[$key]="$canonical"
    WAF_HIT_TRIGGER[$key]="${trigger_url:-}"
}

f_waf_has_confident_hit(){
    local key
    for key in "${!WAF_HIT_CONF[@]}"; do
        [ "${WAF_HIT_CONF[$key]}" = "high" ] || [ "${WAF_HIT_CONF[$key]}" = "medium" ] && return 0
    done
    return 1
}

f_waf_hit_is_reportable(){
    local key="$1"
    local conf="${WAF_HIT_CONF[$key]}"
    local label="${WAF_HIT_LABEL[$key]}"
    local name="${WAF_HIT_NAME[$key]}"

    [ "$conf" = "low" ] && [ "$name" = "Unknown WAF (behavioral)" ] && return 1
    if [ "$WAF_WAF_ONLY" = "1" ]; then
        [ "$label" = "cdn" ] && return 1
        [ "$conf" = "low" ] && return 1
    fi
    return 0
}

f_waf_has_reportable_hit(){
    local key
    for key in "${!WAF_HIT_CONF[@]}"; do
        f_waf_hit_is_reportable "$key" && return 0
    done
    return 1
}

f_waf_should_run_supplemental(){
    case "$WAF_SUPPLEMENTAL" in
        never) return 1 ;;
        always) return 0 ;;
        *)
            f_waf_has_confident_hit && return 1
            return 0
            ;;
    esac
}

f_waf_should_run_signatures(){
    [ "$WAF_SUPPLEMENTAL" = "always" ] && return 0
    [ "$WAF_SUPPLEMENTAL" = "never" ] && return 1
    f_waf_has_confident_hit && return 1
    return 0
}

f_waf_should_run_wafw00f(){
    [ "$WAF_PASSIVE" = "1" ] && return 1
    [ "$WAF_USE_WAFW00F" = "none" ] && return 1
    command -v wafw00f >/dev/null 2>&1 || return 1
    return 0
}

f_waf_urls_to_try(){
    local raw="$1"
    local -n _out=$2
    _out=()
    raw="${raw// /}"
    if [[ "$raw" =~ ^https:// ]]; then
        _out+=("$raw")
    elif [[ "$raw" =~ ^http:// ]]; then
        _out+=("$raw")
    else
        _out+=("https://${raw}")
        _out+=("http://${raw}")
    fi
}

f_waf_trigger_has_waf_headers(){
    local headers_file="$1"
    grep -qiE "$WAF_BEHAVIORAL_CORROBORATION_RE" "$headers_file" 2>/dev/null
}

f_waf_headers_delta_suggests_waf(){
    local normal_file="$1" trigger_file="$2"
    if f_waf_trigger_has_waf_headers "$trigger_file" && ! f_waf_trigger_has_waf_headers "$normal_file"; then
        return 0
    fi
    local n_lines t_lines
    n_lines=$(wc -l < "$normal_file" 2>/dev/null || echo 0)
    t_lines=$(wc -l < "$trigger_file" 2>/dev/null || echo 0)
    [ "$t_lines" -gt "$n_lines" ] && return 0
    return 1
}

f_waf_run_wafw00f(){
    local target="$1"
    local domain="$2"
    local out_json="${OUTPUT_DIR}/waf_engine/$(f_waf_slug "$domain").json"
    local rc=0 runner args=()

    f_waf_should_run_wafw00f || return 1

    runner="${WAF_DETECT_ROOT}/lib/waf-detect/wafw00f_run.py"
    if [ ! -f "$runner" ]; then
        runner="wafw00f"
        args=("$target" -a -o "$out_json" -f json)
        [ "$WAF_NO_REDIRECT" = "1" ] && args+=(-r)
        [ -n "$WAF_PROXY" ] && args+=(-p "$WAF_PROXY")
    else
        args=(python3 "$runner" "$target" -o "$out_json" -a)
        [ "$WAF_INSECURE" = "1" ] && args+=(--insecure)
        [ "$WAF_NO_REDIRECT" = "1" ] && args+=(--no-redirect)
        [ -n "$WAF_PROXY" ] && args+=(--proxy "$WAF_PROXY")
    fi

    f_waf_say "${BLUE}[*] Running wafw00f on $target${NC}"
    "${args[@]}" >> "$WAF_SCAN_LOG" 2>&1 || rc=$?

    [ -s "$out_json" ] || return "$rc"

    local row fw mfg trig
    while IFS= read -r row; do
        [ -n "$row" ] || continue
        fw=$(printf '%s' "$row" | jq -r '.firewall // empty')
        mfg=$(printf '%s' "$row" | jq -r '.manufacturer // empty')
        trig=$(printf '%s' "$row" | jq -r '.trigger_url // empty')
        [ -n "$fw" ] && [ "$fw" != "None" ] || continue
        f_waf_add_hit "$fw" high wafw00f "$mfg" "$(f_waf_label_for "$(f_waf_canonical_name "$fw")")" "$trig"
    done < <(jq -c '.[] | select(.detected==true)' "$out_json" 2>/dev/null)

    return 0
}

f_waf_passive_probe(){
    local target="$1"
    local domain="$2"
    local work="${OUTPUT_DIR}/waf_engine/$(f_waf_slug "$domain")"
    mkdir -p "$work"
    local headers_file body_file
    headers_file=$(mktemp "${work}/headers.XXXXXX")
    body_file=$(mktemp "${work}/body.XXXXXX")

    f_waf_curl_opts
    local ua="Mozilla/5.0 (compatible; DiscoverWAFDetect/2.0; passive)"
    local curl_rc=0

    curl "${WAF_CURL_OPTS[@]}" -A "$ua" -o "$body_file" -D "$headers_file" "$target" >/dev/null 2>&1 || curl_rc=$?

    if [ "$curl_rc" -ne 0 ] || [ ! -s "$headers_file" ]; then
        rm -f "$headers_file" "$body_file"
        return 2
    fi

    local sig_file="${WAF_DETECT_ROOT}/data/waf-signatures.tsv"
    while IFS=$'\t' read -r name header_rx body_rx; do
        [[ "$name" =~ ^# ]] && continue
        [ -n "$name" ] && [ -n "$header_rx" ] || continue
        [ "$name" = "WAF Header Indicator" ] && continue
        local matched=0
        if grep -qiE "$header_rx" "$headers_file" 2>/dev/null; then
            matched=1
        elif [ -n "${body_rx:-}" ] && grep -qiE "$body_rx" "$body_file" 2>/dev/null; then
            matched=1
        fi
        if [ "$matched" = "1" ]; then
            f_waf_add_hit "$name" medium passive_signature "" "$(f_waf_label_for "$(f_waf_canonical_name "$name")")" ""
        fi
    done < "$sig_file"

    rm -f "$headers_file" "$body_file"
    return 0
}

f_waf_supplemental_probe(){
    local target="$1"
    local domain="$2"

    local work="${OUTPUT_DIR}/waf_engine/$(f_waf_slug "$domain")"
    mkdir -p "$work"
    local headers_file body_file trigger_headers
    headers_file=$(mktemp "${work}/headers.XXXXXX")
    body_file=$(mktemp "${work}/body.XXXXXX")
    trigger_headers=$(mktemp "${work}/trigger.XXXXXX")

    f_waf_curl_opts
    local ua="Mozilla/5.0 (compatible; DiscoverWAFDetect/2.0)"
    local curl_rc=0 run_sigs=0 run_behavioral=0

    f_waf_should_run_signatures && run_sigs=1
    if [ "$WAF_PASSIVE" != "1" ] && ! f_waf_has_confident_hit; then
        run_behavioral=1
    fi
    [ "$run_sigs" = "0" ] && [ "$run_behavioral" = "0" ] && {
        rm -f "$headers_file" "$body_file" "$trigger_headers"
        return 0
    }

    curl "${WAF_CURL_OPTS[@]}" -A "$ua" -o "$body_file" -D "$headers_file" \
        -H "X-Forwarded-For: 127.0.0.1" "$target" >/dev/null 2>&1 || curl_rc=$?

    if [ "$curl_rc" -ne 0 ] || [ ! -s "$headers_file" ]; then
        rm -f "$headers_file" "$body_file" "$trigger_headers"
        return 2
    fi

    local sig_file="${WAF_DETECT_ROOT}/data/waf-signatures.tsv"
    local combined="${work}/headers_combined.txt"
    cp "$headers_file" "$combined"

    if [ "$run_behavioral" = "1" ]; then
        local trigger_url="${target%/}/?id=1'%20OR%20'1'%3D'1'%20--%20"
        curl "${WAF_CURL_OPTS[@]}" -A "$ua" -o /dev/null -D "$trigger_headers" \
            -H "X-Forwarded-For: 127.0.0.1" "$trigger_url" >/dev/null 2>&1 || true
        cat "$trigger_headers" >> "$combined"
    fi

    if [ "$run_sigs" = "1" ]; then
        while IFS=$'\t' read -r name header_rx body_rx; do
            [[ "$name" =~ ^# ]] && continue
            [ -n "$name" ] && [ -n "$header_rx" ] || continue
            [ "$name" = "WAF Header Indicator" ] && continue
            local matched=0
            if grep -qiE "$header_rx" "$combined" 2>/dev/null; then
                matched=1
            elif [ -n "${body_rx:-}" ] && grep -qiE "$body_rx" "$body_file" 2>/dev/null; then
                matched=1
            fi
            if [ "$matched" = "1" ]; then
                f_waf_add_hit "$name" medium signature "" "$(f_waf_label_for "$(f_waf_canonical_name "$name")")" ""
            fi
        done < "$sig_file"
    fi

    if [ "$run_behavioral" = "1" ] && [ -s "$trigger_headers" ]; then
        local normal_status trigger_status
        normal_status=$(grep -E '^HTTP/[0-9]\.[0-9] [0-9]{3}' "$headers_file" | tail -1 | awk '{print $2}')
        trigger_status=$(grep -E '^HTTP/[0-9]\.[0-9] [0-9]{3}' "$trigger_headers" | tail -1 | awk '{print $2}')
        [[ "$normal_status" =~ ^403 ]] && normal_status=""
        if [[ "$trigger_status" =~ ^(403|406|429)$ ]] && [[ "$normal_status" =~ ^(200|301|302|307|308)$ ]]; then
            if f_waf_trigger_has_waf_headers "$trigger_headers" && \
               f_waf_headers_delta_suggests_waf "$headers_file" "$trigger_headers" && \
               ! f_waf_has_confident_hit; then
                f_waf_add_hit "Unknown WAF (behavioral)" low behavioral "" "waf" "$trigger_url"
            fi
        fi
    fi

    rm -f "$headers_file" "$body_file" "$trigger_headers"
    return 0
}

f_waf_append_structured_hit(){
    local domain="$1" target="$2" key="$3"
    local lockfile="${OUTPUT_DIR}/.hits.lock"
    (
        flock -x 9
        jq -n \
            --arg target "$target" \
            --arg domain "$domain" \
            --arg vendor "${WAF_HIT_NAME[$key]}" \
            --arg confidence "${WAF_HIT_CONF[$key]}" \
            --arg source "${WAF_HIT_SOURCE[$key]}" \
            --arg type "${WAF_HIT_LABEL[$key]}" \
            --arg manufacturer "${WAF_HIT_MFG[$key]}" \
            --arg trigger_url "${WAF_HIT_TRIGGER[$key]}" \
            --arg url "$target" \
            '{target:$target,domain:$domain,vendor:$vendor,confidence:$confidence,source:$source,type:$type,manufacturer:$manufacturer,trigger_url:$trigger_url,matched_url:$url}' \
            >> "$WAF_HITS_JSONL"
    ) 9>"$lockfile"
}

f_waf_record_consolidated_findings(){
    local domain="$1" target="$2"
    local key canonical conf source mfg label trig detail sev

    for key in "${!WAF_HIT_CONF[@]}"; do
        canonical="${WAF_HIT_NAME[$key]}"
        conf="${WAF_HIT_CONF[$key]}"
        source="${WAF_HIT_SOURCE[$key]}"
        mfg="${WAF_HIT_MFG[$key]}"
        label="${WAF_HIT_LABEL[$key]}"
        trig="${WAF_HIT_TRIGGER[$key]}"
        detail="${canonical} | confidence=${conf} source=${source} type=${label}"
        [ -n "$mfg" ] && [ "$mfg" != "None" ] && detail="${detail} manufacturer=${mfg}"
        [ -n "$trig" ] && [ "$trig" != "null" ] && detail="${detail} trigger_url=${trig}"

        sev=info
        if [ "$label" = "cdn" ] && [ "$WAF_WAF_ONLY" = "1" ]; then
            f_waf_record_finding info "$domain" "$target" cdn_present "$detail" "waf_results.tsv"
            continue
        fi
        if ! f_waf_hit_is_reportable "$key"; then
            continue
        fi
        if [ "$conf" = "low" ]; then
            f_waf_record_finding info "$domain" "$target" waf_possible "$detail" "waf_results.tsv"
            continue
        fi
        f_waf_record_finding "$sev" "$domain" "$target" waf_identified "$detail" "waf_results.tsv"
        f_waf_append_structured_hit "$domain" "$target" "$key"
    done
}

f_waf_reportable_names(){
    local -n _out=$1
    _out=()
    local key
    for key in "${!WAF_HIT_NAME[@]}"; do
        f_waf_hit_is_reportable "$key" && _out+=("${WAF_HIT_NAME[$key]}")
    done
}

f_waf_checkpoint_load(){
    WAF_CHECKPOINT_DONE=()
    [ -f "$WAF_CHECKPOINT_FILE" ] || return 0
    while IFS= read -r line; do
        [ -n "$line" ] && WAF_CHECKPOINT_DONE+=("$line")
    done < <(jq -r '.completed[]? // empty' "$WAF_CHECKPOINT_FILE" 2>/dev/null)
}

f_waf_checkpoint_is_done(){
    local target="$1"
    local t
    for t in "${WAF_CHECKPOINT_DONE[@]}"; do
        [ "$t" = "$target" ] && return 0
    done
    return 1
}

f_waf_checkpoint_mark(){
    local target="$1"
    WAF_CHECKPOINT_DONE+=("$target")
    jq -n --arg now "$(f_waf_now)" --argjson completed "$(printf '%s\n' "${WAF_CHECKPOINT_DONE[@]}" | jq -R -s 'split("\n")|map(select(length>0))')" \
        '{updated:$now,completed:$completed}' > "$WAF_CHECKPOINT_FILE"
}

f_waf_probe_single_url(){
    local target="$1"
    local domain="$2"
    local sup_rc=0

    if f_waf_should_run_wafw00f; then
        f_waf_run_wafw00f "$target" "$domain" || true
    fi

    if [ "$WAF_PASSIVE" = "1" ]; then
        f_waf_passive_probe "$target" "$domain" || sup_rc=$?
    elif f_waf_should_run_supplemental; then
        f_waf_supplemental_probe "$target" "$domain" || sup_rc=$?
    else
        f_waf_log "Skipping supplemental probes"
    fi

    return "$sup_rc"
}

f_waf_detect_one(){
    local raw_target="$1"
    local domain names=() joined detected="No" status="ok"
    local urls=() url sup_rc=0

    f_waf_reset_hits
    f_waf_load_labels
    f_waf_load_aliases

    f_waf_urls_to_try "$raw_target" urls
    domain=$(f_waf_domain_from_url "${urls[0]}")

    f_waf_say "${BLUE}[*] Testing target: $raw_target${NC}"
    f_waf_log "Probing raw=$raw_target passive=$WAF_PASSIVE supplemental=$WAF_SUPPLEMENTAL"

    local matched_url="" url_idx=0
    for url in "${urls[@]}"; do
        url_idx=$((url_idx + 1))
        f_waf_say "${BLUE}[*] URL: $url${NC}"
        sup_rc=0
        f_waf_probe_single_url "$url" "$domain" || sup_rc=$?
        matched_url="$url"
        if [ "$sup_rc" = "2" ]; then
            [ "$url_idx" -lt ${#urls[@]} ] && f_waf_reset_hits && f_waf_load_labels && f_waf_load_aliases
            continue
        fi
        if f_waf_has_reportable_hit; then
            break
        fi
        if [ "$url_idx" -lt ${#urls[@]} ]; then
            f_waf_log "No reportable WAF on $url; trying alternate scheme"
            f_waf_reset_hits
            f_waf_load_labels
            f_waf_load_aliases
        fi
    done

    if [ "$sup_rc" = "2" ] && ! f_waf_has_reportable_hit; then
        f_waf_say "${RED}[!] Probe failed for $raw_target (connection/DNS/TLS error)${NC}"
        f_waf_record_finding high "$domain" "${matched_url:-${urls[0]}}" probe_error \
            "Could not complete HTTP probe" "waf_results.tsv"
        f_waf_append_result_row "${matched_url:-${urls[0]}}" "Error" "-" "probe_error"
        return 1
    fi

    [ -z "$matched_url" ] && matched_url="${urls[0]}"
    f_waf_reportable_names names

    if [ ${#names[@]} -gt 0 ]; then
        detected="Yes"
        joined=$(printf '%s; ' "${names[@]}")
        joined=${joined%; }
        f_waf_say "${GREEN}[+] WAF detected: $joined${NC}"
        f_waf_record_consolidated_findings "$domain" "$matched_url"
    else
        if f_waf_has_confident_hit || [ ${#WAF_HIT_NAME[@]} -gt 0 ]; then
            f_waf_say "${YELLOW}[*] CDN/signals only (omit --waf-only for full list)${NC}"
            f_waf_record_consolidated_findings "$domain" "$matched_url"
        else
            f_waf_say "${YELLOW}[-] No WAF detected for $raw_target${NC}"
        fi
        joined="-"
    fi

    f_waf_append_result_row "$matched_url" "$detected" "$joined" "$status"
    f_waf_checkpoint_mark "$raw_target"
    return 0
}

f_waf_run_scan(){
    local targets=()
    f_waf_load_targets targets "$WAF_FILE"

    if [ ${#targets[@]} -eq 0 ]; then
        echo -e "${RED}[!] No targets to scan (--url or --file required)${NC}"
        return 1
    fi

    if [ "${WAF_MAX_TARGETS:-0}" -gt 0 ] && [ ${#targets[@]} -gt "$WAF_MAX_TARGETS" ]; then
        targets=("${targets[@]:0:$WAF_MAX_TARGETS}")
        f_waf_log "Capped targets to $WAF_MAX_TARGETS"
    fi

    WAF_HITS_JSONL="${OUTPUT_DIR}/waf_engine/hits.jsonl"
    : > "$WAF_HITS_JSONL"
    WAF_CHECKPOINT_FILE="${OUTPUT_DIR}/waf_engine/checkpoint.json"
    f_waf_checkpoint_load

    local filtered=() t
    for t in "${targets[@]}"; do
        f_waf_checkpoint_is_done "$t" && { f_waf_log "Skip checkpoint: $t"; continue; }
        filtered+=("$t")
    done
    targets=("${filtered[@]}")

    local i=0 total=${#targets[@]} rc=0 workers="${WAF_WORKERS:-1}"

    if [ "$total" -eq 0 ]; then
        f_waf_say "${YELLOW}[*] All targets already in checkpoint${NC}"
        f_waf_generate_reports
        return 0
    fi

    if [ "$workers" -gt 1 ]; then
        f_waf_say "${YELLOW}[*] Running with $workers workers${NC}"
        local running=0
        for t in "${targets[@]}"; do
            while [ "$(jobs -rp | wc -l)" -ge "$workers" ]; do
                sleep 0.3
            done
            i=$((i + 1))
            f_waf_say "${YELLOW}[$i/$total]${NC} $t"
            ( f_waf_detect_one "$t" ) &
            if [ "$WAF_DELAY" != "0" ] && [ "${WAF_DELAY:-0}" -gt 0 ] 2>/dev/null; then
                sleep "$WAF_DELAY"
            fi
        done
        wait || rc=1
    else
        for t in "${targets[@]}"; do
            i=$((i + 1))
            f_waf_say "${YELLOW}[$i/$total]${NC} $t"
            f_waf_detect_one "$t" || rc=1
            if [ "$WAF_DELAY" != "0" ] && [ "${WAF_DELAY:-0}" -gt 0 ] 2>/dev/null; then
                sleep "$WAF_DELAY"
            fi
        done
    fi

    f_waf_generate_reports
    return "$rc"
}

# shellcheck disable=SC2034
declare -a WAF_CHECKPOINT_DONE=()