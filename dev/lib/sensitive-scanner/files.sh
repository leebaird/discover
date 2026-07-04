# Local file and directory sensitive-data scanning

f_sensitive_filescan_py(){
    printf '%s/lib/sensitive-scanner/filescan.py' "$SENSITIVE_SCANNER_ROOT"
}

f_sensitive_run_external_scanners(){
    local root="$1"
    local ext_out="${OUTPUT_DIR}/sensitive_info/external"
    mkdir -p "$ext_out"

    case "$SENSITIVE_EXTERNAL" in
        none) return 0 ;;
    esac

    if { [ "$SENSITIVE_EXTERNAL" = "auto" ] || [ "$SENSITIVE_EXTERNAL" = "gitleaks" ]; } && \
       command -v gitleaks >/dev/null 2>&1; then
        f_sensitive_say "${BLUE}[*] Running gitleaks on $root.${NC}"
        gitleaks detect --source "$root" --no-git --report-path "$ext_out/gitleaks.json" --exit-code 0 2>/dev/null || true
        if [ -s "$ext_out/gitleaks.json" ] && command -v jq >/dev/null 2>&1; then
            jq -r '.[] | [.RuleID, .File, .StartLine, .Secret] | @tsv' "$ext_out/gitleaks.json" 2>/dev/null | \
            while IFS=$'\t' read -r rule file line secret; do
                [ -n "$file" ] || continue
                f_sensitive_record_finding high "$(f_sensitive_slug "$(basename "$root")")" "${file}:${line:-0}" \
                    "gitleaks_${rule}" "$(f_sensitive_redact "${secret:-$rule}")" "sensitive_info/external/gitleaks.json"
            done
        fi
    fi

    if { [ "$SENSITIVE_EXTERNAL" = "auto" ] || [ "$SENSITIVE_EXTERNAL" = "trufflehog" ]; } && \
       command -v trufflehog >/dev/null 2>&1; then
        f_sensitive_say "${BLUE}[*] Running trufflehog on $root.${NC}"
        trufflehog filesystem "$root" --json --no-update 2>/dev/null > "$ext_out/trufflehog.jsonl" || true
        if [ -s "$ext_out/trufflehog.jsonl" ]; then
            while IFS= read -r row; do
                [ -n "$row" ] || continue
                local detector source line secret
                detector=$(printf '%s' "$row" | jq -r '.DetectorName // .detector_name // "trufflehog"' 2>/dev/null)
                source=$(printf '%s' "$row" | jq -r '.SourceMetadata.Data.Filesystem.file // .path // "unknown"' 2>/dev/null)
                line=$(printf '%s' "$row" | jq -r '.SourceMetadata.Data.Filesystem.line // 0' 2>/dev/null)
                secret=$(printf '%s' "$row" | jq -r '.Raw // .raw // ""' 2>/dev/null)
                f_sensitive_record_finding high "$(f_sensitive_slug "$(basename "$root")")" "${source}:${line}" \
                    "trufflehog_${detector}" "$(f_sensitive_redact "$secret")" "sensitive_info/external/trufflehog.jsonl"
            done < "$ext_out/trufflehog.jsonl"
        fi
    fi
}

f_sensitive_scan_one_root(){
    local SCAN_ROOT="$1"
    local append="${2:-0}"
    local out_override="${3:-}"
    local domain_override="${4:-}"
    local domain py_out hits_file append_flag=()
    domain="${domain_override:-$(f_sensitive_slug "$(basename "$SCAN_ROOT")")}"
    [ "$append" = "1" ] && append_flag=(--append)

    f_sensitive_say "${BLUE}[*] Scanning $SCAN_ROOT for sensitive information.${NC}"
    f_sensitive_log "File scan root: $SCAN_ROOT"

    py_out="${out_override:-${OUTPUT_DIR}/sensitive_info}"
    mkdir -p "$py_out"
    hits_file="${py_out}/hits.jsonl"

    python3 "$(f_sensitive_filescan_py)" \
        --root "$SCAN_ROOT" \
        --output-dir "$py_out" \
        --domain "$domain" \
        --mode "$SENSITIVE_SCAN_MODE" \
        --entropy-min "${SENSITIVE_ENTROPY_MIN:-3.5}" \
        --hits-out "$hits_file" \
        --evidence-prefix "${py_out#"${OUTPUT_DIR}/"}" \
        "${append_flag[@]}" || {
            echo -e "${RED}[!] filescan engine failed for $SCAN_ROOT${NC}"
            return 1
        }

    f_sensitive_import_jsonl "$hits_file"

    if [ -z "$out_override" ]; then
        f_sensitive_run_external_scanners "$SCAN_ROOT"
    fi
}

f_sensitive_scan_files(){
    f_sensitive_should_run_phase files || { f_sensitive_log "Skipping files (checkpoint)"; return 0; }

    local roots=()
    f_sensitive_resolve_scan_roots roots

    if [ ${#roots[@]} -eq 0 ]; then
        echo -e "${RED}[!] No file paths to scan${NC}"
        return 1
    fi

    local root append=0
    for root in "${roots[@]}"; do
        [ -e "$root" ] || continue
        f_sensitive_scan_one_root "$root" "$append"
        append=1
    done

    {
        echo "Sensitive File Scan Summary"
        echo "Generated: $(f_sensitive_now)"
        echo
        f_sensitive_append_summary_section "API Keys" "${OUTPUT_DIR}/sensitive_info/api_keys.txt"
        f_sensitive_append_summary_section "AWS Keys" "${OUTPUT_DIR}/sensitive_info/aws_keys.txt"
        f_sensitive_append_summary_section "Service Tokens" "${OUTPUT_DIR}/sensitive_info/service_tokens.txt"
        f_sensitive_append_summary_section "Google API Keys" "${OUTPUT_DIR}/sensitive_info/google_api_keys.txt"
        f_sensitive_append_summary_section "Private Keys" "${OUTPUT_DIR}/sensitive_info/private_keys.txt"
        f_sensitive_append_summary_section "DB Connections" "${OUTPUT_DIR}/sensitive_info/db_connections.txt"
        f_sensitive_append_summary_section "GCP Credentials" "${OUTPUT_DIR}/sensitive_info/gcp_credentials.txt"
        f_sensitive_append_summary_section "Auth Tokens" "${OUTPUT_DIR}/sensitive_info/auth_tokens.txt"
        f_sensitive_append_summary_section "Framework Secrets" "${OUTPUT_DIR}/sensitive_info/framework_secrets.txt"
        f_sensitive_append_summary_section "Infra Secrets" "${OUTPUT_DIR}/sensitive_info/infra_secrets.txt"
        f_sensitive_append_summary_section "Credit Cards" "${OUTPUT_DIR}/sensitive_info/credit_cards.txt"
        f_sensitive_append_summary_section "SSN" "${OUTPUT_DIR}/sensitive_info/ssn.txt"
        f_sensitive_append_summary_section "TC Kimlik" "${OUTPUT_DIR}/sensitive_info/tc_kimlik.txt"
        f_sensitive_append_summary_section "Emails" "${OUTPUT_DIR}/sensitive_info/emails.txt"
        f_sensitive_append_summary_section "Config Files" "${OUTPUT_DIR}/sensitive_info/config_files.txt"
    } > "${OUTPUT_DIR}/sensitive_info_summary.txt"

    f_sensitive_mark_phase files
    f_sensitive_say "${YELLOW}[*] File scan complete. See sensitive_info_summary.txt${NC}"
}