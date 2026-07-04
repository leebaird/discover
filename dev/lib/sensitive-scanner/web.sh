# Web URL sensitive information probing (Python engine)

f_sensitive_web_engine_py(){
    printf '%s/lib/sensitive-scanner/engine.py' "$SENSITIVE_SCANNER_ROOT"
}

f_sensitive_build_web_paths_file(){
    local dest="$1"
    if [ -n "$SENSITIVE_WORDLIST" ] && [ -f "$SENSITIVE_WORDLIST" ]; then
        cp "$SENSITIVE_WORDLIST" "$dest"
        return 0
    fi
    if [ "$SENSITIVE_SCAN_MODE" = "quick" ]; then
        cp "${SENSITIVE_SCANNER_ROOT}/data/sensitive-web-paths-quick.txt" "$dest"
    else
        cp "${SENSITIVE_SCANNER_ROOT}/data/sensitive-web-paths-full.txt" "$dest"
    fi
}

f_sensitive_shred_web_content(){
    [ "$SENSITIVE_SHRED_CONTENT" = "1" ] || return 0
    find "${OUTPUT_DIR}/web_sensitive" -type f \( -name 'content_*.txt' -o -name 'index.html' \) -delete 2>/dev/null || true
    rm -rf "${OUTPUT_DIR}/web_sensitive/deep_scan" 2>/dev/null || true
    f_sensitive_log "Shredded stored web response content"
}

f_sensitive_scan_web(){
    local TARGET_URL="$1"
    local engine_args=()

    f_sensitive_should_run_phase web || { f_sensitive_log "Skipping web (checkpoint)"; return 0; }

    TARGET_URL=$(f_sensitive_normalize_url "$TARGET_URL")
    local out="${OUTPUT_DIR}/web_sensitive"
    mkdir -p "$out"

    f_sensitive_say "${BLUE}[*] Scanning $TARGET_URL for exposed sensitive information.${NC}"
    f_sensitive_log "Web scan target: $TARGET_URL"

    f_sensitive_build_web_paths_file "$out/paths_to_check.txt"

    engine_args=(
        python3 "$(f_sensitive_web_engine_py)"
        --url "$TARGET_URL"
        --output-dir "$out"
        --mode "$SENSITIVE_SCAN_MODE"
        --workers "${SENSITIVE_WORKERS:-10}"
        --delay "${SENSITIVE_DELAY:-0}"
        --rps "${SENSITIVE_RPS:-0}"
        --max-paths "${SENSITIVE_MAX_PATHS:-0}"
    )
    [ -n "$SENSITIVE_WORDLIST" ] && [ -f "$SENSITIVE_WORDLIST" ] && \
        engine_args+=(--wordlist "$SENSITIVE_WORDLIST")
    [ -n "$SENSITIVE_SCAN_DIR" ] && [ -d "$SENSITIVE_SCAN_DIR" ] && \
        engine_args+=(--scan-dir "$SENSITIVE_SCAN_DIR")
    [ "$SENSITIVE_INSECURE" = "1" ] && engine_args+=(--insecure)
    [ -n "$SENSITIVE_BEARER_TOKEN" ] && engine_args+=(--bearer-token "$SENSITIVE_BEARER_TOKEN")
    [ "$SENSITIVE_NO_STORE_CONTENT" = "1" ] && engine_args+=(--no-store-content)
    [ "$SENSITIVE_SHRED_CONTENT" = "1" ] && engine_args+=(--shred-content)
    [ -n "$SENSITIVE_RESUME_DIR" ] && engine_args+=(--resume)

    "${engine_args[@]}" || {
        echo -e "${RED}[!] Web engine failed${NC}"
        return 1
    }

    f_sensitive_import_jsonl "${out}/engine/findings.jsonl"

    {
        echo "Web Sensitive Information Report"
        echo "Generated: $(f_sensitive_now)"
        echo "Target: $TARGET_URL"
        echo
        f_sensitive_append_summary_section "robots.txt paths" "$out/sensitive_paths.txt"
        f_sensitive_append_summary_section "Found URLs" "$out/found_paths.txt"
        f_sensitive_append_summary_section "Sensitive content URLs" "$out/sensitive_data_files.txt"
        f_sensitive_append_summary_section "HTTP headers" "$out/http_headers.txt" 5
        f_sensitive_append_summary_section "Emails" "$out/emails.txt"
    } > "${OUTPUT_DIR}/web_sensitive_summary.txt"

    f_sensitive_shred_web_content
    f_sensitive_mark_phase web
    f_sensitive_say "${YELLOW}[*] Web scan complete. See web_sensitive_summary.txt${NC}"
}