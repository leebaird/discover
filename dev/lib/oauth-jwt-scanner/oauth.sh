# OAuth/OIDC discovery and live probes

f_oauth_jwt_probe_url(){
    local url="$1" out_body="$2" out_headers="$3"
    local status
    if [ -n "$out_headers" ]; then
        status=$(f_oauth_jwt_curl -D "$out_headers" -o "$out_body" -w "%{http_code}" "$url")
    else
        status=$(f_oauth_jwt_curl -o "$out_body" -w "%{http_code}" "$url")
    fi
    f_oauth_jwt_log "GET $url -> $status"
    echo "$status"
}

f_oauth_jwt_analyze_oidc_metadata(){
    local target="$1" oidc_file="$2"
    local issuer

    [ -f "$oidc_file" ] || return 0
    jq -e '.issuer' "$oidc_file" >/dev/null 2>&1 || return 0

    issuer=$(jq -r '.issuer' "$oidc_file")
    echo "$issuer" > "$OUTPUT_DIR/oauth_test/issuer.txt"

    if printf '%s' "$issuer" | grep -q '^http://'; then
        f_oauth_jwt_record_finding warning oauth "$issuer" insecure_issuer \
            "OIDC issuer uses HTTP" "oauth_test/oidc_config_formatted.json"
    fi

    if ! printf '%s' "$issuer" | grep -q "$(printf '%s' "$target" | sed -E 's#/$##')"; then
        f_oauth_jwt_record_finding info oauth "$issuer" issuer_host_mismatch \
            "Issuer host may not match scan target" "oauth_test/oidc_config_formatted.json"
    fi

    if jq -e '.response_types_supported[]? | select(. == "token")' "$oidc_file" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding warning oauth "$target" implicit_flow_supported \
            "Discovery lists implicit response_type token" "oauth_test/oidc_config_formatted.json"
    fi

    if ! jq -e '.code_challenge_methods_supported[]? | select(. == "S256")' "$oidc_file" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding info oauth "$target" pkce_s256_missing \
            "S256 PKCE not advertised in discovery" "oauth_test/oidc_config_formatted.json"
    fi
}

f_oauth_jwt_fetch_jwks(){
    local jwks_uri="$1"
    local out="$OUTPUT_DIR/oauth_test/jwks.json"
    [ -n "$jwks_uri" ] || return 0

    f_oauth_jwt_probe_url "$jwks_uri" "$out" "" >/dev/null
    jq -e '.keys' "$out" >/dev/null 2>&1 || return 0

    jq . "$out" > "$OUTPUT_DIR/oauth_test/jwks_formatted.json"
    f_oauth_jwt_record_finding info oauth "$jwks_uri" jwks_exposed \
        "JWKS endpoint reachable" "oauth_test/jwks_formatted.json"

    if jq -e '.keys[]? | select(.alg == "none" or .alg == "HS256")' "$out" >/dev/null 2>&1; then
        f_oauth_jwt_record_finding warning oauth "$jwks_uri" jwks_weak_alg \
            "JWKS contains none/HS256 key algorithms" "oauth_test/jwks_formatted.json"
    fi
}

f_oauth_jwt_test_redirect_uri(){
    local auth_endpoint="$1" evil_redirect="$2" label="$3"
    local slug headers body malicious_url status
    local enc_client enc_redirect

    slug=$(f_oauth_jwt_slug "$label")
    headers="$OUTPUT_DIR/oauth_test/redirect_${slug}_headers.txt"
    body="$OUTPUT_DIR/oauth_test/redirect_${slug}_body.txt"
    enc_client=$(f_oauth_jwt_urlencode "$OAUTH_JWT_CLIENT_ID")
    enc_redirect=$(f_oauth_jwt_urlencode "$evil_redirect")
    malicious_url="${auth_endpoint}?client_id=${enc_client}&response_type=code&redirect_uri=${enc_redirect}"

    f_oauth_jwt_probe_url "$malicious_url" "$body" "$headers" >/dev/null

    if f_oauth_jwt_redirect_accepted "$headers" "$body" "$evil_redirect"; then
        f_oauth_jwt_record_finding critical oauth "$auth_endpoint" redirect_uri_bypass \
            "Authorization may accept redirect_uri ($label)" "oauth_test/redirect_${slug}_headers.txt"
        echo "$malicious_url" >> "$OUTPUT_DIR/oauth_test/redirect_uri_hits.txt"
        return 0
    fi
    return 1
}

f_oauth_jwt_test_authorize_flows(){
    local auth_endpoint="$1"
    local base_params client_id redirect_uri

    client_id="$OAUTH_JWT_CLIENT_ID"
    redirect_uri="$OAUTH_JWT_REDIRECT_URI"

    echo -e "${BLUE}[*] Testing redirect_uri validation variants.${NC}"
    f_oauth_jwt_test_redirect_uri "$auth_endpoint" "https://evil-oauth-test.invalid/callback" "evil_host" || true

    if [ "$OAUTH_JWT_SCAN_MODE" = "full" ]; then
        f_oauth_jwt_test_redirect_uri "$auth_endpoint" "${redirect_uri}/../evil" "path_traversal" || true
        f_oauth_jwt_test_redirect_uri "$auth_endpoint" "${redirect_uri}@evil.invalid" "credential_injection" || true
        f_oauth_jwt_test_redirect_uri "$auth_endpoint" "https://evil.invalid.${redirect_uri#https://}" "subdomain_prefix" || true
    fi

    echo -e "${BLUE}[*] Testing state parameter usage.${NC}"
    local no_state_url with_state_url
    local enc_client enc_redirect
    enc_client=$(f_oauth_jwt_urlencode "$client_id")
    enc_redirect=$(f_oauth_jwt_urlencode "$redirect_uri")
    no_state_url="${auth_endpoint}?client_id=${enc_client}&response_type=code&redirect_uri=${enc_redirect}"
    with_state_url="${no_state_url}&state=oauthjwtscan123"

    f_oauth_jwt_probe_url "$no_state_url" "$OUTPUT_DIR/oauth_test/no_state_response.txt" "$OUTPUT_DIR/oauth_test/no_state_headers.txt" >/dev/null
    f_oauth_jwt_probe_url "$with_state_url" "$OUTPUT_DIR/oauth_test/with_state_response.txt" "$OUTPUT_DIR/oauth_test/with_state_headers.txt" >/dev/null

    if f_oauth_jwt_authorize_without_state "$OUTPUT_DIR/oauth_test/no_state_headers.txt" "$OUTPUT_DIR/oauth_test/no_state_response.txt"; then
        f_oauth_jwt_record_finding warning oauth "$auth_endpoint" missing_state \
            "Authorize flow may proceed without state parameter" "oauth_test/no_state_headers.txt"
    fi

    if [ "$OAUTH_JWT_SCAN_MODE" = "full" ]; then
        echo -e "${BLUE}[*] Testing PKCE requirement.${NC}"
        local no_pkce_url="$OUTPUT_DIR/oauth_test/no_pkce_headers.txt"
        local pkce_url="${auth_endpoint}?client_id=${enc_client}&response_type=code&redirect_uri=${enc_redirect}&state=pkce1"
        f_oauth_jwt_probe_url "$pkce_url" "$OUTPUT_DIR/oauth_test/no_pkce_body.txt" "$no_pkce_url" >/dev/null
        if ! grep -qiE 'code_challenge|invalid_request|error=' "$no_pkce_url" 2>/dev/null && \
           f_oauth_jwt_authorize_without_state "$no_pkce_url" "$OUTPUT_DIR/oauth_test/no_pkce_body.txt"; then
            f_oauth_jwt_record_finding warning oauth "$auth_endpoint" pkce_not_required \
                "Authorize request without PKCE may be accepted" "oauth_test/no_pkce_headers.txt"
        fi

        echo -e "${BLUE}[*] Testing implicit response_type.${NC}"
        local implicit_url="${auth_endpoint}?client_id=${enc_client}&response_type=token&redirect_uri=${enc_redirect}&state=implicit1"
        f_oauth_jwt_probe_url "$implicit_url" "$OUTPUT_DIR/oauth_test/implicit_body.txt" "$OUTPUT_DIR/oauth_test/implicit_headers.txt" >/dev/null
        if grep -qiE '^location:.*access_token=' "$OUTPUT_DIR/oauth_test/implicit_headers.txt" 2>/dev/null; then
            f_oauth_jwt_record_finding high oauth "$auth_endpoint" implicit_flow_enabled \
                "Implicit flow may return access_token in redirect" "oauth_test/implicit_headers.txt"
        fi
    fi
}

f_oauth_analyze(){
    local TARGET_URL="$1"
    local OUTPUT_DIR="$2"
    local endpoint url status file_id auth_endpoint oidc_file jwks_uri userinfo

    f_oauth_jwt_should_run_phase oauth || { f_oauth_jwt_log "Skipping oauth (checkpoint)"; return 0; }

    echo -e "${BLUE}[*] Analyzing OAuth configuration for $TARGET_URL.${NC}"
    mkdir -p "$OUTPUT_DIR/oauth_test"
    : > "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt"

    OAUTH_STATIC_ENDPOINTS=(
        "/.well-known/oauth-authorization-server"
        "/.well-known/openid-configuration"
        "/auth/realms/master/protocol/openid-connect/auth"
        "/auth/realms/master/protocol/openid-connect/token"
        "/authorize" "/connect/authorize" "/connect/token"
        "/o/oauth2/auth" "/o/oauth2/token"
        "/oauth/authorize" "/oauth/token"
        "/oauth2/access_token" "/oauth2/authorize" "/oauth2/token"
        "/oauth2/v1/authorize" "/oauth2/v1/token"
        "/oauth2/v2/authorize" "/oauth2/v2/token"
        "/token"
    )

    echo -e "${BLUE}[*] Fetching OIDC discovery.${NC}"
    oidc_file="$OUTPUT_DIR/oauth_test/oidc_config.json"
    f_oauth_jwt_probe_url "${TARGET_URL%/}/.well-known/openid-configuration" "$oidc_file" "" >/dev/null

    if jq -e '.issuer' "$oidc_file" >/dev/null 2>&1; then
        jq . "$oidc_file" > "$OUTPUT_DIR/oauth_test/oidc_config_formatted.json"
        f_oauth_jwt_record_finding info oauth "${TARGET_URL%/}/.well-known/openid-configuration" oidc_discovery \
            "OpenID Connect discovery endpoint exposed" "oauth_test/oidc_config_formatted.json"
        f_oauth_jwt_analyze_oidc_metadata "$TARGET_URL" "$oidc_file"

        auth_endpoint=$(jq -r '.authorization_endpoint // empty' "$oidc_file")
        jwks_uri=$(jq -r '.jwks_uri // empty' "$oidc_file")
        userinfo=$(jq -r '.userinfo_endpoint // empty' "$oidc_file")
        [ -n "$userinfo" ] && [ -z "$OAUTH_JWT_ENDPOINT" ] && OAUTH_JWT_ENDPOINT="$userinfo"

        for ep in authorization_endpoint token_endpoint userinfo_endpoint jwks_uri end_session_endpoint; do
            url=$(jq -r --arg k "$ep" '.[$k] // empty' "$oidc_file")
            [ -z "$url" ] || [ "$url" = "null" ] && continue
            status=$(f_oauth_jwt_probe_url "$url" "$OUTPUT_DIR/oauth_test/discovery_${ep}.txt" "")
            echo "$url ($status)" >> "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt"
        done

        f_oauth_jwt_fetch_jwks "$jwks_uri"
    fi

    echo -e "${BLUE}[*] Probing static OAuth endpoint paths.${NC}"
    for endpoint in "${OAUTH_STATIC_ENDPOINTS[@]}"; do
        url="${TARGET_URL%/}$endpoint"
        file_id=$(f_oauth_jwt_endpoint_file_id "$endpoint")
        status=$(f_oauth_jwt_probe_url "$url" "$OUTPUT_DIR/oauth_test/${file_id}_response.txt" "")
        if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" || "$status" == "403" ]]; then
            echo "$url ($status)" >> "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt"
        fi
    done
    sort -u "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" -o "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt"

    if [ -z "$auth_endpoint" ]; then
        auth_endpoint=$(grep -m1 '/authorize' "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" 2>/dev/null | awk '{print $1}')
        [ -n "$auth_endpoint" ] || auth_endpoint=$(grep -m1 '/auth' "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" 2>/dev/null | awk '{print $1}')
    fi

    if [ -n "$auth_endpoint" ]; then
        echo "$auth_endpoint" > "$OUTPUT_DIR/oauth_test/authorization_endpoint.txt"
        f_oauth_jwt_test_authorize_flows "$auth_endpoint"
    else
        echo -e "${YELLOW}[!] No authorization endpoint identified for live OAuth probes${NC}"
    fi

    {
        echo "OAuth Security Test Report"
        echo "Date: $(f_oauth_jwt_now)"
        echo "Target: $TARGET_URL"
        echo "Authorization endpoint: ${auth_endpoint:-unknown}"
        echo "JWT live endpoint hint: ${OAUTH_JWT_ENDPOINT:-not set}"
        echo
        echo "Discovered endpoints:"
        cat "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" 2>/dev/null || echo "(none)"
    } > "$OUTPUT_DIR/oauth_security_report.txt"

    f_oauth_jwt_mark_phase oauth
    echo -e "${YELLOW}[*] OAuth scan complete. See oauth_security_report.txt${NC}"
}