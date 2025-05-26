#!/usr/bin/env bash

# by ibrahimsql - OAuth/JWT Security Scanner
# Discover framework compatibility module

clear
f_banner

# Global variables
DATESTAMP=$(date +%F)
TIMESTAMP=$(date +%T)

# Function to terminate script
f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

# Function to analyze OAuth configuration
f_oauth_analyze() {
    local TARGET_URL=$1
    local OUTPUT_DIR=$2

    echo -e "${BLUE}[*] Analyzing OAuth configuration for $TARGET_URL.${NC}"
    echo

    # Create output directory
    mkdir -p "$OUTPUT_DIR/oauth_test"

    # Check common OAuth endpoints
    echo -e "${BLUE}[*] Checking for common OAuth endpoints.${NC}"

    OAUTH_ENDPOINTS=(
        "/.well-known/oauth-authorization-server"
        "/.well-known/openid-configuration"
        "/auth/realms/master/protocol/openid-connect/auth"
        "/auth/realms/master/protocol/openid-connect/token"
        "/authorize"
        "/connect/authorize"
        "/connect/token"
        "/o/oauth2/auth"
        "/o/oauth2/token"
        "/oauth/authorize"
        "/oauth/token"
        "/oauth2/access_token"
        "/oauth2/authorize"
        "/oauth2/token"
        "/oauth2/v1/authorize"
        "/oauth2/v1/token"
        "/oauth2/v2/authorize"
        "/oauth2/v2/token"
        "/token"
    )

    for endpoint in "${OAUTH_ENDPOINTS[@]}"; do
        url="${TARGET_URL%/}$endpoint"
        status=$(curl -s -o "$OUTPUT_DIR/oauth_test/${endpoint##*/}_response.txt" -w "%{http_code}" "$url")
        
        if [[ "$status" == "200" || "$status" == "302" || "$status" == "401" || "$status" == "403" ]]; then
            echo "$url ($status)" >> "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt"
        fi
    done

    # Check for OIDC discovery endpoints
    echo -e "${BLUE}[*] Checking OpenID Connect discovery endpoints.${NC}"
    curl -s "${TARGET_URL%/}/.well-known/openid-configuration" > "$OUTPUT_DIR/oauth_test/oidc_config.json"

    if grep -q "issuer" "$OUTPUT_DIR/oauth_test/oidc_config.json"; then
        echo -e "${YELLOW}[!] OpenID Connect discovery endpoint exposed${NC}"
        jq . "$OUTPUT_DIR/oauth_test/oidc_config.json" > "$OUTPUT_DIR/oauth_test/oidc_config_formatted.json"
    fi

    # Test for common OAuth vulnerabilities
    echo -e "${BLUE}[*] Testing for OAuth security misconfigurations.${NC}"

    # Test 1: Check for redirect_uri validation issues
    if [ -f "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" ]; then
        AUTH_ENDPOINT=$(grep -m 1 "/authorize" "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" | cut -d ' ' -f1)

        if [ -n "$AUTH_ENDPOINT" ]; then
            echo -e "${BLUE}[*] Testing redirect_uri validation.${NC}"
            malicious_redirect="${AUTH_ENDPOINT}?client_id=client_id&response_type=token&redirect_uri=https://evil.com"

            status=$(curl -s -o /dev/null -w "%{http_code}" "$malicious_redirect")

            if [[ "$status" == "200" || "$status" == "302" ]]; then
                echo -e "${RED}[!] CRITICAL: Possible redirect_uri validation issue. Application accepts arbitrary redirect_uri: $malicious_redirect${NC}"
                echo "CRITICAL: redirect_uri validation issue detected" >> "$OUTPUT_DIR/oauth_test/vulnerabilities.txt"
                echo "$malicious_redirect" >> "$OUTPUT_DIR/oauth_test/vulnerabilities.txt"
            fi
        fi
    fi

    # Test 2: Check for state parameter issues
    if [ -f "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" ]; then
        AUTH_ENDPOINT=$(grep -m 1 "/authorize" "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" | cut -d ' ' -f1)

        if [ -n "$AUTH_ENDPOINT" ]; then
            echo -e "${BLUE}[*] Testing state parameter usage.${NC}"
            no_state_url="${AUTH_ENDPOINT}?client_id=client_id&response_type=code&redirect_uri=https://target.com/callback"

            curl -s -o "$OUTPUT_DIR/oauth_test/no_state_response.txt" "$no_state_url"

            if ! grep -q "state" "$OUTPUT_DIR/oauth_test/no_state_response.txt"; then
                echo -e "${RED}[!] WARNING: State parameter may not be required. This could lead to CSRF vulnerabilities.${NC}"
                echo "WARNING: State parameter may not be enforced" >> "$OUTPUT_DIR/oauth_test/vulnerabilities.txt"
            fi
        fi
    fi

    # Generate summary report
    echo -e "${BLUE}[*] Generating OAuth security report.${NC}"
    {
        echo "OAuth Security Test Report"
        echo "=========================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo "Target: $TARGET_URL"
        echo

        echo "1. Discovered OAuth Endpoints"
        echo "----------------------------"

        if [ -f "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt" ]; then
            cat "$OUTPUT_DIR/oauth_test/found_oauth_endpoints.txt"
        else
            echo "No OAuth endpoints discovered"
        fi

        echo
        echo "2. OpenID Connect Configuration"
        echo "-------------------------------"

        if [ -f "$OUTPUT_DIR/oauth_test/oidc_config_formatted.json" ]; then
            echo "OpenID Connect discovery endpoint is exposed at: ${TARGET_URL%/}/.well-known/openid-configuration"
            echo
            echo "Key configuration settings:"
            jq -r 'keys[] as $k | "\($k): \(.[$k])"' "$OUTPUT_DIR/oauth_test/oidc_config_formatted.json" | grep -E "(authorization_endpoint|grant_types_supported|issuer|jwks_uri|response_types_supported|token_endpoint|userinfo_endpoint)"
        else
            echo "No OpenID Connect discovery configuration found"
        fi

        echo
        echo "3. Security Issues"
        echo "-----------------"

        if [ -f "$OUTPUT_DIR/oauth_test/vulnerabilities.txt" ]; then
            cat "$OUTPUT_DIR/oauth_test/vulnerabilities.txt"
        else
            echo "No obvious OAuth security issues detected"
            echo
            echo "Note: This is a basic test. A comprehensive OAuth security assessment would require"
            echo "manual testing and analysis of the application's specific implementation."
        fi
    } > "$OUTPUT_DIR/oauth_security_report.txt"
    
    echo -e "${YELLOW}[*] OAuth security test complete. Results saved to $OUTPUT_DIR/oauth_security_report.txt${NC}"
}

###############################################################################################################################

# Function to perform JWT security tests
f_jwt_security() {
    local JWT=$1
    local OUTPUT_DIR=$2

    echo -e "${BLUE}[*] Running JWT security tests.${NC}"
    echo

    # Create output directory
    mkdir -p "$OUTPUT_DIR/jwt_test"

    # Split JWT into header, payload, and signature
    HEADER=$(echo "$JWT" | cut -d '.' -f1)
    PAYLOAD=$(echo "$JWT" | cut -d '.' -f2)
    SIGNATURE=$(echo "$JWT" | cut -d '.' -f3)

    # Decode header and payload
    echo -e "${BLUE}[*] Decoding header.${NC}"
    echo "$HEADER" | base64 -d 2>/dev/null | jq . > "$OUTPUT_DIR/jwt_test/header.json" || echo "$HEADER" > "$OUTPUT_DIR/jwt_test/header.json"

    echo -e "${BLUE}[*] Decoding payload.${NC}"
    echo "$PAYLOAD" | base64 -d 2>/dev/null | jq . > "$OUTPUT_DIR/jwt_test/payload.json" || echo "$PAYLOAD" > "$OUTPUT_DIR/jwt_test/payload.json"

    # Security tests
    echo -e "${BLUE}[*] Running JWT security checks.${NC}"

    # Comprehensive JWT Security Tests

    # Test 1: Algorithm None Attack
    echo -e "${BLUE}[*] Testing for algorithm none vulnerability.${NC}"

    # Create multiple headers with alg=none variations
    echo '{"alg":"none"}' | base64 | tr '+/' '-_' | tr -d '=' > "$OUTPUT_DIR/jwt_test/none_header1.txt"
    echo '{"alg":"None"}' | base64 | tr '+/' '-_' | tr -d '=' > "$OUTPUT_DIR/jwt_test/none_header2.txt"
    echo '{"alg":"NONE"}' | base64 | tr '+/' '-_' | tr -d '=' > "$OUTPUT_DIR/jwt_test/none_header3.txt"
    echo '{"alg":"nOnE"}' | base64 | tr '+/' '-_' | tr -d '=' > "$OUTPUT_DIR/jwt_test/none_header4.txt"

    # Create tokens for testing
    for i in {1..4}; do
        HEADER_CONTENT=$(cat "$OUTPUT_DIR/jwt_test/none_header$i.txt")
        # Tokens without signature
        echo "${HEADER_CONTENT}.${PAYLOAD}." > "$OUTPUT_DIR/jwt_test/none_attack_token${i}_empty.txt"
        # Tokens with original signature
        echo "${HEADER_CONTENT}.${PAYLOAD}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/none_attack_token${i}_sig.txt"
    done

    echo -e "${YELLOW}[*] Created 8 algorithm none attack test tokens${NC}"

    # Test 2: Algorithm Confusion Attacks (RS256/HS256 confusion)
    echo -e "${BLUE}[*] Testing for algorithm confusion vulnerabilities.${NC}"

    # Check if current token uses RS256
    if grep -q '"alg":\s*"RS256"' "$OUTPUT_DIR/jwt_test/header.json"; then
        # Create a modified header with alg=HS256 instead of RS256
        jq '.alg = "HS256"' "$OUTPUT_DIR/jwt_test/header.json" > "$OUTPUT_DIR/jwt_test/hs256_header.json"
        MODIFIED_HEADER=$(cat "$OUTPUT_DIR/jwt_test/hs256_header.json" | base64 | tr -d '=' | tr '+/' '-_')

        # Create a test token with the modified header
        echo "${MODIFIED_HEADER}.${PAYLOAD}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/algorithm_confusion_token.txt"
        echo -e "${YELLOW}[*] Created algorithm confusion attack token (RS256->HS256)${NC}"
    fi

    # Test 3: Check for weak algorithms and cryptographic issues
    echo -e "${BLUE}[*] Checking for weak cryptographic implementation.${NC}"

    # Create structured algorithm security assessment
    if grep -q '"alg":\s*"HS256"' "$OUTPUT_DIR/jwt_test/header.json"; then
        echo -e "${YELLOW}[!] WARNING: JWT uses HMAC-SHA256 algorithm - potentially vulnerable to brute-force if key length < 256 bits${NC}"
        echo "WARNING: JWT uses HMAC-SHA256 algorithm" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        echo "RISK: If the secret key is weak or predictable, token could be forged" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    if grep -q '"alg":\s*"HS1' "$OUTPUT_DIR/jwt_test/header.json"; then
        echo -e "${RED}[!] CRITICAL: JWT uses HS1xx algorithm which is cryptographically weak${NC}"
        echo "CRITICAL: JWT uses weak HS1xx algorithm" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    if grep -q '"alg":\s*"RS1' "$OUTPUT_DIR/jwt_test/header.json"; then
        echo -e "${RED}[!] CRITICAL: JWT uses RS1xx algorithm which is cryptographically weak${NC}"
        echo "CRITICAL: JWT uses weak RS1xx algorithm" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    # Test 4: Check for kid manipulation vulnerabilities
    echo -e "${BLUE}[*] Checking for kid (Key ID) parameter vulnerabilities.${NC}"

    if grep -q '"kid"' "$OUTPUT_DIR/jwt_test/header.json"; then
        KID_VALUE=$(grep -o '"kid":\s*"[^"]*"' "$OUTPUT_DIR/jwt_test/header.json" | cut -d\" -f4)
        echo -e "${YELLOW}[!] JWT contains 'kid' parameter: $KID_VALUE${NC}"

        # Generate test tokens with manipulated kid values
        jq '.kid = "../../../../../dev/null"' "$OUTPUT_DIR/jwt_test/header.json" > "$OUTPUT_DIR/jwt_test/header_path_traversal.json"
        TRAVERSAL_HEADER=$(cat "$OUTPUT_DIR/jwt_test/header_path_traversal.json" | base64 | tr -d '=' | tr '+/' '-_')
        echo "${TRAVERSAL_HEADER}.${PAYLOAD}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/kid_traversal_attack.txt"

        jq '.kid = "1 OR 1=1"' "$OUTPUT_DIR/jwt_test/header.json" > "$OUTPUT_DIR/jwt_test/header_sqli.json"
        SQLI_HEADER=$(cat "$OUTPUT_DIR/jwt_test/header_sqli.json" | base64 | tr -d '=' | tr '+/' '-_')
        echo "${SQLI_HEADER}.${PAYLOAD}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/kid_sqli_attack.txt"

        echo -e "${YELLOW}[*] Created JWT kid manipulation attack tokens${NC}"
        echo "TEST: JWT kid parameter manipulation tokens generated" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    # Test 5: Check for missing or weak signature
    if [ -z "$SIGNATURE" ] || [ "$SIGNATURE" = "0" ]; then
        echo -e "${RED}[!] CRITICAL: JWT has no signature or uses a trivial signature${NC}"
        echo "CRITICAL: JWT has no valid signature" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    # Test 6: Check for JWT claims security
    echo -e "${BLUE}[*] Analyzing JWT claims for security issues.${NC}"
    jq . "$OUTPUT_DIR/jwt_test/payload.json" > "$OUTPUT_DIR/jwt_test/payload_formatted.json"

    # Create tokens with modified claims for testing
    echo -e "${BLUE}[*] Generating test tokens with modified claims.${NC}"

    # 6.1 Check critical security claims (exp, nbf, iat)
    # Expiration claim
    if ! grep -q '"exp"' "$OUTPUT_DIR/jwt_test/payload.json"; then
        echo -e "${RED}[!] CRITICAL: JWT does not have an expiration claim (exp)${NC}"
        echo "CRITICAL: JWT does not have an expiration claim (exp)" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        echo "RISK: Non-expiring tokens remain valid indefinitely" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"

        # Create a payload with added exp claim for testing
        jq '. += {"exp": '"$(date -d '+10 years' +%s)"'}' "$OUTPUT_DIR/jwt_test/payload.json" > "$OUTPUT_DIR/jwt_test/payload_with_exp.json"
        PAYLOAD_WITH_EXP=$(cat "$OUTPUT_DIR/jwt_test/payload_with_exp.json" | base64 | tr -d '=' | tr '+/' '-_')
        echo "${HEADER}.${PAYLOAD_WITH_EXP}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/added_exp_token.txt"
    else
        EXP=$(grep -o '"exp":\s*[0-9]*' "$OUTPUT_DIR/jwt_test/payload.json" | cut -d: -f2 | tr -d ' ')
        CURRENT_TIME=$(date +%s)

        if [ "$EXP" -lt "$CURRENT_TIME" ]; then
            echo -e "${YELLOW}[!] WARNING: JWT is expired${NC}"
            echo "WARNING: JWT is expired" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"

            # Create a token with updated expiration
            jq '.exp = '"$(date -d '+1 hour' +%s)"'' "$OUTPUT_DIR/jwt_test/payload.json" > "$OUTPUT_DIR/jwt_test/payload_updated_exp.json"
            UPDATED_EXP_PAYLOAD=$(cat "$OUTPUT_DIR/jwt_test/payload_updated_exp.json" | base64 | tr -d '=' | tr '+/' '-_')
            echo "${HEADER}.${UPDATED_EXP_PAYLOAD}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/updated_exp_token.txt"
        elif [ "$((EXP - CURRENT_TIME))" -gt 86400 ]; then
            echo -e "${YELLOW}[!] WARNING: JWT has a long expiration time (>24 hours)${NC}"
            echo "WARNING: JWT has a long expiration time (>24 hours)" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
            echo "RISK: Long-lived tokens increase the window of opportunity for token compromise" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        fi
    fi

    # 6.2 Check for 'not before' claim
    if ! grep -q '"nbf"' "$OUTPUT_DIR/jwt_test/payload.json"; then
        echo -e "${YELLOW}[!] WARNING: JWT does not have a not-before claim (nbf)${NC}"
        echo "WARNING: JWT does not have a not-before claim (nbf)" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"

        # Add nbf claim for testing
        jq '. += {"nbf": '"$(date -d '-1 day' +%s)"'}' "$OUTPUT_DIR/jwt_test/payload.json" > "$OUTPUT_DIR/jwt_test/payload_with_nbf.json"
        PAYLOAD_WITH_NBF=$(cat "$OUTPUT_DIR/jwt_test/payload_with_nbf.json" | base64 | tr -d '=' | tr '+/' '-_')
        echo "${HEADER}.${PAYLOAD_WITH_NBF}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/added_nbf_token.txt"
    fi

    # 6.3 Check for issued at claim
    if ! grep -q '"iat"' "$OUTPUT_DIR/jwt_test/payload.json"; then
        echo -e "${YELLOW}[!] WARNING: JWT does not have an issued-at claim (iat)${NC}"
        echo "WARNING: JWT does not have an issued-at claim (iat)" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    # 6.4 Check for audience validation
    if ! grep -q '"aud"' "$OUTPUT_DIR/jwt_test/payload.json"; then
        echo -e "${YELLOW}[!] WARNING: JWT does not have an audience claim (aud)${NC}"
        echo "WARNING: JWT does not have an audience claim (aud)" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        echo "RISK: Without audience validation, tokens might be accepted by unintended services" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    else
        # Create token with modified audience
        jq '.aud = "evil.com"' "$OUTPUT_DIR/jwt_test/payload.json" > "$OUTPUT_DIR/jwt_test/payload_evil_aud.json"
        EVIL_AUD_PAYLOAD=$(cat "$OUTPUT_DIR/jwt_test/payload_evil_aud.json" | base64 | tr -d '=' | tr '+/' '-_')
        echo "${HEADER}.${EVIL_AUD_PAYLOAD}.${SIGNATURE}" > "$OUTPUT_DIR/jwt_test/evil_aud_token.txt"
    fi

    # Test 7: Check for sensitive info in payload
    echo -e "${BLUE}[*] Checking for sensitive information in payload.${NC}"
    grep -i -E "(password|secret|key|token|credential|auth|private|confidential|ssn|social|account|credit|card|cvv|routing|license|access|refresh)" "$OUTPUT_DIR/jwt_test/payload.json" > "$OUTPUT_DIR/jwt_test/sensitive.txt"

    if [ -s "$OUTPUT_DIR/jwt_test/sensitive.txt" ]; then
        echo -e "${RED}[!] CRITICAL: JWT contains potentially sensitive information${NC}"
        cat "$OUTPUT_DIR/jwt_test/sensitive.txt"
        echo "CRITICAL: JWT contains potentially sensitive information:" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        cat "$OUTPUT_DIR/jwt_test/sensitive.txt" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        echo "RISK: Sensitive data in tokens may be exposed if the token is compromised" >> "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
    fi

    # Test 8: Privilege escalation tests
    echo -e "${BLUE}[*] Creating privilege escalation test tokens.${NC}"

    # Extract information from the original payload
    ORIG_PAYLOAD=$(cat "$OUTPUT_DIR/jwt_test/payload.json")

    # Create a payload with modified user role/privileges if available
    if echo "$ORIG_PAYLOAD" | grep -q "role\|admin\|isAdmin\|privileges\|permissions"; then
        echo "$ORIG_PAYLOAD" | sed 's/"role"\s*:\s*"user"/"role":"admin"/g' | sed 's/"admin"\s*:\s*false/"admin":true/g' | sed 's/"isAdmin"\s*:\s*false/"isAdmin":true/g' > "$OUTPUT_DIR/jwt_test/admin_payload.json"

        # Base64 encode the modified payload
        cat "$OUTPUT_DIR/jwt_test/admin_payload.json" | base64 | tr '+/' '-_' | tr -d '=' > "$OUTPUT_DIR/jwt_test/admin_payload_b64.txt"
        ADMIN_PAYLOAD=$(cat "$OUTPUT_DIR/jwt_test/admin_payload_b64.txt")

        # Create a token with the modified payload
        ADMIN_TOKEN="${HEADER}.${ADMIN_PAYLOAD}.${SIGNATURE}"
        echo "$ADMIN_TOKEN" > "$OUTPUT_DIR/jwt_test/admin_role_token.txt"
    fi

    # Generate final report
    echo -e "${BLUE}[*] Generating JWT security report.${NC}"
    {
        echo "JWT Security Test Report"
        echo "======================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo
        echo "1. JWT Structure"
        echo "---------------"
        echo "Original Token: $JWT"
        echo
        echo "2. Decoded Header:"
        echo "------------------"
        cat "$OUTPUT_DIR/jwt_test/header.json"
        echo
        echo "3. Decoded Payload:"
        echo "------------------"
        cat "$OUTPUT_DIR/jwt_test/payload.json"
        echo
        echo "4. Security Issues:"
        echo "------------------"

        if [ -f "$OUTPUT_DIR/jwt_test/vulnerabilities.txt" ]; then
            cat "$OUTPUT_DIR/jwt_test/vulnerabilities.txt"
        else
            echo "No obvious JWT security issues detected"
        fi

        echo
        echo "5. Test Tokens:"
        echo "---------------"
        echo "Alg=None Attack Token 1: $(cat "$OUTPUT_DIR/jwt_test/none_attack_token1.txt")"
        echo "Alg=None Attack Token 2: $(cat "$OUTPUT_DIR/jwt_test/none_attack_token2.txt")"
        
        if [ -f "$OUTPUT_DIR/jwt_test/admin_role_token.txt" ]; then
            echo "Privilege Escalation Token: $(cat "$OUTPUT_DIR/jwt_test/admin_role_token.txt")"
        fi

        echo
        echo "Note: These tokens can be used to test if the server properly validates JWT signatures and claims."
        echo "WARNING: Only use these test tokens in authorized security assessments."

    } > "$OUTPUT_DIR/jwt_security_report.txt"

    echo -e "${YELLOW}[*] JWT security test complete. Results saved to $OUTPUT_DIR/jwt_security_report.txt${NC}"
}

###############################################################################################################################

# Main function
f_oauth_jwt_main(){
    echo -e "${BLUE}OAuth/JWT Security Scanner${NC}"
    echo
    echo "1. OAuth Configuration/Security Test"
    echo "2. JWT Security Test"
    echo "3. Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
        1)
           echo
           echo -n "Enter target URL (e.g., http://target.com): "
           read -r TARGET_URL

           if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
               echo
               echo -e "${RED}[!] Invalid URL. Must start with http:// or https://${NC}"
               echo
               exit 1
           fi

           f_oauth_analyze "$TARGET_URL" "$NAME"
           ;;
        2)
           echo
           echo -n "Enter JWT token to test: "
           read -r JWT_TOKEN

           if [[ ! "$JWT_TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
               echo
               echo -e "${RED}[!] Invalid JWT format. Must be in format 'header.payload.signature'${NC}"
               echo
               exit 1
           fi

           f_jwt_security "$JWT_TOKEN" "$NAME"
           ;;
        3) f_main ;;
        *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; clear && f_banner && f_oauth_jwt_main ;;
    esac
}

# Run the script
f_oauth_jwt_main
