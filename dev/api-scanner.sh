#!/usr/bin/env bash

# by ibrahimsql - API Security Scanner
# Upgrades and bug fixes by Lee Baird (@discoverscripts)
#
# Standalone scanner: writes only under $HOME/data/api-scan_*/ (or --resume).
# Does not call Discover report helpers (f_report*, report.sh) or update recon HTML.

if ! declare -f f_banner >/dev/null 2>&1; then
    _API_SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    DISCOVER_SOURCE_ONLY=1 source "${_API_SCANNER_DIR}/../discover.sh"
fi

_API_SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/api-scanner/common.sh
source "${_API_SCANNER_DIR}/lib/api-scanner/common.sh"

###############################################################################################################################

f_terminate(){
    echo
    echo -e "${RED}[!] Terminating.${NC}"
    echo
    exit 1
}

trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################
# Phase: passive link extraction from HTML/JS

f_api_phase_link_extract(){
    f_api_should_run_phase "link_extract" || return 0
    echo -e "${BLUE}[*] Extracting API links from target HTML/JS.${NC}"

    local page="${OUTPUT_DIR}/api_scanner/crawl/index.html"
    mkdir -p "${OUTPUT_DIR}/api_scanner/crawl"
    f_api_request GET "$API_TARGET_URL" -o "$page" 2>/dev/null || true

    if [ -s "$page" ]; then
        grep -oiE 'href=["'\'']([^"'\'']+)["'\'']|src=["'\'']([^"'\'']+)["'\'']|["'\''](/api[^"'\'']*|/graphql[^"'\'']*|/swagger[^"'\'']*|/v[0-9]+/[^"'\'']*)["'\'']' "$page" 2>/dev/null \
            | sed -E 's/^[^"\x27]*["'\'']([^"'\'']+)["'\'']$/\1/; s/^["'\'']([^"'\'']+)["'\'']$/\1/' \
            | grep -E '^https?://|^\.' | sed "s|^\./|${API_TARGET_URL%/}/|" \
            | grep -E '/api/|/graphql|/gql|/swagger|/openapi|/v[0-9]+/' \
            | while read -r u; do f_url_normalize "$u"; done \
            | sort -u > "${OUTPUT_DIR}/api_scanner/endpoints_html.txt"

        if [ -s "${OUTPUT_DIR}/api_scanner/endpoints_html.txt" ]; then
            local n
            n=$(wc -l < "${OUTPUT_DIR}/api_scanner/endpoints_html.txt")
            echo -e "${YELLOW}[*] HTML/JS extraction found $n URLs.${NC}"
            while read -r u; do
                echo "$u (200 - HTML)" >> "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt"
            done < "${OUTPUT_DIR}/api_scanner/endpoints_html.txt"
        fi
    fi
    f_api_mark_phase "link_extract"
}

###############################################################################################################################
# Phase: ffuf / feroxbuster path discovery

f_api_phase_fuzzer(){
    f_api_should_run_phase "fuzzer" || return 0
    local wordlist="${OUTPUT_DIR}/api_scanner/_wordlist.txt"
    f_api_paths_file "$wordlist"

    if command -v ffuf >/dev/null 2>&1; then
        echo -e "${BLUE}[*] Running ffuf path discovery (threads: $API_MAX_PARALLEL).${NC}"
        f_api_log "ffuf User-Agent: $USER_AGENT"
        f_api_request GET "${API_TARGET_URL%/}/" -o /dev/null 2>/dev/null || true
        local ffuf_args=(-u "${API_TARGET_URL%/}/FUZZ" -w "$wordlist" -H "User-Agent: ${USER_AGENT}")
        [ -n "$API_BEARER_TOKEN" ] && ffuf_args+=(-H "Authorization: Bearer ${API_BEARER_TOKEN}")
        ffuf "${ffuf_args[@]}" \
            -mc 200,201,204,301,302,307,401,403,405,500 \
            -t "$API_MAX_PARALLEL" -s -o "${OUTPUT_DIR}/api_scanner/ffuf.json" -of json 2>>"$API_SCAN_LOG" || true

        if [ -s "${OUTPUT_DIR}/api_scanner/ffuf.json" ] && command -v jq >/dev/null 2>&1; then
            jq -r '.results[]? | .url' "${OUTPUT_DIR}/api_scanner/ffuf.json" 2>/dev/null | while read -r u; do
                [ -n "$u" ] && echo "$u (200 - FFUF)" >> "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt"
            done
            local fn
            fn=$(jq -r '.results | length' "${OUTPUT_DIR}/api_scanner/ffuf.json" 2>/dev/null || echo 0)
            echo -e "${YELLOW}[*] ffuf discovered $fn paths.${NC}"
        fi
    elif command -v feroxbuster >/dev/null 2>&1; then
        echo -e "${BLUE}[*] Running feroxbuster path discovery.${NC}"
        f_api_log "feroxbuster User-Agent: $USER_AGENT"
        feroxbuster -u "$API_TARGET_URL" -w "$wordlist" -a "$USER_AGENT" -t "$API_MAX_PARALLEL" \
            -C 404 -q --no-recursion -o "${OUTPUT_DIR}/api_scanner/feroxbuster.txt" 2>>"$API_SCAN_LOG" || true
        if [ -s "${OUTPUT_DIR}/api_scanner/feroxbuster.txt" ]; then
            awk '{print $2}' "${OUTPUT_DIR}/api_scanner/feroxbuster.txt" | while read -r u; do
                [ -n "$u" ] && echo "$u (200 - FEROX)" >> "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt"
            done
        fi
    else
        echo -e "${YELLOW}[*] Skipping fuzzer (ffuf/feroxbuster not installed).${NC}"
    fi
    rm -f "$wordlist"
    f_api_mark_phase "fuzzer"
}

###############################################################################################################################
# Phase: sequential path probe (fallback / complement)

f_api_probe_single_path(){
    local path="$1"
    local url="${API_TARGET_URL%/}${path}"
    local status safe response_file status_message curl_args=()

    f_api_curl_args curl_args
    status=$(curl "${curl_args[@]}" -o /dev/null -w "%{http_code}" "$url" || echo "000")
    ((API_REQUEST_COUNT++))
    f_api_log "REQUEST #$API_REQUEST_COUNT GET $url -> $status"

    [[ "$status" == "200" || "$status" == "201" || "$status" == "204" ||
       "$status" == "301" || "$status" == "302" || "$status" == "307" ||
       "$status" == "401" || "$status" == "403" || "$status" == "405" ||
       "$status" == "500" ]] || return 0

    case "$status" in
        200|201|204) status_message="SUCCESS";;
        301|302|307) status_message="REDIRECT";;
        401) status_message="UNAUTHORIZED";;
        403) status_message="FORBIDDEN";;
        405) status_message="METHOD NOT ALLOWED";;
        500) status_message="SERVER ERROR";;
    esac

    echo "$url ($status - $status_message)" >> "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt"
    safe=$(echo "$path" | sed 's/[\/:#?=&% ]/_/g' | tr -cd 'a-zA-Z0-9_.-')
    response_file="${OUTPUT_DIR}/api_scanner/responses/response_${safe}.txt"

    if curl "${curl_args[@]}" -i -H "Accept: application/json, text/plain, */*" "$url" > "$response_file" 2>"${OUTPUT_DIR}/api_scanner/curl_err_${safe}.txt"; then
        if grep -qi "Content-Type:.*json" "$response_file" 2>/dev/null; then
            sed -n '/^\r\{0,1\}$/,$p' "$response_file" | sed '1d' > "${response_file}.json" 2>/dev/null || cp "$response_file" "${response_file}.json"
            if [[ "$path" == *graphql* || "$path" == *gql* ]]; then
                local intro='{"query":"{__schema{queryType{name}}}"}'
                f_api_request POST "$url" -H "Content-Type: application/json" -d "$intro" \
                    -o "${OUTPUT_DIR}/api_scanner/responses/graphql_introspection_${safe}.json" 2>/dev/null || true
            fi
        fi
        grep -i -E '(api[-_]?key[[:space:]:=]|apikey[[:space:]:=]|password[[:space:]:=]|secrettoken[[:space:]:=]|credential[[:space:]:=]|bearer[[:space:]]+[a-zA-Z0-9._-]{20,}|"secret"[[:space:]]*:)' \
            "$response_file" > "${response_file}.sensitive" 2>/dev/null
        if [ -s "${response_file}.sensitive" ]; then
            f_api_record_finding "high" "likely" "sensitive" "$url" "$response_file.sensitive" "Potential sensitive data in response"
        fi
    fi
}

f_api_phase_path_probe(){
    f_api_should_run_phase "path_probe" || return 0
    if [ -f "${API_CHECKPOINT_DIR}/fuzzer.done" ] && \
       grep -q 'FFUF\|FEROX' "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt" 2>/dev/null && \
       [ "${API_FORCE_PATH_PROBE:-0}" != "1" ]; then
        echo -e "${YELLOW}[*] Skipping sequential path probe (fuzzer found endpoints). Set API_FORCE_PATH_PROBE=1 to override.${NC}"
        f_api_mark_phase "path_probe"
        return 0
    fi
    echo -e "${BLUE}[*] Probing common API paths (parallel: $API_MAX_PARALLEL).${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/responses"
    local paths_file="${OUTPUT_DIR}/api_scanner/_paths_probe.txt"
    f_api_paths_file "$paths_file"
    local total=0 active=0 path

    while read -r path; do
        [[ "$path" =~ ^[[:space:]]*# || -z "$path" ]] && continue
        ((total++))
        f_api_probe_single_path "$path" &
        ((active++))
        while [ "$(jobs -rp | wc -l)" -ge "$API_MAX_PARALLEL" ]; do
            wait -n 2>/dev/null || wait
        done
    done < "$paths_file"
    wait
    rm -f "$paths_file"
    echo -e "${YELLOW}[*] Path probe complete ($total paths tested).${NC}"
    f_api_mark_phase "path_probe"
}

###############################################################################################################################
# Phase: GraphQL testing (introspection, depth, batching)

f_api_phase_graphql(){
    f_api_should_run_phase "graphql" || return 0
    echo -e "${BLUE}[*] GraphQL security testing.${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/graphql"

    grep -iE '(graphql|gql)' "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt" 2>/dev/null | cut -d ' ' -f1 | sort -u | while read -r gql_url; do
        [ -z "$gql_url" ] && continue
        local name intro_file schema_file
        name=$(echo "$gql_url" | sed 's|https\?://||' | sed 's|[/.:]|_|g')
        intro_file="${OUTPUT_DIR}/api_scanner/graphql/${name}_introspection_basic.json"

        f_api_request POST "$gql_url" -H "Content-Type: application/json" \
            -d '{"query":"{__schema{queryType{name}}}"}' -o "$intro_file" 2>/dev/null || true

        if f_graphql_introspection_ok "$intro_file"; then
            f_api_record_finding "high" "confirmed" "graphql" "$gql_url" "$intro_file" "GraphQL introspection enabled"
            schema_file="${OUTPUT_DIR}/api_scanner/graphql/${name}_schema_full.json"
            f_api_request POST "$gql_url" -H "Content-Type: application/json" \
                -d '{"query":"query IntrospectionQuery { __schema { queryType { name } types { kind name fields { name } } } }"}' \
                -o "$schema_file" 2>/dev/null || true
        fi

        # Depth limit test
        local depth_file="${OUTPUT_DIR}/api_scanner/graphql/${name}_depth_test.json"
        f_api_request POST "$gql_url" -H "Content-Type: application/json" \
            -d '{"query":"{__typename __typename __typename __typename __typename __typename __typename __typename __typename __typename}"}' \
            -o "$depth_file" 2>/dev/null || true
        if f_graphql_has_data "$depth_file" 2>/dev/null || ! grep -q '"errors"' "$depth_file" 2>/dev/null; then
            [ -s "$depth_file" ] && f_api_record_finding "medium" "likely" "graphql" "$gql_url" "$depth_file" "GraphQL may lack depth limiting"
        fi

        # Batch query test
        local batch_file="${OUTPUT_DIR}/api_scanner/graphql/${name}_batch_test.json"
        f_api_request POST "$gql_url" -H "Content-Type: application/json" \
            -d '[{"query":"{__typename}"},{"query":"{__schema{queryType{name}}}"}]' \
            -o "$batch_file" 2>/dev/null || true
        if f_graphql_has_data "$batch_file" 2>/dev/null; then
            f_api_record_finding "medium" "likely" "graphql" "$gql_url" "$batch_file" "GraphQL batch queries accepted"
        fi

        # Alias overload (light)
        local alias_file="${OUTPUT_DIR}/api_scanner/graphql/${name}_alias_test.json"
        f_api_request POST "$gql_url" -H "Content-Type: application/json" \
            -d '{"query":"{a1:__typename a2:__typename a3:__typename a4:__typename a5:__typename}"}' \
            -o "$alias_file" 2>/dev/null || true
        if f_graphql_has_data "$alias_file" 2>/dev/null; then
            f_api_record_finding "low" "inconclusive" "graphql" "$gql_url" "$alias_file" "GraphQL alias queries accepted"
        fi
    done
    f_api_mark_phase "graphql"
}

###############################################################################################################################
# Phase: OpenAPI / Swagger documentation

f_api_phase_documentation(){
    f_api_should_run_phase "documentation" || return 0
    echo -e "${BLUE}[*] API documentation discovery.${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/documentation"
    API_FOUND_DOCS=0

    f_api_probe_doc_path(){
        local path="$1"
        local url="${API_TARGET_URL%/}${path}" safe status spec_file
        safe=$(echo "$path" | sed 's|/|.|g')
        status=$(f_api_request GET "$url" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
        [[ "$status" == "200" ]] || return 0

        spec_file="${OUTPUT_DIR}/api_scanner/documentation/api_doc${safe}.txt"
        f_api_request GET "$url" -o "$spec_file" 2>/dev/null || true
        f_api_record_finding "medium" "confirmed" "documentation" "$url" "$spec_file" "API documentation exposed"
        echo 1 >> "${OUTPUT_DIR}/api_scanner/_doc_hits.txt"

        if command -v jq >/dev/null 2>&1 && jq -e '.paths' "$spec_file" >/dev/null 2>&1; then
            jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\($p)|\(.key)|\(.value|keys|join(","))"' "$spec_file" \
                > "${OUTPUT_DIR}/api_scanner/documentation/openapi_ops${safe}.txt" 2>/dev/null
            jq -r '.paths | keys[]' "$spec_file" 2>/dev/null >> "${OUTPUT_DIR}/api_scanner/openapi_endpoints.txt"
            head -5 "${OUTPUT_DIR}/api_scanner/documentation/openapi_ops${safe}.txt" 2>/dev/null | while IFS='|' read -r ep method _keys; do
                f_api_request "$method" "${API_TARGET_URL%/}${ep}" \
                    -o "${OUTPUT_DIR}/api_scanner/documentation/probe_${safe}_${method}.txt" 2>/dev/null || true
            done
        fi
    }

    : > "${OUTPUT_DIR}/api_scanner/_doc_hits.txt"
    while read -r path; do
        [ -z "$path" ] && continue
        f_api_probe_doc_path "$path" &
        while [ "$(jobs -rp | wc -l)" -ge "$API_MAX_PARALLEL" ]; do wait -n 2>/dev/null || wait; done
    done < <(f_api_swagger_paths)
    wait
    API_FOUND_DOCS=$(wc -l < "${OUTPUT_DIR}/api_scanner/_doc_hits.txt" 2>/dev/null || echo 0)
    rm -f "${OUTPUT_DIR}/api_scanner/_doc_hits.txt"

    echo -e "${YELLOW}[*] Documentation scan found $API_FOUND_DOCS resources.${NC}"
    f_api_mark_phase "documentation"
}

###############################################################################################################################
# Phase: merge and normalize endpoints

f_api_phase_merge_endpoints(){
    f_api_should_run_phase "merge" || return 0
    cut -d ' ' -f1 "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt" 2>/dev/null > "${OUTPUT_DIR}/api_scanner/_found_urls.txt"
    f_merge_endpoint_lists "${OUTPUT_DIR}/api_scanner/all_endpoints.txt" \
        "${OUTPUT_DIR}/api_scanner/_found_urls.txt" \
        "${OUTPUT_DIR}/api_scanner/openapi_endpoints.txt" \
        "${OUTPUT_DIR}/api_scanner/endpoints_html.txt"
    rm -f "${OUTPUT_DIR}/api_scanner/_found_urls.txt"
    f_api_limit_endpoints "${OUTPUT_DIR}/api_scanner/all_endpoints.txt"
    local n
    n=$(wc -l < "${OUTPUT_DIR}/api_scanner/all_endpoints.txt" 2>/dev/null || echo 0)
    echo -e "${YELLOW}[*] $n unique endpoints ready for testing.${NC}"
    f_api_mark_phase "merge"
}

###############################################################################################################################
# Phase: CORS (simple + preflight)

f_api_phase_cors(){
    f_api_should_run_phase "cors" || return 0
    echo -e "${BLUE}[*] CORS security testing (GET + preflight).${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/cors"
    local origins_file="${OUTPUT_DIR}/api_scanner/cors/test_origins.txt"
    f_api_build_cors_origins "$API_TARGET_HOST" "$API_TARGET_AUTHORITY" "$origins_file"

    while read -r endpoint; do
        [ -z "$endpoint" ] && continue
        local safe origin cors_file preflight_file
        safe=$(echo "$endpoint" | sed 's|[:/]|_|g')

        while read -r origin; do
            [ -z "$origin" ] && continue
            cors_file="${OUTPUT_DIR}/api_scanner/cors/get_${safe}_$(echo "$origin" | sed 's|[^a-zA-Z0-9]|_|g').txt"
            f_api_request GET "$endpoint" -H "Origin: $origin" -D "$cors_file" -o /dev/null 2>/dev/null || true

            if grep -qi "access-control-allow-origin:" "$cors_file" 2>/dev/null && \
               { grep -qiF "access-control-allow-origin: ${origin}" "$cors_file" 2>/dev/null || \
                 grep -qi "access-control-allow-origin: \*" "$cors_file" 2>/dev/null; }; then
                local sev="high" cred
                grep -qi 'access-control-allow-credentials: true' "$cors_file" && sev="critical"
                f_api_record_finding "$sev" "confirmed" "cors" "$endpoint" "$cors_file" "CORS reflects origin: $origin"
                break
            fi

            preflight_file="${OUTPUT_DIR}/api_scanner/cors/preflight_${safe}_$(echo "$origin" | sed 's|[^a-zA-Z0-9]|_|g').txt"
            f_api_request OPTIONS "$endpoint" \
                -H "Origin: $origin" \
                -H "Access-Control-Request-Method: POST" \
                -H "Access-Control-Request-Headers: Content-Type, Authorization" \
                -D "$preflight_file" -o /dev/null 2>/dev/null || true

            if grep -qi "access-control-allow-origin:" "$preflight_file" 2>/dev/null && \
               { grep -qiF "access-control-allow-origin: ${origin}" "$preflight_file" 2>/dev/null || \
                 grep -qi "access-control-allow-origin: \*" "$preflight_file" 2>/dev/null; }; then
                local psev="high"
                grep -qi 'access-control-allow-credentials: true' "$preflight_file" && psev="critical"
                f_api_record_finding "$psev" "confirmed" "cors" "$endpoint" "$preflight_file" "CORS preflight allows origin: $origin"
                break
            fi
        done < "$origins_file"
    done < "${OUTPUT_DIR}/api_scanner/all_endpoints.txt"
    f_api_mark_phase "cors"
}

###############################################################################################################################
# Phase: HTTP methods

f_api_phase_http_methods(){
    f_api_should_run_phase "http_methods" || return 0
    echo -e "${BLUE}[*] HTTP method testing (sample).${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/security"
    head -10 "${OUTPUT_DIR}/api_scanner/all_endpoints.txt" > "${OUTPUT_DIR}/api_scanner/sample_endpoints.txt"

    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD")
    [ "$API_AGGRESSIVE_HTTP" = "1" ] && methods+=("TRACE" "CONNECT")

    while read -r endpoint; do
        [ -z "$endpoint" ] && continue
        local safe opts_file allowed
        safe=$(echo "$endpoint" | sed 's|[:/]|_|g')
        opts_file="${OUTPUT_DIR}/api_scanner/security/options_${safe}.txt"
        f_api_request OPTIONS "$endpoint" -D "$opts_file" -o /dev/null 2>/dev/null || true
        allowed=$(grep -iE '^Allow:|access-control-allow-methods:' "$opts_file" | cut -d: -f2- | tr -d '\r')

        for method in "${methods[@]}"; do
            local mfile="${OUTPUT_DIR}/api_scanner/security/response_${safe}_${method}.txt"
            local status
            status=$(f_api_request "$method" "$endpoint" -o "$mfile" -w "%{http_code}" 2>/dev/null || echo "000")
            [[ "$status" =~ ^(200|201|202|204)$ ]] || continue
            if [[ "$method" == "TRACE" || "$method" == "CONNECT" ]]; then
                f_api_record_finding "high" "confirmed" "http_methods" "$endpoint" "$mfile" "Unsafe method $method returned $status"
            elif [[ "$method" != "GET" && "$method" != "HEAD" && "$method" != "OPTIONS" ]] && \
                 ! echo "$allowed" | grep -qi "$method"; then
                f_api_record_finding "medium" "likely" "http_methods" "$endpoint" "$mfile" "Undeclared method $method returned $status"
            fi
        done
    done < "${OUTPUT_DIR}/api_scanner/sample_endpoints.txt"
    f_api_mark_phase "http_methods"
}

###############################################################################################################################
# Phase: rate limiting burst

f_api_phase_rate_limit(){
    f_api_should_run_phase "rate_limit" || return 0
    local test_ep
    test_ep=$(head -1 "${OUTPUT_DIR}/api_scanner/all_endpoints.txt")
    [ -z "$test_ep" ] && { f_api_mark_phase "rate_limit"; return 0; }

    echo -e "${BLUE}[*] Rate limit burst test (50 requests).${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/security"
    local hits429=0 i status

    for i in $(seq 1 50); do
        status=$(f_api_request GET "$test_ep" -o "${OUTPUT_DIR}/api_scanner/security/rate_${i}.txt" -w "%{http_code}" 2>/dev/null || echo "000")
        [[ "$status" == "429" || "$status" == "503" ]] && ((hits429++))
    done

    if [ "$hits429" -gt 0 ]; then
        f_api_record_finding "info" "confirmed" "rate_limit" "$test_ep" "${OUTPUT_DIR}/api_scanner/security/rate_*.txt" "Rate limiting observed ($hits429/50 throttled)"
    elif grep -qi 'rate\|limit\|quota\|throttle' "${OUTPUT_DIR}"/api_scanner/security/rate_*.txt 2>/dev/null; then
        f_api_record_finding "info" "confirmed" "rate_limit" "$test_ep" "${OUTPUT_DIR}/api_scanner/security/rate_1.txt" "Rate limit headers present"
    else
        f_api_record_finding "low" "inconclusive" "rate_limit" "$test_ep" "${OUTPUT_DIR}/api_scanner/security/rate_1.txt" "No rate limiting observed in 50-request burst"
    fi
    f_api_mark_phase "rate_limit"
}

###############################################################################################################################
# Phase: JWT discovery and deep analysis

f_api_phase_jwt(){
    f_api_should_run_phase "jwt" || return 0
    echo -e "${BLUE}[*] JWT token analysis.${NC}"
    mkdir -p "${OUTPUT_DIR}/api_scanner/security"
    grep -Rho "eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" "${OUTPUT_DIR}/api_scanner" --include="*.txt" --include="*.json" 2>/dev/null \
        | sort -u > "${OUTPUT_DIR}/api_scanner/jwt_found.txt" || true

    if [ -s "${OUTPUT_DIR}/api_scanner/jwt_found.txt" ]; then
        while read -r token; do
            f_api_jwt_deep_check "$token" "${OUTPUT_DIR}/api_scanner/security"
        done < "${OUTPUT_DIR}/api_scanner/jwt_found.txt"
        echo -e "${YELLOW}[*] For OAuth/OIDC testing, also run: dev/oauth-jwt-scanner.sh${NC}"
    fi
    f_api_mark_phase "jwt"
}

###############################################################################################################################
# Reporting

f_api_phase_report(){
    echo -e "${BLUE}[*] Generating reports.${NC}"
    API_REQUEST_COUNT=$(grep -c 'REQUEST #' "$API_SCAN_LOG" 2>/dev/null || echo 0)
    local vuln_count endpoints_count report_generated
    vuln_count=$(wc -l < "$API_VULN_URL_FILE" 2>/dev/null || echo 0)
    endpoints_count=$(wc -l < "${OUTPUT_DIR}/api_scanner/all_endpoints.txt" 2>/dev/null || echo 0)
    report_generated=$(date -Iseconds)

    cat > "${OUTPUT_DIR}/api_scanner/report.txt" <<EOF
API Security Scanner Report

Target:     $API_TARGET_URL
Scan ID:    api-scan_${SCAN_STAMP}
Mode:       $API_SCAN_MODE
Generated:  $report_generated
Requests:   $API_REQUEST_COUNT
--------------------------------------------

EXECUTIVE SUMMARY BY CATEGORY
------------------------------
Documentation (confirmed):     $(f_api_count_findings documentation confirmed)
CORS (confirmed):              $(f_api_count_findings cors confirmed)
GraphQL (confirmed):           $(f_api_count_findings graphql confirmed)
GraphQL (likely/inconclusive): $(($(f_api_count_findings graphql likely) + $(f_api_count_findings graphql inconclusive)))
HTTP methods (confirmed):    $(f_api_count_findings http_methods confirmed)
Rate limit (inconclusive):     $(f_api_count_findings rate_limit inconclusive)
JWT issues:                    $(f_api_count_findings jwt confirmed)
Sensitive data (likely):       $(f_api_count_findings sensitive likely)

Total endpoints:               $endpoints_count
Unique vulnerable endpoints:   $vuln_count
Documentation resources:       ${API_FOUND_DOCS:-0}

DETAILED FINDINGS (with evidence)
----------------------------------
EOF

    tail -n +2 "$API_FINDINGS_FILE" 2>/dev/null | while IFS=$'\t' read -r sev conf cat url ev desc; do
        echo "  [$sev/$conf] $cat — $url" >> "${OUTPUT_DIR}/api_scanner/report.txt"
        echo "    Evidence: $ev" >> "${OUTPUT_DIR}/api_scanner/report.txt"
        echo "    $desc" >> "${OUTPUT_DIR}/api_scanner/report.txt"
        echo "" >> "${OUTPUT_DIR}/api_scanner/report.txt"
    done

    # Markdown report
    cat > "${OUTPUT_DIR}/api_scanner/report.md" <<EOF
# API Security Scanner Report

| Field | Value |
|-------|-------|
| Target | $API_TARGET_URL |
| Scan ID | api-scan_${SCAN_STAMP} |
| Mode | $API_SCAN_MODE |
| Generated | $report_generated |
| Requests | $API_REQUEST_COUNT |
| Endpoints | $endpoints_count |
| Vulnerable URLs | $vuln_count |

## Summary by Category

| Category | Confirmed | Likely | Inconclusive |
|----------|-----------|--------|--------------|
| Documentation | $(f_api_count_findings documentation confirmed) | $(f_api_count_findings documentation likely) | $(f_api_count_findings documentation inconclusive) |
| CORS | $(f_api_count_findings cors confirmed) | $(f_api_count_findings cors likely) | $(f_api_count_findings cors inconclusive) |
| GraphQL | $(f_api_count_findings graphql confirmed) | $(f_api_count_findings graphql likely) | $(f_api_count_findings graphql inconclusive) |
| HTTP Methods | $(f_api_count_findings http_methods confirmed) | $(f_api_count_findings http_methods likely) | $(f_api_count_findings http_methods inconclusive) |
| Rate Limiting | $(f_api_count_findings rate_limit confirmed) | $(f_api_count_findings rate_limit likely) | $(f_api_count_findings rate_limit inconclusive) |
| JWT | $(f_api_count_findings jwt confirmed) | $(f_api_count_findings jwt likely) | $(f_api_count_findings jwt inconclusive) |

## Findings

EOF

    tail -n +2 "$API_FINDINGS_FILE" 2>/dev/null | while IFS=$'\t' read -r sev conf cat url ev desc; do
        echo "### [$sev] $cat — $url" >> "${OUTPUT_DIR}/api_scanner/report.md"
        echo "- **Confidence:** $conf" >> "${OUTPUT_DIR}/api_scanner/report.md"
        echo "- **Evidence:** \`$ev\`" >> "${OUTPUT_DIR}/api_scanner/report.md"
        echo "- $desc" >> "${OUTPUT_DIR}/api_scanner/report.md"
        echo "" >> "${OUTPUT_DIR}/api_scanner/report.md"
    done

    echo "" >> "${OUTPUT_DIR}/api_scanner/report.md"
    echo "Request log: \`${API_SCAN_LOG}\`" >> "${OUTPUT_DIR}/api_scanner/report.md"
    echo "Findings JSON: \`findings.json\`" >> "${OUTPUT_DIR}/api_scanner/report.md"

    f_api_write_findings_json "$report_generated" "api-scan_${SCAN_STAMP}" "$API_REQUEST_COUNT" "$endpoints_count" "$vuln_count"

    find "${OUTPUT_DIR}/api_scanner" -type f \( -name 'curl_err_*' -o -name 'rate_*.txt' \) -empty -delete 2>/dev/null || true
    f_api_log "Scan complete. Requests: $API_REQUEST_COUNT Findings: $(tail -n +2 "$API_FINDINGS_FILE" | wc -l) (findings.json)"
}

###############################################################################################################################
# Scan orchestration

f_api_require_authorization(){
    [ "$API_AUTHORIZED" = "1" ] && return 0
    echo -e "${YELLOW}[!] Full scans send many requests to the target.${NC}"
    echo -n "Confirm you have authorization to test this target? (yes/no): "
    read -r ans
    [[ "$ans" == "yes" ]] || { echo "Aborted."; exit 1; }
    API_AUTHORIZED=1
}

f_api_run_scan(){
    local target="$1"
    mkdir -p "${OUTPUT_DIR}/api_scanner"
    touch "${OUTPUT_DIR}/api_scanner/found_api_endpoints.txt" "${OUTPUT_DIR}/api_scanner/all_endpoints.txt"
    f_api_init_scan "$target" "$([ -n "$API_RESUME_DIR" ] && echo 1 || echo 0)"

    if [ "$API_SCAN_MODE" = "full" ]; then
        f_api_require_authorization
    fi

    f_api_phase_link_extract
    f_api_phase_fuzzer
    f_api_phase_path_probe
    f_api_phase_documentation
    f_api_phase_merge_endpoints

    if [ "$API_SCAN_MODE" = "quick" ]; then
        f_api_phase_report
        echo -e "${YELLOW}[*] Quick scan complete (discovery + documentation).${NC}"
        echo -e "${YELLOW}[*] Run with --full for CORS, methods, rate limit, and JWT testing.${NC}"
        return 0
    fi

    f_api_phase_graphql
    f_api_phase_cors
    f_api_phase_http_methods
    f_api_phase_rate_limit
    f_api_phase_jwt
    f_api_phase_report
}

f_api_orchestrate(){
    local target="$1"
    echo -e "${BLUE}[*] Full API assessment orchestrator.${NC}"
    f_api_run_scan "$target"
    echo
    echo -e "${BLUE}Related Discover scanners for deeper coverage:${NC}"
    echo "  - dev/oauth-jwt-scanner.sh  (OAuth/OIDC)"
    echo "  - dev/open-redirect.sh      (open redirect fuzzing)"
    echo "  - dev/sensitive-scanner.sh  (secret leakage)"
    echo "  - dev/web-api-scanner.sh    (Metasploit web/API modules)"
    echo
    echo -n "Run oauth-jwt-scanner on same target now? (y/n): "
    read -r run_oauth
    if [[ "$run_oauth" =~ ^[Yy] ]]; then
        echo -e "${YELLOW}[*] Run: ${_API_SCANNER_DIR}/oauth-jwt-scanner.sh --target $target${NC}"
    fi
    echo -n "Run open-redirect on api-scan output? (y/n): "
    read -r run_redirect
    if [[ "$run_redirect" =~ ^[Yy] ]]; then
        echo -e "${YELLOW}[*] Run: ${_API_SCANNER_DIR}/open-redirect.sh --scan-dir $OUTPUT_DIR --quick${NC}"
    fi
    echo -n "Run sensitive-scanner on same target? (y/n): "
    read -r run_sens
    if [[ "$run_sens" =~ ^[Yy] ]]; then
        echo -e "${YELLOW}[*] Run: ${_API_SCANNER_DIR}/sensitive-scanner.sh${NC}"
    fi
}

###############################################################################################################################
# JWT standalone analysis (menu option 2)

f_jwt_analysis(){
    local JWT=$1
    local out=${2:-"$OUTPUT_DIR/jwt_analysis"}
    mkdir -p "$out"
    echo -e "${BLUE}[*] Analyzing JWT token.${NC}"
    f_api_jwt_deep_check "$JWT" "$out"
    echo -e "${YELLOW}[*] For OAuth/OIDC flows, use dev/oauth-jwt-scanner.sh${NC}"
    echo -e "${YELLOW}[*] Results in $out${NC}"
}

###############################################################################################################################
# CLI

f_api_usage(){
    cat <<EOF
Usage: api-scanner.sh [options]

Options:
  -u, --url URL           Target URL (skips menu when set)
  --quick                 Discovery + documentation only
  --full                  All test phases (default)
  --orchestrate           Full scan + prompt for sibling scanners
  --token TOKEN           Bearer token for authenticated scanning
  --cookie-file FILE      Netscape cookie jar for authenticated scanning
  --max-endpoints N       Limit endpoints tested after merge
  --max-parallel N        Concurrent workers (default: 3)
  --connect-timeout SEC   curl connect timeout (default: 3)
  --max-time SEC          curl max time (default: 7)
  --skip PHASE            Skip phase (link_extract,fuzzer,path_probe,graphql,
                          documentation,merge,cors,http_methods,rate_limit,jwt)
  --resume DIR            Resume scan using existing output directory
  --authorized            Skip authorization prompt
  --aggressive-http       Include TRACE/CONNECT method tests
  -h, --help              Show this help

Environment: API_MAX_PARALLEL, API_BEARER_TOKEN, API_COOKIE_FILE, etc.
EOF
}

f_api_parse_cli(){
    API_CLI_URL=""
    API_CLI_MODE=""
    API_RESUME_DIR=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -u|--url) API_CLI_URL="$2"; shift 2 ;;
            --quick) API_SCAN_MODE="quick"; shift ;;
            --full) API_SCAN_MODE="full"; shift ;;
            --orchestrate) API_CLI_MODE="orchestrate"; shift ;;
            --token) API_BEARER_TOKEN="$2"; shift 2 ;;
            --cookie-file) API_COOKIE_FILE="$2"; shift 2 ;;
            --max-endpoints) API_MAX_ENDPOINTS="$2"; shift 2 ;;
            --max-parallel) API_MAX_PARALLEL="$2"; shift 2 ;;
            --connect-timeout) API_CONNECT_TIMEOUT="$2"; shift 2 ;;
            --max-time) API_MAX_TIME="$2"; shift 2 ;;
            --skip) API_SKIP_PHASES="${API_SKIP_PHASES},$2,"; shift 2 ;;
            --resume) API_RESUME_DIR="$2"; shift 2 ;;
            --authorized) API_AUTHORIZED=1; shift ;;
            --aggressive-http) API_AGGRESSIVE_HTTP=1; shift ;;
            -h|--help) f_api_usage; exit 0 ;;
            *) echo "Unknown option: $1"; f_api_usage; exit 1 ;;
        esac
    done
}

###############################################################################################################################
# Main menu

f_api_main(){
    f_api_parse_cli "$@"

    if [ -n "$API_RESUME_DIR" ]; then
        OUTPUT_DIR="$API_RESUME_DIR"
        SCAN_STAMP=$(basename "$OUTPUT_DIR" | sed 's/api-scan_//')
    else
        SCAN_STAMP=$(date +%Y%m%d-%H%M)
        OUTPUT_DIR="$HOME/data/api-scan_${SCAN_STAMP}"
        mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] Cannot create $OUTPUT_DIR${NC}"; exit 1; }
    fi

    f_api_check_deps

    if [ -n "$API_CLI_URL" ]; then
        [[ "$API_CLI_URL" =~ ^https?:// ]] || { echo "Invalid URL"; exit 1; }
        if [ "$API_CLI_MODE" = "orchestrate" ]; then
            f_api_orchestrate "$API_CLI_URL"
        else
            f_api_run_scan "$API_CLI_URL"
        fi
        echo -e "${YELLOW}[*] Results: ${OUTPUT_DIR}/api_scanner/${NC}"
        echo -e "${YELLOW}[*] Reports: report.txt, report.md, findings.json${NC}"
        echo -e "${YELLOW}[*] Request log: ${OUTPUT_DIR}/api_scanner/scan.log${NC}"
        return 0
    fi

    clear
    f_banner
    echo -e "${BLUE}API Security Scanner${NC} | ${YELLOW}by ibrahimsql${NC}"
    echo
    echo "1. API Discovery and Testing (full)"
    echo "2. API Quick Scan (discovery + docs)"
    echo "3. JWT Token Analysis"
    echo "4. Full API Assessment (orchestrated)"
    echo "5. Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
        1)
            echo -n "Enter target URL: "
            read -r TARGET_URL
            [[ "$TARGET_URL" =~ ^https?:// ]] || { echo "Invalid URL"; exit 1; }
            echo -n "Bearer token (optional, Enter to skip): "
            read -r API_BEARER_TOKEN
            API_SCAN_MODE="full"
            f_api_run_scan "$TARGET_URL" ;;
        2)
            echo -n "Enter target URL: "
            read -r TARGET_URL
            [[ "$TARGET_URL" =~ ^https?:// ]] || { echo "Invalid URL"; exit 1; }
            API_SCAN_MODE="quick"
            f_api_run_scan "$TARGET_URL" ;;
        3)
            echo -n "Enter JWT token: "
            read -r JWT_TOKEN
            [[ "$JWT_TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]] || { echo "Invalid JWT"; exit 1; }
            f_jwt_analysis "$JWT_TOKEN" ;;
        4)
            echo -n "Enter target URL: "
            read -r TARGET_URL
            [[ "$TARGET_URL" =~ ^https?:// ]] || { echo "Invalid URL"; exit 1; }
            API_SCAN_MODE="full"
            f_api_orchestrate "$TARGET_URL" ;;
        5) f_main ;;
        *) f_error ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    f_api_main "$@"
fi