#!/usr/bin/env bash

# by ibrahimsql - API Security Scanner Module

clear
f_banner

# Variables
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

# Function to discover and test API endpoints
f_discover_api(){
    local TARGET_URL=$1
    local OUTPUT_DIR=$2

    echo
    echo -e "${BLUE}[*] Discovering API endpoints for $TARGET_URL.${NC}"

    # Create results directory
    mkdir -p "$OUTPUT_DIR/api_scanner"

    # Crawl for API endpoints
    echo -e "${BLUE}[*] Crawling target for API endpoints.${NC}"
    wget -q --spider -r --no-parent -l 2 "$TARGET_URL" 2>&1 | grep '^--' | awk '{ print $3 }' | grep -E '(/v[0-9]+/|/api/|/docs/|/graph|/graphql|/gql|/query|/rest/|/schema/service/|/swagger)' | sort -u > "$OUTPUT_DIR/api_scanner/endpoints.txt"

    # Check common API paths
    echo -e "${BLUE}[*] Checking common API paths.${NC}"

    # Common API paths
    cat > "$OUTPUT_DIR/api_scanner/api_paths.txt" << EOF
# Admin & Management
/admin/api
/api/admin
/api/console
/api/internal
/api/manage
/api/system
/console/api
/control/api
/manage/api
/management
/management/api

# API Schema Info
/api/model
/api/schema
/json-schema
/jsonschema
/metadata
/schema
/schema.graphql
/schema.json

# Authentication/User APIs
/api/account
/api/accounts
/api/auth
/api/authenticate
/api/login
/api/profile
/api/refresh
/api/token
/api/user
/api/users
/auth
/auth/login
/login
/oauth
/oauth/authorize
/oauth/token
/oauth2
/oauth2/authorize
/oauth2/token
/sso

# Common Resource Endpoints
/api/cart
/api/checkout
/api/comments
/api/config
/api/customers
/api/dashboard
/api/download
/api/events
/api/files
/api/images
/api/items
/api/logs
/api/messages
/api/notifications
/api/orders
/api/payments
/api/products
/api/reports
/api/search
/api/settings
/api/stats
/api/transactions
/api/upload

# GraphQL Endpoints
/gql
/graph
/graph/api
/graph/v1
/graphiql
/graphql
/graphql-api
/graphql/console
/graphql/explorer
/graphql/playground
/graphql/schema
/graphql/v1

# Health & Monitoring
/actuator/health
/api/health
/api/healthcheck
/api/metrics
/api/ping
/api/status
/health
/health-check
/healthcheck
/heartbeat
/isalive
/liveness
/metrics
/monitor
/monitoring
/ping
/readiness
/status

# REST API Base Paths
/api
/api/admin
/api/app
/api/backend
/api/client
/api/cloud
/api/core
/api/current
/api/data
/api/external
/api/gateway
/api/integration
/api/internal
/api/latest
/api/mobile
/api/open
/api/private
/api/public
/api/server
/api/service
/api/services
/api/stable
/api/system
/api/v1
/api/v2
/api/v3
/api/v4
/api/web
/apis
/apis/v1
/apis/v2

# RESTful Variants
/apirest
/rest
/rest/api
/rest/api/latest
/rest/api/v1
/rest/api/v2
/rest/v1
/rest/v2
/rest/v3
/restapi
/restapi/v1
/restapi/v2
/restful
/restful/api
/restservices
/restws

# Special Case APIs
/api/async
/api/batch
/api/callback
/api/jobs
/api/queue
/api/rpc
/api/stream
/api/webhook
/jsonrpc
/rpc
/soap
/wsdl

# Spring Boot Actuator Endpoints
/actuator
/actuator/beans
/actuator/config
/actuator/configprops
/actuator/env
/actuator/httptrace
/actuator/info
/actuator/loggers
/actuator/mappings
/actuator/metrics

# Swagger & API Documentation
/api-docs
/api-explorer
/api-guide
/api/docs
/api/documentation
/api/explorer
/api/spec
/api/swagger
/apidocs
/docs/api
/openapi
/openapi.json
/openapi.yaml
/openapi/v3
/specs
/specs/v1
/swagger
/swagger-resources
/swagger-ui
/swagger-ui.html
/swagger.json
/swagger.yaml
/swagger/index.html
/swagger/ui
/swagger/ui.html

# Version Paths
/v1
/v1.0
/v1.1
/v2
/v2.0
/v2.1
/v3
/v3.0
/v4
EOF

    # Test each path, ignoring comment lines
    echo -e "${BLUE}[*] Testing ${YELLOW}$(grep -v '^#' "$OUTPUT_DIR/api_scanner/api_paths.txt" | wc -l)${BLUE} API paths.${NC}"

    # Create a directory for storing responses
    mkdir -p "$OUTPUT_DIR/api_scanner/responses"

    # Prepare a user agent to mimic a browser
    USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

    # Counter for progress display
    TOTAL_PATHS=$(grep -v '^#' "$OUTPUT_DIR/api_scanner/api_paths.txt" | wc -l)
    CURRENT=0

    # Create an empty file to store found endpoints
    touch "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt"

    while read -r path; do
        # Skip comment and empty lines
        [[ "$PATH" =~ ^\s*# || -z "$PATH" ]] && continue

        # Increment counter
        ((CURRENT++))

        # Calculate percentage
        PERCENTAGE=$((CURRENT * 100 / TOTAL_PATHS))

        # Display progress
        echo -ne "${BLUE}[*] Testing: [${YELLOW}${PERCENTAGE}%${BLUE}] $PATH${NC}\r"

        URL="${TARGET_URL%/}$PATH"
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)

        # Check for success or interesting responses
        if [[ "$STATUS" == "200" || "$STATUS" == "201" || "$STATUS" == "204" || 
              "$STATUS" == "301" || "$STATUS" == "302" || "$STATUS" == "307" || 
              "$STATUS" == "401" || "$STATUS" == "403" ]]; then

            # Create safe filename from path
            SAFE_NAME=$(echo "$PATH" | sed 's/\//_/g')
            RESPONSE_FILE="$OUTPUT_DIR/api_scanner/responses/response$SAFE_NAME"

            # Store the status
            STATUS_MESSAGE=""
            case "$STATUS" in
                200|201|204) STATUS_MESSAGE="SUCCESS";;
                301|302|307) STATUS_MESSAGE="REDIRECT";;
                401) STATUS_MESSAGE="UNAUTHORIZED";;
                403) STATUS_MESSAGE="FORBIDDEN";;
            esac

            echo -e "\n${YELLOW}[*] Found API Endpoint: $URL ($STATUS - $STATUS_MESSAGE)${NC}"
            echo "$URL ($STATUS - $STATUS_MESSAGE)" >> "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt"

            # Get response and headers
            curl -s -i "$URL" -H "User-Agent: $USER_AGENT" -H "Accept: application/json, text/plain, */*" --connect-timeout 3 -m 7 > "$RESPONSE_FILE"

            # Try to detect if it's JSON
            grep -q "Content-Type:.*json" "$RESPONSE_FILE"
            is_json=$?

            if [[ $is_json -eq 0 ]]; then
                echo -e "${YELLOW}[*] JSON response detected${NC}"

                # Extract the body (remove headers)
                sed '1,/^\r\?$/d' "$RESPONSE_FILE" > "$RESPONSE_FILE.json"

                # Check if response is valid JSON
                jq . "$RESPONSE_FILE.json" &> /dev/null
                if [[ $? -eq 0 ]]; then
                    echo -e "${YELLOW}[*] Valid JSON response${NC}"

                    # If this is a GraphQL endpoint, try introspection
                    if [[ "$PATH" == *graphql* || "$PATH" == *gql* ]]; then
                        echo -e "${YELLOW}[*] Testing GraphQL endpoint for introspection.${NC}"
                        INTROSPECTION_QUERY='{"query":"{__schema{queryType{name}}}"}'
                        curl -s -X POST -H "Content-Type: application/json" -d "$INTROSPECTION_QUERY" "$URL" > "$OUTPUT_DIR/api_scanner/responses/graphql_introspection$SAFE_NAME.json"
                    fi
                else
                    echo -e "${YELLOW}[*] Invalid JSON response, might be protected or not a standard API${NC}"
                fi
            fi

            # Check for sensitive info in response
            grep -i -E "(api[-_]?key|auth|credential|key|password|secrettoken)" "$RESPONSE_FILE" > "$RESPONSE_FILE.sensitive" 2>/dev/null

            if [ -s "$RESPONSE_FILE.sensitive" ]; then
                echo -e "${RED}[!] Potential sensitive information leaked in API response!${NC}"
                echo "$URL" >> "$OUTPUT_DIR/api_scanner/sensitive_endpoints.txt"
            fi
        fi
    done < "$OUTPUT_DIR/api_scanner/api_paths.txt"

    echo -e "\n${BLUE}[*] API path scan complete.${NC}"

    # Count discovered endpoints
    ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" 2>/dev/null || echo "0")
    echo -e "${YELLOW}[*] Discovered $ENDPOINT_COUNT API endpoints${NC}"

    # Enhanced GraphQL Testing
    echo -e "${BLUE}[*] Performing enhanced GraphQL endpoint testing.${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/graphql"

    # Gather all potential GraphQL endpoints
    GRAPHQL_ENDPOINTS=$(grep -E '(graphql|gql)' "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" 2>/dev/null | cut -d ' ' -f1)

    if [ -n "$GRAPHQL_ENDPOINTS" ]; then
        echo -e "${YELLOW}[*] Found $(echo "$GRAPHQL_ENDPOINTS" | wc -l) potential GraphQL endpoints${NC}"

        while read -r GRAPHQL_URL; do
            [ -z "$GRAPHQL_URL" ] && continue

            echo -e "${BLUE}[*] Testing GraphQL endpoint: $GRAPHQL_URL${NC}"
            ENDPOINT_NAME=$(echo "$GRAPHQL_URL" | sed 's/https\?:\/\///' | sed 's/[\/:.]/_/g')

            # Test 1: Basic Introspection
            echo -e "${BLUE}[*] Testing introspection.${NC}"
            INTROSPECTION_QUERY='{"query":"{__schema{queryType{name}}}"}'
            curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$INTROSPECTION_QUERY" "$GRAPHQL_URL" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_introspection_basic.json"

            # Check if introspection is enabled
            if grep -q "__schema" "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_introspection_basic.json"; then
                echo -e "${RED}[!] GraphQL introspection is enabled (information disclosure vulnerability)${NC}"
                echo "$GRAPHQL_URL: Introspection enabled" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"

                # Test 2: Full Schema Introspection
                echo -e "${BLUE}[*] Getting full schema.${NC}"
                FULL_INTROSPECTION='{"query":"query IntrospectionQuery {__schema {queryType {name} mutationType {name} subscriptionType {name} types {kind name description fields(includeDeprecated: true) {name description args {name description type {kind name ofType {kind name ofType {kind name ofType {kind name}}}} defaultValue} type {kind name ofType {kind name ofType {kind name ofType {kind name}}}} isDeprecated deprecationReason} inputFields {name description type {kind name ofType {kind name ofType {kind name ofType {kind name}}}} defaultValue} interfaces {kind name ofType {kind name ofType {kind name ofType {kind name}}}} enumValues(includeDeprecated: true) {name description isDeprecated deprecationReason} possibleTypes {kind name ofType {kind name ofType {kind name ofType {kind name}}}}}}}"}'
                curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$FULL_INTROSPECTION" "$GRAPHQL_URL" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_schema_full.json"

                # Extract types and fields for analysis
                jq -r '.data.__schema.types[] | select(.kind == "OBJECT") | .name' "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_schema_full.json" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_types.txt" 2>/dev/null

                # Check for sensitive types
                grep -i -E '(user|admin|account|password|secret|token|auth|credential|key|payment|credit|card|personal|profile|address|private|internal)' "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_types.txt" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_sensitive_types.txt" 2>/dev/null

                if [ -s "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_sensitive_types.txt" ]; then
                    echo -e "${RED}[!] Potentially sensitive GraphQL types detected:${NC}"
                    cat "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_sensitive_types.txt" | sed 's/^/  - /'
                    echo "$GRAPHQL_URL: Sensitive types detected" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                fi

                # Test 3: Test for Direct Queries on Sensitive Types
                echo -e "${BLUE}[*] Testing sample queries for sensitive data.${NC}"
                while read -r type_name; do
                    # Get fields for this type
                    FIELDS=$(jq -r ".data.__schema.types[] | select(.name == \"$type_name\") | .fields[].name" "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_schema_full.json" 2>/dev/null | paste -sd "," -)

                    if [ -n "$FIELDS" ]; then
                        # Create a basic query for this type
                        QUERY_FIELDS=$(echo "$FIELDS" | sed 's/,/ /g' | awk '{for(i=1; i<=NF && i<=5; i++) printf "%s ", $i}')
                        TEST_QUERY="{\"query\":\"{${type_name}s{${QUERY_FIELDS}}}\"}"

                        # Try the query
                        curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$TEST_QUERY" "$GRAPHQL_URL" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_query_${type_name}.json"

                        # Check if query succeeded
                        if ! grep -q "errors" "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_query_${type_name}.json"; then
                            echo -e "${RED}[!] Successful query on sensitive type: $type_name${NC}"
                            echo "$GRAPHQL_URL: Successful query on $type_name" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                        fi
                    fi
                done < "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_sensitive_types.txt"

                # Test 4: NoSQL Injection Test (basic)
                echo -e "${BLUE}[*] Testing for basic NoSQL injection.${NC}"
                NOSQL_TEST_QUERY='{"query":"{user(id:{\\\"$gt\\\":\\\"\\\"}){username}}"}'
                curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$NOSQL_TEST_QUERY" "$GRAPHQL_URL" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_nosql_test.json"

                # Check for successful injection (highly dependent on implementation)
                if ! grep -q "errors" "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_nosql_test.json" && \
                   ! grep -q "syntax" "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_nosql_test.json"; then
                    echo -e "${RED}[!] Potential NoSQL injection vulnerability${NC}"
                    echo "$GRAPHQL_URL: Potential NoSQL injection" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                fi
            else
                echo -e "${YELLOW}[*] GraphQL introspection is properly disabled${NC}"

                # Test 5: Try common queries blindly
                echo -e "${BLUE}[*] Testing common GraphQL queries.${NC}"

                # Array of common queries to try
                common_queries=(
                    '{"query":"{users{id username email}}"}'
                    '{"query":"{user(id:1){id username email}}"}'
                    '{"query":"{me{id username email}}"}'
                    '{"query":"{products{id name price}}"}'
                    '{"query":"{orders{id status}}"}'
                )

                for (( i=0; i<${#common_queries[@]}; i++ )); do
                    QUERY=${common_queries[$i]}
                    QUERY_NAME="query_$(($i+1))"

                    curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$QUERY" "$GRAPHQL_URL" > "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_${QUERY_NAME}.json"

                    # If query succeeds (no errors field)
                    if ! grep -q "errors" "$OUTPUT_DIR/api_scanner/graphql/${ENDPOINT_NAME}_${QUERY_NAME}.json"; then
                        echo -e "${YELLOW}[!] Successful blind query: ${QUERY_NAME}${NC}"
                        echo "$GRAPHQL_URL: Successful blind query: ${QUERY_NAME}" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                    fi
                done
            fi
        done <<< "$GRAPHQL_ENDPOINTS"
    else
        echo -e "${BLUE}[*] No GraphQL endpoints found${NC}"
    fi

    # Enhanced Swagger/OpenAPI Documentation Check
    echo -e "${BLUE}[*] Performing comprehensive check for API documentation.${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/documentation"

    # More complete paths for API documentation
    swagger_paths=(
        "/api-doc"
        "/api-docs"
        "/api-explorer"
        "/api-schema"
        "/api/docs"
        "/api/documentation"
        "/api/explorer"
        "/api/schema"
        "/api/specs"
        "/api/swagger"
        "/apidocs"
        "/docs"
        "/docs/api"
        "/docs/swagger.json"
        "/docs/swagger.yaml"
        "/openapi.json"
        "/openapi.yaml"
        "/openapi"
        "/redoc"
        "/specs"
        "/swagger-resources"
        "/swagger-ui.html"
        "/swagger-ui"
        "/swagger.json"
        "/swagger.yaml"
        "/swagger"
        "/swagger/index.html"
        "/swagger/ui.html"
        "/swagger/ui"
        "/v1/api-docs"
        "/v2/api-docs"
        "/v3/api-docs"
    )

    echo -e "${BLUE}[*] Testing ${#swagger_paths[@]} potential documentation paths.${NC}"

    # Counter for progress display
    TOTAL_PATHS=${#swagger_paths[@]}
    CURRENT=0
    FOUND_DOCS=0

    for path in "${swagger_paths[@]}"; do
        # Increment counter
        ((CURRENT++))

        # Calculate percentage
        PERCENTAGE=$((CURRENT * 100 / TOTAL_PATHS))

        # Display progress
        echo -ne "${BLUE}[*] Testing doc path: [${YELLOW}${PERCENTAGE}%${BLUE}] $PATH${NC}\r"

        URL="${TARGET_URL%/}$PATH"
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)

        if [[ "$STATUS" == "200" ]]; then
            # Create a safe filename
            SAFE_PATH=$(echo "$PATH" | sed 's/\//./g')

            # Check file type and save accordingly
            echo -e "\n${RED}[!] API documentation found at $URL ($STATUS)${NC}"
            curl -s "$URL" -H "User-Agent: $USER_AGENT" > "$OUTPUT_DIR/api_scanner/documentation/api_doc${SAFE_PATH}.txt"

            # Check if it's JSON format
            if grep -q "swagger\|openapi" "$OUTPUT_DIR/api_scanner/documentation/api_doc${SAFE_PATH}.txt"; then
                echo -e "${RED}[!] Valid API specification found (Swagger/OpenAPI)${NC}"

                # Try to extract version info
                if grep -q "\"swagger\":\|\"openapi\":" "$OUTPUT_DIR/api_scanner/documentation/api_doc${SAFE_PATH}.txt"; then
                    VERSION=$(grep -o '"\(swagger\|openapi\)":[[:space:]]*"[^"]*"' "$OUTPUT_DIR/api_scanner/documentation/api_doc${SAFE_PATH}.txt" | head -1)
                    echo -e "${YELLOW}[*] API Specification version: ${VERSION:-Unknown}${NC}"
                fi

                # Try to get endpoints count
                ENDPOINTS_COUNT=$(grep -o '"paths"\|"endpoints"' "$OUTPUT_DIR/api_scanner/documentation/api_doc${SAFE_PATH}.txt" | wc -l)
                if [ "$ENDPOINTS_COUNT" -gt 0 ]; then
                    echo -e "${YELLOW}[*] Specification contains endpoint definitions${NC}"

                    # Extract endpoints if possible
                    if command -v jq &> /dev/null; then
                        jq -r '.paths | keys[]' "$OUTPUT_DIR/api_scanner/documentation/api_doc${SAFE_PATH}.txt" > "$OUTPUT_DIR/api_scanner/documentation/extracted_endpoints${SAFE_PATH}.txt" 2>/dev/null
                        ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/api_scanner/documentation/extracted_endpoints${SAFE_PATH}.txt" 2>/dev/null || echo 0)
                        if [ "$ENDPOINT_COUNT" -gt 0 ]; then
                            echo -e "${YELLOW}[*] Extracted $ENDPOINT_COUNT API endpoints from documentation${NC}"

                            # Add to our endpoints list for testing
                            while read -r endpoint; do
                                echo "${TARGET_URL%/}$ENDPOINT" >> "$OUTPUT_DIR/api_scanner/all_endpoints.txt"
                            done < "$OUTPUT_DIR/api_scanner/documentation/extracted_endpoints${SAFE_PATH}.txt"
                        fi
                    fi
                fi
                echo "$URL: API documentation" >> "$OUTPUT_DIR/api_scanner/findings.txt"
            fi

            ((FOUND_DOCS++))
        fi
    done

    echo -e "\n${BLUE}[*] Documentation scan complete. Found $FOUND_DOCS documents.${NC}"

    # Enhanced CORS Misconfiguration Testing
    echo -e "${BLUE}[*] Performing comprehensive CORS security testing.${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/cors"

    # Prepare a list of origins to test with
    cat > "$OUTPUT_DIR/api_scanner/cors/test_origins.txt" << EOF
http://target.com
https://target.com
null
file://
https://attacker.target.com
https://${TARGET_URL#*//}.target.com
https://subdomain.${TARGET_URL#*//}
data:
https://\\${TARGET_URL#*//}
https://attacker.com%60javascript:alert(1)
https://target.com\@${TARGET_URL#*//}
EOF

    # Combine all endpoints
    cat "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" 2>/dev/null | cut -d ' ' -f1 > "$OUTPUT_DIR/api_scanner/all_endpoints.txt" 2>/dev/null

    ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/api_scanner/all_endpoints.txt" 2>/dev/null || echo "0")
    echo -e "${BLUE}[*] Testing CORS policies on $ENDPOINT_COUNT endpoints.${NC}"

    CURRENT=0
    CORS_VULNS=0

    # Create headers file for output
    touch "$OUTPUT_DIR/api_scanner/cors/cors_headers.txt"
    touch "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"

    while read -r ENDPOINT; do
        [ -z "$ENDPOINT" ] && continue

        # Increment counter
        ((CURRENT++))

        # Calculate percentage
        PERCENTAGE=$((CURRENT * 100 / ENDPOINT_COUNT))

        # Display progress
        echo -ne "${BLUE}[*] Testing CORS: [${YELLOW}${PERCENTAGE}%${BLUE}] $ENDPOINT${NC}\r"

        ENDPOINT_SAFE=$(echo "$ENDPOINT" | sed 's/[:\/]/_/g')

        # Test each origin
        while read -r ORIGIN; do
            [ -z "$ORIGIN" ] && continue

            # Skip testing if we've already found a vulnerability for this endpoint
            if grep -q "^$ENDPOINT" "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" 2>/dev/null; then
                continue
            fi

            CORS_RESPONSE=$(curl -s -I -H "Origin: $ORIGIN" "$ENDPOINT" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
            echo "$CORS_RESPONSE" > "$OUTPUT_DIR/api_scanner/cors/headers_${ENDPOINT_SAFE}_${origin//[:\/]/_}.txt"

            # Check for various CORS vulnerabilities
            if echo "$CORS_RESPONSE" | grep -i "access-control-allow-origin: $ORIGIN" &>/dev/null; then
                echo -e "\n${RED}[!] CORS Vulnerability: $ENDPOINT allows requests from arbitrary origin: $ORIGIN${NC}"
                echo "$ENDPOINT - Allows arbitrary origin: $ORIGIN" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                ((CORS_VULNS++))

                # Check for allow-credentials
                if echo "$CORS_RESPONSE" | grep -i "access-control-allow-credentials: true" &>/dev/null; then
                    echo -e "${RED}[!] HIGH Severity: Allows credentials with specific arbitrary origin${NC}"
                    echo "$ENDPOINT - HIGH: Allows credentials with arbitrary origin: $ORIGIN" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                fi

                # No need to check other origins for this endpoint
                break
            fi

            # Check for wildcard
            if echo "$CORS_RESPONSE" | grep -i "access-control-allow-origin: \*" &>/dev/null; then
                echo -e "\n${YELLOW}[!] CORS Warning: $ENDPOINT allows requests from any origin (*)${NC}"
                echo "$ENDPOINT - Allows any origin (*)" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                ((CORS_VULNS++))

                # Check for credentials with wildcard (severe security issue)
                if echo "$CORS_RESPONSE" | grep -i "access-control-allow-credentials: true" &>/dev/null; then
                    echo -e "${RED}[!] CRITICAL: Allows credentials with wildcard origin (severe configuration error)${NC}"
                    echo "$ENDPOINT - CRITICAL: Allows credentials with wildcard origin" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                fi

                # No need to check other origins for this endpoint
                break
            fi
        done < "$OUTPUT_DIR/api_scanner/cors/test_origins.txt"
    done < "$OUTPUT_DIR/api_scanner/all_endpoints.txt"

    echo -e "\n${BLUE}[*] CORS testing complete. Found $CORS_VULNS vulnerabilities.${NC}"

    # API Security Testing
    echo -e "${BLUE}[*] Performing additional API security tests.${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/security"

    # Test for HTTP methods allowed (VERB tampering)
    echo -e "${BLUE}[*] Testing HTTP method handling.${NC}"

    # Take sample of endpoints to test (max 10 to avoid excessive requests)
    head -10 "$OUTPUT_DIR/api_scanner/all_endpoints.txt" > "$OUTPUT_DIR/api_scanner/sample_endpoints.txt"

    HTTP_METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE" "CONNECT")

    while read -r ENDPOINT; do
        [ -z "$ENDPOINT" ] && continue

        ENDPOINT_SAFE=$(echo "$ENDPOINT" | sed 's/[:\/]/_/g')
        echo -e "${BLUE}[*] Testing HTTP methods on: $ENDPOINT${NC}"

        # First get OPTIONS to check declared allowed methods
        OPTIONS_RESPONSE=$(curl -s -I -X OPTIONS "$ENDPOINT" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
        echo "$OPTIONS_RESPONSE" > "$OUTPUT_DIR/api_scanner/security/options_${ENDPOINT_SAFE}.txt"

        # Extract allowed methods from OPTIONS response
        ALLOWED_METHODS=$(echo "$OPTIONS_RESPONSE" | grep -i "Allow\|Access-Control-Allow-Methods" | cut -d ':' -f2- || echo "None specified")
        echo "Declared allowed methods: $ALLOWED_METHODS" > "$OUTPUT_DIR/api_scanner/security/methods_${ENDPOINT_SAFE}.txt"

        # Test each method
        for METHOD in "${HTTP_METHODS[@]}"; do
            STATUS=$(curl -s -o "$OUTPUT_DIR/api_scanner/security/response_${ENDPOINT_SAFE}_${METHOD}.txt" -w "%{http_code}" -X "$METHOD" "$ENDPOINT" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
            echo "$METHOD: $STATUS" >> "$OUTPUT_DIR/api_scanner/security/methods_${ENDPOINT_SAFE}.txt"

            # Check for successful status codes with potentially dangerous methods
            if [[ "$METHOD" != "GET" && "$METHOD" != "HEAD" && "$METHOD" != "OPTIONS" ]] && \
               [[ "$STATUS" == "200" || "$STATUS" == "201" || "$STATUS" == "202" || "$STATUS" == "204" ]]; then
                echo -e "${RED}[!] Potentially unsafe HTTP method $METHOD allowed on $ENDPOINT${NC}"
                echo "$ENDPOINT - Unsafe method $METHOD returned $STATUS" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
            fi
        done
    done < "$OUTPUT_DIR/api_scanner/sample_endpoints.txt"

    # Test for missing rate limiting
    echo -e "${BLUE}[*] Testing for rate limiting.${NC}"
    RATE_TEST_ENDPOINT=$(head -1 "$OUTPUT_DIR/api_scanner/all_endpoints.txt")

    if [ -n "$RATE_TEST_ENDPOINT" ]; then
        echo -e "${BLUE}[*] Testing rate limiting on: $RATE_TEST_ENDPOINT${NC}"

        # Make 20 rapid requests
        for i in {1..20}; do
            echo -ne "${BLUE}[*] Rate limit test: request $i/20${NC}\r"
            curl -s -I "$RATE_TEST_ENDPOINT" -H "User-Agent: $USER_AGENT" --connect-timeout 2 -m 3 > "$OUTPUT_DIR/api_scanner/security/rate_limit_${i}.txt"
            # Small sleep to avoid completely hammering the server
            sleep 0.2
        done

        # Check for rate limiting headers
        if grep -q -i "rate\|limit\|quota\|throttle" "$OUTPUT_DIR/api_scanner/security/rate_limit_*.txt"; then
            echo -e "\n${YELLOW}[*] Rate limiting appears to be implemented${NC}"
            echo "Rate limiting implemented" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        else
            echo -e "\n${YELLOW}[!] No evidence of rate limiting found${NC}"
            echo "$RATE_TEST_ENDPOINT - No evidence of rate limiting" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        fi
    fi

    # Authentication Analysis
    echo -e "${BLUE}[*] Performing authentication analysis.${NC}"

    # Check for authentication headers
    if [ -n "$RATE_TEST_ENDPOINT" ]; then
        AUTH_RESPONSE=$(curl -s -I "$RATE_TEST_ENDPOINT" -H "User-Agent: $USER_AGENT")

        # Check for WWW-Authenticate header
        if echo "$AUTH_RESPONSE" | grep -i "www-authenticate" &>/dev/null; then
            AUTH_TYPE=$(echo "$AUTH_RESPONSE" | grep -i "www-authenticate" | awk '{print $2}' | tr -d '"')
            echo -e "${YELLOW}[!] Authentication required: $AUTH_TYPE${NC}"
            echo "$RATE_TEST_ENDPOINT - Authentication type: $AUTH_TYPE" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        fi

        # Check for common authorization headers in responses
        if echo "$AUTH_RESPONSE" | grep -i "authorization\|x-api-key\|api-key" &>/dev/null; then
            echo -e "${RED}[!] Authorization headers in response - potential information disclosure${NC}"
            echo "$RATE_TEST_ENDPOINT - Authorization headers exposed" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        fi
    fi

    # JWT Token Testing
    echo -e "${BLUE}[*] Testing for JWT token vulnerabilities.${NC}"

    # Check if we can find JWT tokens in any of the responses
    find "$OUTPUT_DIR/api_scanner" -type f -name "*.txt" -o -name "*.json" | xargs grep -l "eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" > "$OUTPUT_DIR/api_scanner/jwt_found.txt"

    if [ -s "$OUTPUT_DIR/api_scanner/jwt_found.txt" ]; then
        echo -e "${YELLOW}[!] Found JWT tokens in responses${NC}"

        # Extract and analyze each token
        cat "$OUTPUT_DIR/api_scanner/jwt_found.txt" | while read -r file; do
            grep -o "eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" "$file" | while read -r TOKEN; do
                echo -e "${BLUE}[*] Analyzing JWT token: ${TOKEN:0:20}.${NC}"

                # Decode header
                HEADER=$(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | tr -d '\0')

                # Check for weak algorithms
                if echo "$HEADER" | grep -q '"alg":"none\|"alg":"HS256\|"alg":"HS1"'; then
                    echo -e "${RED}[!] JWT using weak algorithm: $(echo "$HEADER" | grep -o '"alg":"[^"]*"')${NC}"
                    echo "JWT with weak algorithm found: $(echo "$HEADER" | grep -o '"alg":"[^"]*"')" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
                fi

                # Decode payload
                PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | tr -d '\0')

                # Check for sensitive data in payload
                if echo "$PAYLOAD" | grep -q '"password\|"api_key\|"secret\|"private'; then
                    echo -e "${RED}[!] JWT contains sensitive data in payload${NC}"
                    echo "JWT with sensitive data in payload" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
                fi

                # Save decoded token
                echo "Header: $HEADER" > "$OUTPUT_DIR/api_scanner/security/jwt_decoded_${TOKEN:0:10}.txt"
                echo "Payload: $PAYLOAD" >> "$OUTPUT_DIR/api_scanner/security/jwt_decoded_${TOKEN:0:10}.txt"
            done
        done
    else
        echo -e "${BLUE}[*] No JWT tokens found in responses${NC}"
    fi

    # Generate Enhanced Summary Report
    echo -e "${BLUE}[*] Generating comprehensive summary report.${NC}"

    cat > "$OUTPUT_DIR/api_scanner/summary_report.txt" << EOF
==========================================================================
                 API SECURITY SCANNER REPORT
==========================================================================
Target: $TARGET_URL
Scan Date: $(date)
Scan ID: $(date +%s)
==========================================================================

EXECUTIVE SUMMARY
----------------
Total API Endpoints Discovered: $(wc -l < "$OUTPUT_DIR/api_scanner/all_endpoints.txt" 2>/dev/null || echo "0")
API Documentation Resources Found: $FOUND_DOCS
GraphQL Endpoints: $(grep -c graphql "$OUTPUT_DIR/api_scanner/all_endpoints.txt" 2>/dev/null || echo "0")
Vulnerable Endpoints Found: $(( $(wc -l < "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" 2>/dev/null || echo "0") + $(grep -c "vulnerability\|unsafe\|sensitive" "$OUTPUT_DIR/api_scanner/security_findings.txt" 2>/dev/null || echo "0") + $(grep -c "Introspection enabled\|Sensitive types\|Successful query\|NoSQL injection" "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt" 2>/dev/null || echo "0") ))

KEY FINDINGS
------------
EOF

    # Add CORS findings
    echo "CORS SECURITY ISSUES:" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    if [ -f "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" ] && [ -s "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" ]; then
        cat "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" | sed 's/^/  - /' >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    else
        echo "  - No CORS vulnerabilities found" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    fi

    echo "" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"

    # Add GraphQL findings
    echo "GRAPHQL SECURITY ISSUES:" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    if [ -f "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt" ] && [ -s "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt" ]; then
        cat "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt" | sed 's/^/  - /' >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    else
        echo "  - No GraphQL vulnerabilities found" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    fi

    echo "" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"

    # Add API Documentation findings
    echo "API DOCUMENTATION:" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    if [ "$FOUND_DOCS" -gt 0 ]; then
        grep -h ": API documentation" "$OUTPUT_DIR/api_scanner/findings.txt" 2>/dev/null | sed 's/^/  - /' >> "$OUTPUT_DIR/api_scanner/summary_report.txt" || echo "  - API documentation found but with unknown format" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    else
        echo "  - No API documentation found" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    fi

    echo "" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"

    # Add Security Testing findings
    echo "API SECURITY TESTING RESULTS:" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    if [ -f "$OUTPUT_DIR/api_scanner/security_findings.txt" ] && [ -s "$OUTPUT_DIR/api_scanner/security_findings.txt" ]; then
        cat "$OUTPUT_DIR/api_scanner/security_findings.txt" | sed 's/^/  - /' >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    else
        echo "  - No additional security issues found" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    fi

    echo "" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"

    # Discovered endpoints summary
    echo "DISCOVERED API ENDPOINTS:" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    if [ -f "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" ] && [ -s "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" ]; then
        head -20 "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" | sed 's/^/  - /' >> "$OUTPUT_DIR/api_scanner/summary_report.txt"

        # If there are more than 20 endpoints, indicate that
        ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt")
        if [ "$ENDPOINT_COUNT" -gt 20 ]; then
            echo "  - ... and $(($ENDPOINT_COUNT - 20)) more endpoints (see full list in found_api_endpoints.txt)" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
        fi
    else
        echo "  - No API endpoints found" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
    fi

    # Add recommendations section
    cat >> "$OUTPUT_DIR/api_scanner/summary_report.txt" << EOF

RECOMMENDATIONS
--------------
1. API Documentation: $([ "$FOUND_DOCS" -gt 0 ] && echo "Restrict access to API documentation in production environments." || echo "No issues found.")
2. CORS Policy: $(grep -q ". CORS" "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" 2>/dev/null && echo "Fix CORS configuration to only allow trusted origins and never use wildcards with credentials." || echo "No issues found.")
3. GraphQL Security: $(grep -q "GraphQL" "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt" 2>/dev/null && echo "Disable introspection in production and implement proper authorization checks." || echo "No issues found.")
4. Rate Limiting: $(grep -q "No evidence of rate limiting" "$OUTPUT_DIR/api_scanner/security_findings.txt" 2>/dev/null && echo "Implement proper rate limiting to prevent API abuse." || echo "Continue monitoring for abuse.")
5. HTTP Methods: $(grep -q "Unsafe method" "$OUTPUT_DIR/api_scanner/security_findings.txt" 2>/dev/null && echo "Restrict HTTP methods to only those required for each endpoint." || echo "Properly configured.")
6. JWT Tokens: $(grep -q "JWT with weak algorithm" "$OUTPUT_DIR/api_scanner/security_findings.txt" 2>/dev/null && echo "Use strong algorithms for JWT tokens and avoid storing sensitive data in the payload." || echo "No issues found with tokens.")

==========================================================================
Report generated by API Security Scanner v2.0
==========================================================================
EOF

    echo -e "${YELLOW}[*] API scan complete. Results saved to $OUTPUT_DIR/api_scanner/${NC}"
    echo -e "${YELLOW}[*] Comprehensive summary report: $OUTPUT_DIR/api_scanner/summary_report.txt${NC}"
}

###############################################################################################################################

# Function for JWT token analysis
f_jwt_analysis(){
    local JWT=$1
    local OUTPUT_DIR=$2

    echo -e "${BLUE}[*] Analyzing JWT token.${NC}"
    echo

    # Split JWT into header, payload, and signature
    HEADER=$(echo "$JWT" | cut -d '.' -f1)
    PAYLOAD=$(echo "$JWT" | cut -d '.' -f2)

    # Decode header and payload
    echo -e "${BLUE}[*] Decoding header.${NC}"
    echo "$HEADER" | base64 -d 2>/dev/null | jq . > "$OUTPUT_DIR/jwt_header.json" || echo "$HEADER" > "$OUTPUT_DIR/jwt_header.json"

    echo -e "${BLUE}[*] Decoding payload.${NC}"
    echo "$PAYLOAD" | base64 -d 2>/dev/null | jq . > "$OUTPUT_DIR/jwt_payload.json" || echo "$PAYLOAD" > "$OUTPUT_DIR/jwt_payload.json"

    # Check for weak algorithm
    if grep -q '"alg":\s*"none"' "$OUTPUT_DIR/jwt_header.json"; then
        echo -e "${RED}[!] CRITICAL: JWT uses 'none' algorithm (alg:none vulnerability)${NC}"
    fi

    if grep -q '"alg":\s*"HS256"' "$OUTPUT_DIR/jwt_header.json"; then
        echo -e "${YELLOW}[!] WARNING: JWT uses HMAC-SHA256 algorithm which may be vulnerable to brute force if weak key is used${NC}"
    fi

    # Check for sensitive info in payload
    echo -e "${BLUE}[*] Checking for sensitive information in payload.${NC}"
    grep -E "(auth|credential|key|password|secret|token)" "$OUTPUT_DIR/jwt_payload.json" > "$OUTPUT_DIR/jwt_sensitive.txt"

    if [ -s "$OUTPUT_DIR/jwt_sensitive.txt" ]; then
        echo -e "${RED}[!] CRITICAL: JWT contains potentially sensitive information${NC}"
        cat "$OUTPUT_DIR/jwt_sensitive.txt"
    fi

    # Check for expiration
    if ! grep -q '"exp"' "$OUTPUT_DIR/jwt_payload.json"; then
        echo -e "${RED}[!] CRITICAL: JWT does not have an expiration claim (exp)${NC}"
    fi

    # Generate summary
    {
        echo "JWT Token Analysis"
        echo "==================="
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo
        echo "Header:"
        cat "$OUTPUT_DIR/jwt_header.json"
        echo
        echo "Payload:"
        cat "$OUTPUT_DIR/jwt_payload.json"
        echo

        echo "Security Issues:"
        if grep -q '"alg":\s*"none"' "$OUTPUT_DIR/jwt_header.json"; then
            echo "- CRITICAL: JWT uses 'none' algorithm (alg:none vulnerability)"
        fi

        if grep -q '"alg":\s*"HS256"' "$OUTPUT_DIR/jwt_header.json"; then
            echo "- WARNING: JWT uses HMAC-SHA256 algorithm which may be vulnerable to brute force if weak key is used"
        fi

        if [ -s "$OUTPUT_DIR/jwt_sensitive.txt" ]; then
            echo "- CRITICAL: JWT contains potentially sensitive information:"
            cat "$OUTPUT_DIR/jwt_sensitive.txt"
        fi

        if ! grep -q '"exp"' "$OUTPUT_DIR/jwt_payload.json"; then
            echo "- CRITICAL: JWT does not have an expiration claim (exp)"
        fi
    } > "$OUTPUT_DIR/jwt_analysis.txt"

    echo -e "${YELLOW}[*] JWT analysis complete. Results saved to $OUTPUT_DIR/jwt_analysis.txt${NC}"
}

###############################################################################################################################

# Main function
f_api_main(){
    echo -e "${BLUE}API Security Scanner${NC} | ${YELLOW}by ibrahimsql${NC}"
    echo
    echo "1. API Endpoint Discovery and Testing"
    echo "2. JWT Token Analysis"
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

            f_discover_api "$TARGET_URL" "$NAME" ;;
        2)
            echo
            echo -n "Enter JWT token to analyze: "
            read -r JWT_TOKEN

            if [[ ! "$JWT_TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
                echo
                echo -e "${RED}[!] Invalid JWT format. Must be in format 'header.payload.signature'${NC}"
                echo
                exit 1
            fi

            f_jwt_analysis "$JWT_TOKEN" "$NAME" ;;
        3)
            f_main ;;
        *)
            echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; clear && f_banner && f_api_main ;;
    esac
}

# Run the script
f_api_main
