#!/usr/bin/env bash

# by ibrahimsql - API Security Scanner Module
# Discover framework compatibility module

echo
echo "$MEDIUM"
echo
echo "API Security Scanner"
echo "$MEDIUM"
echo

# Global settings
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

# Function for JWT token analysis
f_jwt_analysis() {
    local JWT=$1
    local OUTPUT_DIR=$2
    
    echo -e "${BLUE}[*] Analyzing JWT token...${NC}"
    echo
    
    # Split JWT into header, payload, and signature
    HEADER=$(echo "$JWT" | cut -d '.' -f1)
    PAYLOAD=$(echo "$JWT" | cut -d '.' -f2)
    
    # Decode header and payload
    echo -e "${BLUE}[*] Decoding header...${NC}"
    echo "$HEADER" | base64 -d 2>/dev/null | jq . > "$OUTPUT_DIR/jwt_header.json" || echo "$HEADER" > "$OUTPUT_DIR/jwt_header.json"
    
    echo -e "${BLUE}[*] Decoding payload...${NC}"
    echo "$PAYLOAD" | base64 -d 2>/dev/null | jq . > "$OUTPUT_DIR/jwt_payload.json" || echo "$PAYLOAD" > "$OUTPUT_DIR/jwt_payload.json"
    
    # Check for weak algorithm
    if grep -q '"alg":\s*"none"' "$OUTPUT_DIR/jwt_header.json"; then
        echo -e "${RED}[!] CRITICAL: JWT uses 'none' algorithm (alg:none vulnerability)${NC}"
    fi
    
    if grep -q '"alg":\s*"HS256"' "$OUTPUT_DIR/jwt_header.json"; then
        echo -e "${YELLOW}[!] WARNING: JWT uses HMAC-SHA256 algorithm which may be vulnerable to brute force if weak key is used${NC}"
    fi
    
    # Check for sensitive info in payload
    echo -e "${BLUE}[*] Checking for sensitive information in payload...${NC}"
    grep -E "(password|secret|key|token|credential|auth)" "$OUTPUT_DIR/jwt_payload.json" > "$OUTPUT_DIR/jwt_sensitive.txt"
    
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
    
    echo -e "${GREEN}[*] JWT analysis complete. Results saved to $OUTPUT_DIR/jwt_analysis.txt${NC}"
}

# Function to discover and test API endpoints
f_discover_api() {
    local TARGET_URL=$1
    local OUTPUT_DIR=$2
    
    echo -e "${BLUE}[*] Discovering API endpoints for $TARGET_URL...${NC}"
    echo
    
    # Create directories
    mkdir -p "$OUTPUT_DIR/api_scanner"
    
    # Crawl for API endpoints
    echo -e "${BLUE}[*] Crawling target for API endpoints...${NC}"
    wget -q --spider -r --no-parent -l 2 "$TARGET_URL" 2>&1 | grep '^--' | awk '{ print $3 }' | grep -E '(/api/|/rest/|/v[0-9]+/|/service/|/graphql|/graph|/gql|/query|/swagger|/docs/|/schema)' | sort -u > "$OUTPUT_DIR/api_scanner/endpoints.txt"
    
    # Check common API paths
    echo -e "${BLUE}[*] Checking common API paths...${NC}"
    
    # Common API paths
    cat > "$OUTPUT_DIR/api_scanner/api_paths.txt" << EOF
# REST API Base Paths
/api
/api/v1
/api/v2
/api/v3
/api/v4
/api/latest
/api/current
/api/stable
/api/core
/api/public
/api/private
/api/internal
/api/external
/api/open
/api/system
/api/service
/api/services
/api/backend
/api/web
/api/mobile
/api/app
/api/client
/api/server
/api/cloud
/api/admin
/api/data
/api/integration
/api/gateway
/apis
/apis/v1
/apis/v2

# RESTful Variants
/rest
/rest/v1
/rest/v2
/rest/v3
/rest/api
/rest/api/v1
/rest/api/v2
/rest/api/latest
/restapi
/restapi/v1
/restapi/v2
/restful
/restful/api
/restservices
/restws
/apirest

# GraphQL Endpoints
/graphql
/graphiql
/gql
/graph
/graph/api
/graph/v1
/graphql/v1
/graphql/console
/graphql/explorer
/graphql/playground
/graphql-api
/graphql/schema

# Version Paths
/v1
/v2
/v3
/v4
/v1.0
/v2.0
/v3.0
/v1.1
/v2.1

# Swagger & API Documentation
/swagger
/swagger-ui
/swagger-ui.html
/swagger/ui
/swagger/ui.html
/swagger/index.html
/swagger-resources
/swagger.json
/swagger.yaml
/api-docs
/api/docs
/api-explorer
/api/explorer
/api/swagger
/apidocs
/api-guide
/api/spec
/openapi
/openapi.json
/openapi.yaml
/openapi/v3
/docs/api
/api/documentation
/specs
/specs/v1

# API Schema Info
/schema
/schema.json
/schema.graphql
/json-schema
/jsonschema
/metadata
/api/schema
/api/model

# Health & Monitoring
/health
/healthcheck
/health-check
/api/health
/api/healthcheck
/actuator/health
/status
/api/status
/ping
/api/ping
/isalive
/metrics
/api/metrics
/monitor
/monitoring
/heartbeat
/liveness
/readiness

# Spring Boot Actuator Endpoints
/actuator
/actuator/info
/actuator/env
/actuator/beans
/actuator/config
/actuator/configprops
/actuator/mappings
/actuator/metrics
/actuator/loggers
/actuator/httptrace

# Authentication/User APIs
/auth
/auth/login
/api/auth
/api/login
/api/user
/api/users
/api/account
/api/accounts
/api/profile
/api/token
/api/refresh
/oauth
/oauth/token
/oauth/authorize
/oauth2
/oauth2/token
/oauth2/authorize
/sso
/login
/api/authenticate

# Common Resource Endpoints
/api/customers
/api/products
/api/orders
/api/items
/api/transactions
/api/payments
/api/cart
/api/checkout
/api/search
/api/upload
/api/download
/api/files
/api/images
/api/notifications
/api/events
/api/messages
/api/comments
/api/settings
/api/config
/api/logs
/api/stats
/api/reports
/api/dashboard

# Admin & Management
/admin/api
/api/admin
/manage/api
/management
/management/api
/console/api
/api/console
/api/manage
/api/internal
/api/system
/control/api

# Special Case APIs
/api/callback
/api/webhook
/api/rpc
/api/batch
/api/stream
/api/async
/api/queue
/api/jobs
/jsonrpc
/rpc
/soap
/wsdl
EOF
    
    # Test each path, ignoring comment lines
    echo -e "${BLUE}[*] Testing ${YELLOW}$(grep -v '^#' "$OUTPUT_DIR/api_scanner/api_paths.txt" | wc -l)${BLUE} API paths...${NC}"
    
    # Create a directory for storing responses
    mkdir -p "$OUTPUT_DIR/api_scanner/responses"
    
    # Prepare a user agent to mimic a browser
    USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    
    # Counter for progress display
    TOTAL_PATHS=$(grep -v '^#' "$OUTPUT_DIR/api_scanner/api_paths.txt" | wc -l)
    CURRENT=0
    
    # Create an empty file to store found endpoints
    > "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt"
    
    while read -r path; do
        # Skip comment and empty lines
        [[ "$path" =~ ^\s*# || -z "$path" ]] && continue
        
        # Increment counter
        ((CURRENT++))
        
        # Calculate percentage
        PERCENTAGE=$((CURRENT * 100 / TOTAL_PATHS))
        
        # Display progress
        echo -ne "${BLUE}[*] Testing: [${YELLOW}${PERCENTAGE}%${BLUE}] $path${NC}\r"
        
        url="${TARGET_URL%/}$path"
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
        
        # Check for success or interesting responses
        if [[ "$status" == "200" || "$status" == "201" || "$status" == "204" || 
              "$status" == "301" || "$status" == "302" || "$status" == "307" || 
              "$status" == "401" || "$status" == "403" ]]; then
            
            # Create safe filename from path
            safe_name=$(echo "$path" | sed 's/\//_/g')
            response_file="$OUTPUT_DIR/api_scanner/responses/response$safe_name"
            
            # Store the status
            status_message=""
            case "$status" in
                200|201|204) status_message="SUCCESS";;  
                301|302|307) status_message="REDIRECT";;  
                401) status_message="UNAUTHORIZED";;  
                403) status_message="FORBIDDEN";;  
            esac
            
            echo -e "\n${GREEN}[*] Found API Endpoint: $url ($status - $status_message)${NC}"
            echo "$url ($status - $status_message)" >> "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt"
            
            # Get response and headers
            curl -s -i "$url" -H "User-Agent: $USER_AGENT" -H "Accept: application/json, text/plain, */*" --connect-timeout 3 -m 7 > "$response_file"
            
            # Try to detect if it's JSON
            grep -q "Content-Type:.*json" "$response_file"
            is_json=$?
            
            if [[ $is_json -eq 0 ]]; then
                echo -e "${YELLOW}[*] JSON response detected${NC}"
                
                # Extract the body (remove headers)
                sed '1,/^\r\?$/d' "$response_file" > "$response_file.json"
                
                # Check if response is valid JSON
                jq . "$response_file.json" &> /dev/null
                if [[ $? -eq 0 ]]; then
                    echo -e "${YELLOW}[*] Valid JSON response${NC}"
                    
                    # If this is a GraphQL endpoint, try introspection
                    if [[ "$path" == *graphql* || "$path" == *gql* ]]; then
                        echo -e "${YELLOW}[*] Testing GraphQL endpoint for introspection...${NC}"
                        introspection_query='{"query":"{__schema{queryType{name}}}"}'
                        curl -s -X POST -H "Content-Type: application/json" -d "$introspection_query" "$url" > "$OUTPUT_DIR/api_scanner/responses/graphql_introspection$safe_name.json"
                    fi
                else
                    echo -e "${YELLOW}[*] Invalid JSON response, might be protected or not a standard API${NC}"
                fi
            fi
            
            # Check for sensitive info in response
            grep -i -E "(api[-_]?key|secret|key|token|password|credential|auth)" "$response_file" > "$response_file.sensitive" 2>/dev/null
            
            if [ -s "$response_file.sensitive" ]; then
                echo -e "${RED}[!] Potential sensitive information leaked in API response!${NC}"
                echo "$url" >> "$OUTPUT_DIR/api_scanner/sensitive_endpoints.txt"
            fi
        fi
    done < "$OUTPUT_DIR/api_scanner/api_paths.txt"
    
    echo -e "\n${BLUE}[*] API path scan complete.${NC}"
    
    # Count discovered endpoints
    ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[*] Discovered $ENDPOINT_COUNT API endpoints${NC}"
    
    # Enhanced GraphQL Testing
    echo -e "${BLUE}[*] Performing enhanced GraphQL endpoint testing...${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/graphql"
    
    # Gather all potential GraphQL endpoints
    graphql_endpoints=$(grep -E '(graphql|gql)' "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" 2>/dev/null | cut -d ' ' -f1)
    
    if [ -n "$graphql_endpoints" ]; then
        echo -e "${GREEN}[*] Found $(echo "$graphql_endpoints" | wc -l) potential GraphQL endpoints${NC}"
        
        while read -r graphql_url; do
            [ -z "$graphql_url" ] && continue
            
            echo -e "${BLUE}[*] Testing GraphQL endpoint: $graphql_url${NC}"
            endpoint_name=$(echo "$graphql_url" | sed 's/https\?:\/\///' | sed 's/[\/:.]/_/g')
            
            # Test 1: Basic Introspection
            echo -e "${BLUE}[*] Testing introspection...${NC}"
            introspection_query='{"query":"{__schema{queryType{name}}}"}'  
            curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$introspection_query" "$graphql_url" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_introspection_basic.json"
            
            # Check if introspection is enabled
            if grep -q "__schema" "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_introspection_basic.json"; then
                echo -e "${RED}[!] GraphQL introspection is enabled (information disclosure vulnerability)${NC}"
                echo "$graphql_url: Introspection enabled" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                
                # Test 2: Full Schema Introspection
                echo -e "${BLUE}[*] Getting full schema...${NC}"
                full_introspection='{"query":"query IntrospectionQuery {__schema {queryType {name} mutationType {name} subscriptionType {name} types {kind name description fields(includeDeprecated: true) {name description args {name description type {kind name ofType {kind name ofType {kind name ofType {kind name}}}} defaultValue} type {kind name ofType {kind name ofType {kind name ofType {kind name}}}} isDeprecated deprecationReason} inputFields {name description type {kind name ofType {kind name ofType {kind name ofType {kind name}}}} defaultValue} interfaces {kind name ofType {kind name ofType {kind name ofType {kind name}}}} enumValues(includeDeprecated: true) {name description isDeprecated deprecationReason} possibleTypes {kind name ofType {kind name ofType {kind name ofType {kind name}}}}}}}"}'
                curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$full_introspection" "$graphql_url" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_schema_full.json"
                
                # Extract types and fields for analysis
                jq -r '.data.__schema.types[] | select(.kind == "OBJECT") | .name' "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_schema_full.json" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_types.txt" 2>/dev/null
                
                # Check for sensitive types
                grep -i -E '(user|admin|account|password|secret|token|auth|credential|key|payment|credit|card|personal|profile|address|private|internal)' "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_types.txt" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_sensitive_types.txt" 2>/dev/null
                
                if [ -s "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_sensitive_types.txt" ]; then
                    echo -e "${RED}[!] Potentially sensitive GraphQL types detected:${NC}"
                    cat "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_sensitive_types.txt" | sed 's/^/  - /'
                    echo "$graphql_url: Sensitive types detected" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                fi
                
                # Test 3: Test for Direct Queries on Sensitive Types
                echo -e "${BLUE}[*] Testing sample queries for sensitive data...${NC}"
                while read -r type_name; do
                    # Get fields for this type
                    fields=$(jq -r ".data.__schema.types[] | select(.name == \"$type_name\") | .fields[].name" "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_schema_full.json" 2>/dev/null | paste -sd "," -)
                    
                    if [ -n "$fields" ]; then
                        # Create a basic query for this type
                        query_fields=$(echo "$fields" | sed 's/,/ /g' | awk '{for(i=1; i<=NF && i<=5; i++) printf "%s ", $i}')
                        test_query="{\"query\":\"{${type_name}s{${query_fields}}}\"}" 
                        
                        # Try the query
                        curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$test_query" "$graphql_url" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_query_${type_name}.json"
                        
                        # Check if query succeeded
                        if ! grep -q "errors" "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_query_${type_name}.json"; then
                            echo -e "${RED}[!] Successful query on sensitive type: $type_name${NC}"
                            echo "$graphql_url: Successful query on $type_name" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                        fi
                    fi
                done < "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_sensitive_types.txt"
                
                # Test 4: NoSQL Injection Test (basic)
                echo -e "${BLUE}[*] Testing for basic NoSQL injection...${NC}"
                nosql_test_query='{"query":"{user(id:{\"$gt\":\"\"}){username}}"}'  
                curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$nosql_test_query" "$graphql_url" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_nosql_test.json"
                
                # Check for successful injection (highly dependent on implementation)
                if ! grep -q "errors" "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_nosql_test.json" && \
                   ! grep -q "syntax" "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_nosql_test.json"; then
                    echo -e "${RED}[!] Potential NoSQL injection vulnerability${NC}"
                    echo "$graphql_url: Potential NoSQL injection" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                fi
            else
                echo -e "${GREEN}[*] GraphQL introspection is properly disabled${NC}"
                
                # Test 5: Try common queries blindly
                echo -e "${BLUE}[*] Testing common GraphQL queries...${NC}"
                
                # Array of common queries to try
                common_queries=(
                    '{"query":"{users{id username email}}"}'  
                    '{"query":"{user(id:1){id username email}}"}'  
                    '{"query":"{me{id username email}}"}'  
                    '{"query":"{products{id name price}}"}'  
                    '{"query":"{orders{id status}}"}'  
                )
                
                for (( i=0; i<${#common_queries[@]}; i++ )); do
                    query=${common_queries[$i]}
                    query_name="query_$(($i+1))"
                    
                    curl -s -X POST -H "Content-Type: application/json" -H "User-Agent: $USER_AGENT" -d "$query" "$graphql_url" > "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_${query_name}.json"
                    
                    # If query succeeds (no errors field)
                    if ! grep -q "errors" "$OUTPUT_DIR/api_scanner/graphql/${endpoint_name}_${query_name}.json"; then
                        echo -e "${YELLOW}[!] Successful blind query: ${query_name}${NC}"
                        echo "$graphql_url: Successful blind query: ${query_name}" >> "$OUTPUT_DIR/api_scanner/graphql_vulnerable.txt"
                    fi
                done
            fi
        done <<< "$graphql_endpoints"
    else
        echo -e "${BLUE}[*] No GraphQL endpoints found${NC}"
    fi
    
    # Enhanced Swagger/OpenAPI Documentation Check
    echo -e "${BLUE}[*] Performing comprehensive check for API documentation...${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/documentation"
    
    # More complete paths for API documentation
    swagger_paths=(
        "/swagger"
        "/swagger-ui"
        "/swagger-ui.html"
        "/swagger/index.html"
        "/swagger/ui"
        "/swagger/ui.html"
        "/swagger.json"
        "/swagger.yaml"
        "/api-docs"
        "/api/docs"
        "/api-doc"
        "/api/documentation"
        "/api/explorer"
        "/api-explorer"
        "/openapi"
        "/openapi.json"
        "/openapi.yaml"
        "/docs/api"
        "/api/swagger"
        "/specs"
        "/api/specs"
        "/redoc"
        "/docs"
        "/apidocs"
        "/api/schema"
        "/api-schema"
        "/docs/swagger.json"
        "/docs/swagger.yaml"
        "/swagger-resources"
        "/v1/api-docs"
        "/v2/api-docs"
        "/v3/api-docs"
    )
    
    echo -e "${BLUE}[*] Testing ${#swagger_paths[@]} potential documentation paths...${NC}"
    
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
        echo -ne "${BLUE}[*] Testing doc path: [${YELLOW}${PERCENTAGE}%${BLUE}] $path${NC}\r"
        
        url="${TARGET_URL%/}$path"
        status=$(curl -s -o /dev/null -w "%{http_code}" "$url" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
        
        if [[ "$status" == "200" ]]; then
            # Create a safe filename
            safe_path=$(echo "$path" | sed 's/\//./g')
            
            # Check file type and save accordingly
            echo -e "\n${RED}[!] API documentation found at $url ($status)${NC}"
            curl -s "$url" -H "User-Agent: $USER_AGENT" > "$OUTPUT_DIR/api_scanner/documentation/api_doc${safe_path}.txt"
            
            # Check if it's JSON format
            if grep -q "swagger\|openapi" "$OUTPUT_DIR/api_scanner/documentation/api_doc${safe_path}.txt"; then
                echo -e "${RED}[!] Valid API specification found (Swagger/OpenAPI)${NC}"
                
                # Try to extract version info
                if grep -q "\"swagger\":\|\"openapi\":" "$OUTPUT_DIR/api_scanner/documentation/api_doc${safe_path}.txt"; then
                    version=$(grep -o '"\(swagger\|openapi\)":[[:space:]]*"[^"]*"' "$OUTPUT_DIR/api_scanner/documentation/api_doc${safe_path}.txt" | head -1)
                    echo -e "${YELLOW}[*] API Specification version: ${version:-Unknown}${NC}"
                fi
                
                # Try to get endpoints count
                endpoints_count=$(grep -o '"paths"\|"endpoints"' "$OUTPUT_DIR/api_scanner/documentation/api_doc${safe_path}.txt" | wc -l)
                if [ "$endpoints_count" -gt 0 ]; then
                    echo -e "${YELLOW}[*] Specification contains endpoint definitions${NC}"
                    
                    # Extract endpoints if possible
                    if command -v jq &> /dev/null; then
                        jq -r '.paths | keys[]' "$OUTPUT_DIR/api_scanner/documentation/api_doc${safe_path}.txt" > "$OUTPUT_DIR/api_scanner/documentation/extracted_endpoints${safe_path}.txt" 2>/dev/null
                        endpoint_count=$(wc -l < "$OUTPUT_DIR/api_scanner/documentation/extracted_endpoints${safe_path}.txt" 2>/dev/null || echo 0)
                        if [ "$endpoint_count" -gt 0 ]; then
                            echo -e "${GREEN}[*] Extracted $endpoint_count API endpoints from documentation${NC}"
                            
                            # Add to our endpoints list for testing
                            while read -r endpoint; do
                                echo "${TARGET_URL%/}$endpoint" >> "$OUTPUT_DIR/api_scanner/all_endpoints.txt"
                            done < "$OUTPUT_DIR/api_scanner/documentation/extracted_endpoints${safe_path}.txt"
                        fi
                    fi
                fi
                echo "$url: API documentation" >> "$OUTPUT_DIR/api_scanner/findings.txt"
            fi
            
            ((FOUND_DOCS++))
        fi
    done
    
    echo -e "\n${BLUE}[*] Documentation scan complete. Found $FOUND_DOCS documents.${NC}"
    
    # Enhanced CORS Misconfiguration Testing
    echo -e "${BLUE}[*] Performing comprehensive CORS security testing...${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/cors"
    
    # Prepare a list of origins to test with
    cat > "$OUTPUT_DIR/api_scanner/cors/test_origins.txt" << EOF
https://evil.com
http://evil.com
null
file://
https://attacker.evil.com
https://${TARGET_URL#*//}.evil.com
https://subdomain.${TARGET_URL#*//}
data:
https://\\${TARGET_URL#*//}
https://attacker.com%60javascript:alert(1)
https://evil.com\@${TARGET_URL#*//}
EOF
    
    # Combine all endpoints
    cat "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt" 2>/dev/null | cut -d ' ' -f1 > "$OUTPUT_DIR/api_scanner/all_endpoints.txt" 2>/dev/null
    
    ENDPOINT_COUNT=$(wc -l < "$OUTPUT_DIR/api_scanner/all_endpoints.txt" 2>/dev/null || echo "0")
    echo -e "${BLUE}[*] Testing CORS policies on $ENDPOINT_COUNT endpoints...${NC}"
    
    CURRENT=0
    CORS_VULNS=0
    
    # Create headers file for output
    > "$OUTPUT_DIR/api_scanner/cors/cors_headers.txt"
    > "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
    
    while read -r endpoint; do
        [ -z "$endpoint" ] && continue
        
        # Increment counter
        ((CURRENT++))
        
        # Calculate percentage
        PERCENTAGE=$((CURRENT * 100 / ENDPOINT_COUNT))
        
        # Display progress
        echo -ne "${BLUE}[*] Testing CORS: [${YELLOW}${PERCENTAGE}%${BLUE}] $endpoint${NC}\r"
        
        endpoint_safe=$(echo "$endpoint" | sed 's/[:\/]/_/g')
        
        # Test each origin
        while read -r origin; do
            [ -z "$origin" ] && continue
            
            # Skip testing if we've already found a vulnerability for this endpoint
            if grep -q "^$endpoint" "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt" 2>/dev/null; then
                continue
            fi
            
            cors_response=$(curl -s -I -H "Origin: $origin" "$endpoint" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
            echo "$cors_response" > "$OUTPUT_DIR/api_scanner/cors/headers_${endpoint_safe}_${origin//[:\/]/_}.txt"
            
            # Check for various CORS vulnerabilities
            if echo "$cors_response" | grep -i "access-control-allow-origin: $origin" &>/dev/null; then
                echo -e "\n${RED}[!] CORS Vulnerability: $endpoint allows requests from arbitrary origin: $origin${NC}"
                echo "$endpoint - Allows arbitrary origin: $origin" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                ((CORS_VULNS++))
                
                # Check for allow-credentials
                if echo "$cors_response" | grep -i "access-control-allow-credentials: true" &>/dev/null; then
                    echo -e "${RED}[!] HIGH Severity: Allows credentials with specific arbitrary origin${NC}"
                    echo "$endpoint - HIGH: Allows credentials with arbitrary origin: $origin" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                fi
                
                # No need to check other origins for this endpoint
                break
            fi
            
            # Check for wildcard
            if echo "$cors_response" | grep -i "access-control-allow-origin: \*" &>/dev/null; then
                echo -e "\n${YELLOW}[!] CORS Warning: $endpoint allows requests from any origin (*)${NC}"
                echo "$endpoint - Allows any origin (*)" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                ((CORS_VULNS++))
                
                # Check for credentials with wildcard (severe security issue)
                if echo "$cors_response" | grep -i "access-control-allow-credentials: true" &>/dev/null; then
                    echo -e "${RED}[!] CRITICAL: Allows credentials with wildcard origin (severe configuration error)${NC}"
                    echo "$endpoint - CRITICAL: Allows credentials with wildcard origin" >> "$OUTPUT_DIR/api_scanner/cors_vulnerable.txt"
                fi
                
                # No need to check other origins for this endpoint
                break
            fi
        done < "$OUTPUT_DIR/api_scanner/cors/test_origins.txt"
    done < "$OUTPUT_DIR/api_scanner/all_endpoints.txt"
    
    echo -e "\n${BLUE}[*] CORS testing complete. Found $CORS_VULNS vulnerabilities.${NC}"
    
    # API Security Testing
    echo -e "${BLUE}[*] Performing additional API security tests...${NC}"
    mkdir -p "$OUTPUT_DIR/api_scanner/security"
    
    # Test for HTTP methods allowed (VERB tampering)
    echo -e "${BLUE}[*] Testing HTTP method handling...${NC}"
    
    # Take sample of endpoints to test (max 10 to avoid excessive requests)
    head -10 "$OUTPUT_DIR/api_scanner/all_endpoints.txt" > "$OUTPUT_DIR/api_scanner/sample_endpoints.txt"
    
    HTTP_METHODS=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE" "CONNECT")
    
    while read -r endpoint; do
        [ -z "$endpoint" ] && continue
        
        endpoint_safe=$(echo "$endpoint" | sed 's/[:\/]/_/g')
        echo -e "${BLUE}[*] Testing HTTP methods on: $endpoint${NC}"
        
        # First get OPTIONS to check declared allowed methods
        options_response=$(curl -s -I -X OPTIONS "$endpoint" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
        echo "$options_response" > "$OUTPUT_DIR/api_scanner/security/options_${endpoint_safe}.txt"
        
        # Extract allowed methods from OPTIONS response
        allowed_methods=$(echo "$options_response" | grep -i "Allow\|Access-Control-Allow-Methods" | cut -d ':' -f2- || echo "None specified")
        echo "Declared allowed methods: $allowed_methods" > "$OUTPUT_DIR/api_scanner/security/methods_${endpoint_safe}.txt"
        
        # Test each method
        for method in "${HTTP_METHODS[@]}"; do
            status=$(curl -s -o "$OUTPUT_DIR/api_scanner/security/response_${endpoint_safe}_${method}.txt" -w "%{http_code}" -X "$method" "$endpoint" -H "User-Agent: $USER_AGENT" --connect-timeout 3 -m 7)
            echo "$method: $status" >> "$OUTPUT_DIR/api_scanner/security/methods_${endpoint_safe}.txt"
            
            # Check for successful status codes with potentially dangerous methods
            if [[ "$method" != "GET" && "$method" != "HEAD" && "$method" != "OPTIONS" ]] && \
               [[ "$status" == "200" || "$status" == "201" || "$status" == "202" || "$status" == "204" ]]; then
                echo -e "${RED}[!] Potentially unsafe HTTP method $method allowed on $endpoint${NC}"
                echo "$endpoint - Unsafe method $method returned $status" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
            fi
        done
    done < "$OUTPUT_DIR/api_scanner/sample_endpoints.txt"
    
    # Test for missing rate limiting
    echo -e "${BLUE}[*] Testing for rate limiting...${NC}"
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
            echo -e "\n${GREEN}[*] Rate limiting appears to be implemented${NC}"
            echo "Rate limiting implemented" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        else
            echo -e "\n${YELLOW}[!] No evidence of rate limiting found${NC}"
            echo "$RATE_TEST_ENDPOINT - No evidence of rate limiting" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        fi
    fi
    
    # Authentication Analysis
    echo -e "${BLUE}[*] Performing authentication analysis...${NC}"
    
    # Check for authentication headers
    if [ -n "$RATE_TEST_ENDPOINT" ]; then
        auth_response=$(curl -s -I "$RATE_TEST_ENDPOINT" -H "User-Agent: $USER_AGENT")
        
        # Check for WWW-Authenticate header
        if echo "$auth_response" | grep -i "www-authenticate" &>/dev/null; then
            auth_type=$(echo "$auth_response" | grep -i "www-authenticate" | awk '{print $2}' | tr -d '"')
            echo -e "${YELLOW}[!] Authentication required: $auth_type${NC}"
            echo "$RATE_TEST_ENDPOINT - Authentication type: $auth_type" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        fi
        
        # Check for common authorization headers in responses
        if echo "$auth_response" | grep -i "authorization\|x-api-key\|api-key" &>/dev/null; then
            echo -e "${RED}[!] Authorization headers in response - potential information disclosure${NC}"
            echo "$RATE_TEST_ENDPOINT - Authorization headers exposed" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
        fi
    fi
    
    # JWT Token Testing
    echo -e "${BLUE}[*] Testing for JWT token vulnerabilities...${NC}"
    
    # Check if we can find JWT tokens in any of the responses
    find "$OUTPUT_DIR/api_scanner" -type f -name "*.txt" -o -name "*.json" | xargs grep -l "eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" > "$OUTPUT_DIR/api_scanner/jwt_found.txt"
    
    if [ -s "$OUTPUT_DIR/api_scanner/jwt_found.txt" ]; then
        echo -e "${YELLOW}[!] Found JWT tokens in responses${NC}"
        
        # Extract and analyze each token
        cat "$OUTPUT_DIR/api_scanner/jwt_found.txt" | while read -r file; do
            grep -o "eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*" "$file" | while read -r token; do
                echo -e "${BLUE}[*] Analyzing JWT token: ${token:0:20}...${NC}"
                
                # Decode header
                header=$(echo "$token" | cut -d. -f1 | base64 -d 2>/dev/null | tr -d '\0')
                
                # Check for weak algorithms
                if echo "$header" | grep -q '"alg":"none\|"alg":"HS256\|"alg":"HS1"'; then
                    echo -e "${RED}[!] JWT using weak algorithm: $(echo "$header" | grep -o '"alg":"[^"]*"')${NC}"
                    echo "JWT with weak algorithm found: $(echo "$header" | grep -o '"alg":"[^"]*"')" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
                fi
                
                # Decode payload
                payload=$(echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null | tr -d '\0')
                
                # Check for sensitive data in payload
                if echo "$payload" | grep -q '"password\|"api_key\|"secret\|"private'; then
                    echo -e "${RED}[!] JWT contains sensitive data in payload${NC}"
                    echo "JWT with sensitive data in payload" >> "$OUTPUT_DIR/api_scanner/security_findings.txt"
                fi
                
                # Save decoded token
                echo "Header: $header" > "$OUTPUT_DIR/api_scanner/security/jwt_decoded_${token:0:10}.txt"
                echo "Payload: $payload" >> "$OUTPUT_DIR/api_scanner/security/jwt_decoded_${token:0:10}.txt"
            done
        done
    else
        echo -e "${BLUE}[*] No JWT tokens found in responses${NC}"
    fi
    
    # Generate Enhanced Summary Report
    echo -e "${BLUE}[*] Generating comprehensive summary report...${NC}"
    
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
        endpoint_count=$(wc -l < "$OUTPUT_DIR/api_scanner/found_api_endpoints.txt")
        if [ "$endpoint_count" -gt 20 ]; then
            echo "  - ... and $(($endpoint_count - 20)) more endpoints (see full list in found_api_endpoints.txt)" >> "$OUTPUT_DIR/api_scanner/summary_report.txt"
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

    echo -e "${GREEN}[*] API scan complete. Results saved to $OUTPUT_DIR/api_scanner/${NC}"
    echo -e "${GREEN}[*] Comprehensive summary report: $OUTPUT_DIR/api_scanner/summary_report.txt${NC}"
}

# Main function
f_api_scanner(){
    f_scanname
{{ ... }}
    echo
    echo -e "${BLUE}Select scan type:${NC}"
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
            echo -n "Enter target URL (e.g., http://example.com): "
            read -r TARGET_URL
            
            if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
                echo -e "${RED}[!] Invalid URL. Must start with http:// or https://${NC}"
                echo
                exit 1
            fi
            
            f_discover_api "$TARGET_URL" "$NAME"
            ;;
        2)
            echo
            echo -n "Enter JWT token to analyze: "
            read -r JWT_TOKEN
            
            if [[ ! "$JWT_TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
                echo -e "${RED}[!] Invalid JWT format. Must be in format 'header.payload.signature'${NC}"
                echo
                exit 1
            fi
            
            f_jwt_analysis "$JWT_TOKEN" "$NAME"
            ;;
        3)
            return
            ;;
        *)
            f_error
            ;;
    esac
}

# Export the main function
export -f f_api_scanner
