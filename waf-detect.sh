#!/usr/bin/env bash

# by ibrahimsql - WAF Detection Tool

clear
f_banner

# Variables
OUTPUT_DIR="waf-detection-$(date +%s)"

# WAF signatures
declare -A WAF_SIGNATURES=(
    ["Akamai"]="akamai|x-akamai-transformed"
    ["AWS_WAF"]="aws-waf|awswaf|aws protect"
    ["Barracuda"]="barracuda|barra_counter"
    ["ChinaCache"]="chinacache"
    ["Citrix"]="citrix|netscaler"
    ["Cloudflare"]="cloudflare|ray-id|cf-ray|cloudflare-nginx"
    ["Comodo"]="comodo|protected by comodo"
    ["DDoS-Guard"]="ddos-guard|ddosguard"
    ["Distil"]="distil|x-distil"
    ["Edgecast"]="edgecast|ecdf"
    ["F5_BIG-IP"]="big-ip|f5-trafficshield"
    ["Fastly"]="fastly|x-fastly"
    ["Fortinet"]="fortinet|fortigate|fortiweb"
    ["Generic"]="waf|security|firewall|protection"
    ["Imperva"]="imperva|incapsula"
    ["MaxCDN"]="maxcdn"
    ["ModSecurity"]="mod_security|modsecurity"
    ["Radware"]="radware|x-sl-compstate"
    ["Reblaze"]="reblaze"
    ["Stackpath"]="stackpath"
    ["Sucuri"]="sucuri|cloudproxy"
    ["USP_Secure_Entry"]="usp-secure-entry"
    ["Varnish"]="varnish|x-varnish"
    ["Wallarm"]="wallarm|nginx-wallarm"
    ["Wordfence"]="wordfence"
    ["Yunsuo"]="yunsuo"
)

f_error(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] Invalid choice or entry.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
}

###############################################################################################################################

f_create_output_dir(){
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
        echo -e "[*] Created output directory: ${GREEN}$OUTPUT_DIR${NC}"
    fi
}

###############################################################################################################################

f_detect_waf(){
    local target=$1
    local detected=false
    local detected_wafs=()

    echo -e "[*] Testing target: ${BLUE}$target${NC}"

    # Ensure target has http:// or https:// prefix
    if [[ ! $target =~ ^https?:// ]]; then
        target="http://$target"
    fi

    # Create temporary files
    local headers_file="$OUTPUT_DIR/tmp_headers_$(date +%s).txt"
    local body_file="$OUTPUT_DIR/tmp_body_$(date +%s).txt"

    # Make request with custom headers to trigger WAF
    local user_agents=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        "sqlmap/1.4.11#dev (http://sqlmap.org)"
    )

    local random_agent=${user_agents[$RANDOM % ${#user_agents[@]}]}

    # Basic request to get headers and initial response
    curl -s -k -L -A "$random_agent" -o "$body_file" -D "$headers_file" \
         -H "X-Forwarded-For: 127.0.0.1" \
         -H "X-Originating-IP: 127.0.0.1" \
         -H "X-Remote-IP: 127.0.0.1" \
         -H "X-Remote-Addr: 127.0.0.1" \
         "$target" > /dev/null 2>&1

    # Trigger-based request with common attack patterns
    local trigger_url="${target}/?id=1'%20OR%20'1'%3D'1'%20--%20"
    curl -s -k -L -A "$random_agent" -o /dev/null -D "$headers_file.trigger" \
         -H "X-Forwarded-For: 127.0.0.1" \
         -H "X-Originating-IP: 127.0.0.1" \
         -H "X-Remote-IP: 127.0.0.1" \
         -H "X-Remote-Addr: 127.0.0.1" \
         "$trigger_url" > /dev/null 2>&1

    # Combine header files for analysis
    cat "$headers_file" "$headers_file.trigger" > "$headers_file.combined"

    # Check for WAF signatures in headers and body
    for waf_name in "${!WAF_SIGNATURES[@]}"; do
        local signature=${WAF_SIGNATURES[$waf_name]}
        display_name=${waf_name//_/ } # Replace underscores with spaces for display

        if grep -i -E "$signature" "$headers_file.combined" > /dev/null || grep -i -E "$signature" "$body_file" > /dev/null; then
            detected=true
            detected_wafs+=("$display_name")
            echo -e "[+] ${GREEN}Detected WAF: $display_name${NC}"
        fi
    done

    # Behavioral analysis for WAF detection
    local status_code=$(grep -E "^HTTP/[0-9]\.[0-9] [0-9]{3}" "$headers_file.trigger" | tail -1 | awk '{print $2}')

    # Common WAF behavior patterns
    if [[ "$status_code" =~ ^(403|406|429|500|502)$ ]]; then
        # Get normal status code
        local normal_status_code=$(grep -E "^HTTP/[0-9]\.[0-9] [0-9]{3}" "$headers_file" | tail -1 | awk '{print $2}')

        # If the normal request succeeded but the trigger request failed, likely a WAF
        if [[ "$normal_status_code" =~ ^(200|301|302|307|308)$ ]]; then
            detected=true
            detected_wafs+=("Unknown WAF (Behavioral Detection)")
            echo -e "[+] ${GREEN}Detected WAF: Unknown WAF (Behavioral Detection)${NC}"
            echo -e "    ${YELLOW}Normal request: $normal_status_code, Attack request: $status_code${NC}"
        fi
    fi

    # Check for special response headers that indicate WAF
    if grep -i -E "x-firewall|x-web-protection|x-security|challenge|captcha|blocked|protect" "$headers_file.combined" > /dev/null; then
        detected=true
        detected_wafs+=("Unknown WAF (Header Detection)")
        echo -e "[+] ${GREEN}Detected WAF: Unknown WAF (Header Detection)${NC}"
    fi

    # Clean up temporary files
    rm -f "$headers_file" "$headers_file.trigger" "$headers_file.combined" "$body_file"

    # Return results for CSV logging
    if $detected; then
        local wafs_string=$(printf "%s," "${detected_wafs[@]}")
        wafs_string=${wafs_string%,} # Remove trailing comma
        echo "$target,Yes,$wafs_string,$(date +%Y-%m-%d' '%H:%M:%S)" >> "$OUTPUT_DIR/waf_results.csv"
    else
        echo -e "[-] ${RED}No WAF detected for: $target${NC}"
        echo "$target,No,-,$(date +%Y-%m-%d' '%H:%M:%S)" >> "$OUTPUT_DIR/waf_results.csv"
    fi
}

###############################################################################################################################

f_load_from_file(){
    local file_path=$1

    if [ ! -f "$file_path" ]; then
        echo -e "${RED}[!] File not found: $file_path${NC}"
        f_error
    fi

    # Create CSV header
    echo "Target,WAF Detected,WAF Names,Timestamp" > "$OUTPUT_DIR/waf_results.csv"

    # Process each line in the file
    local total_lines=$(wc -l < "$file_path")
    local current_line=0

    while IFS= read -r target || [ -n "$target" ]; do
        # Skip empty lines and comments
        if [[ -z "$target" || "$target" =~ ^# ]]; then
            continue
        fi

        current_line=$((current_line + 1))
        echo -e "\n${YELLOW}[$current_line/$total_lines]${NC} Processing target: $target"
        f_detect_waf "$target"
    done < "$file_path"
}

###############################################################################################################################

f_single_target(){
    echo -n "Enter the target (domain or IP): "
    read -r TARGET

    # Check for no answer
    if [ -z "$TARGET" ]; then
        f_error
    fi

    # Create CSV header
    echo "Target,WAF Detected,WAF Names,Timestamp" > "$OUTPUT_DIR/waf_results.csv"

    f_detect_waf "$TARGET"
}

###############################################################################################################################

f_waf_main(){
    f_create_output_dir

    echo -e "${BLUE}WAF Detection${NC} | ${YELLOW}by ibrahimsql${NC}"
    echo
    echo "1. Single target"
    echo "2. Multiple targets from file"
    echo "3. Previous menu"
    echo

    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
        1)
            f_single_target
            ;;
        2)
            echo -n "Enter the path to the targets file: "
            read -r FILE_PATH

            # Check for no answer
            if [ -z "$FILE_PATH" ]; then
                f_error
            fi

            f_load_from_file "$FILE_PATH"
            ;;
        3)
            f_main ;;
        *)
            echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; clear && f_banner && f_waf_main ;;
    esac

    echo
    echo "$MEDIUM"
    echo
    echo -e "[*] WAF detection completed."
    echo
    echo -e "Results saved to ${YELLOW}$OUTPUT_DIR/waf_results.csv${NC}"
    echo
    exit 0
}

# Run the script
f_waf_main
