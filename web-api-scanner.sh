#!/usr/bin/env bash

# by ibrahimsql - Metasploit Web and API Security Scanner
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

# Check if PostgreSQL is running
if ! service postgresql status | grep -q "active (running)"; then
    echo -e "${BLUE}[*] Starting PostgreSQL service.${NC}"
    sudo service postgresql start
    sleep 2
fi

# Check if MSF database is connected
if ! msfconsole -q -x "db_status; exit" | grep -q "postgresql connected"; then
    echo -e "${RED}[!] Metasploit database is not connected. Running initialization.${NC}"
    sudo msfdb init
    sleep 2
fi

# Create resource directory
mkdir -p "/tmp/msf_resources"
MSF_RESOURCE_DIR="/tmp/msf_resources"

###############################################################################################################################

# Function to create web application security resource scripts
f_create_web_resources() {
    echo -e "${BLUE}[*] Preparing web application security test resource scripts.${NC}"

    # Apache Vulnerabilities
    cat > "$MSF_RESOURCE_DIR/apache_vulns.rc" << EOF
use auxiliary/scanner/http/apache_optionsbleed
run
use auxiliary/scanner/http/mod_negotiation_scanner
run
use exploit/multi/http/struts2_rest_xstream
check
use exploit/multi/http/struts2_content_type_ognl
check
use exploit/multi/http/struts_code_exec_classloader
check
use exploit/multi/http/struts_dev_mode
check
EOF

    # API Security Tests
    cat > "$MSF_RESOURCE_DIR/api_security.rc" << EOF
use auxiliary/scanner/http/http_login
set AUTH_URI /api/login
set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt
run
use auxiliary/scanner/http/soap_xml
run
use auxiliary/scanner/http/brute_dirs
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
set FORMAT /api/%s
run
set FORMAT /v1/%s
run
set FORMAT /v2/%s
run
set FORMAT /rest/%s
run
EOF

    # Drupal Scanner Resource
    cat > "$MSF_RESOURCE_DIR/drupal.rc" << EOF
use auxiliary/scanner/http/drupal_scanner
setg THREADS 5
setg TIMEOUT 15
run
EOF

    # GraphQL Scanner
    cat > "$MSF_RESOURCE_DIR/graphql.rc" << EOF
use auxiliary/scanner/http/graphql_introspection
run
EOF

    # Jenkins Vulnerabilities
    cat > "$MSF_RESOURCE_DIR/jenkins_vulns.rc" << EOF
use auxiliary/scanner/http/jenkins_enum
run
use auxiliary/scanner/http/jenkins_command
run
EOF

    # OAuth/OpenID Vulnerabilities
    cat > "$MSF_RESOURCE_DIR/oauth_openid.rc" << EOF
use auxiliary/gather/oauth_key_leak
run
use auxiliary/scanner/http/oauth_token
run
EOF

    # JWT Scanner Resource
    cat > "$MSF_RESOURCE_DIR/jwt.rc" << EOF
use auxiliary/scanner/http/jwt_scanner
run
EOF

    # SQL Injection Scanner Resources
    cat > "$MSF_RESOURCE_DIR/sqli.rc" << EOF
use auxiliary/scanner/http/blind_sql_query
run
use auxiliary/scanner/http/sql_injection
run
EOF

    # Tomcat Vulnerabilities
    cat > "$MSF_RESOURCE_DIR/tomcat_vulns.rc" << EOF
use auxiliary/scanner/http/tomcat_mgr_login
run
use auxiliary/admin/http/tomcat_administration
run
use auxiliary/admin/http/tomcat_utf8_traversal
run
EOF

    # Web Application Vulnerability Scanner Resources
    cat > "$MSF_RESOURCE_DIR/web_vulns.rc" << EOF
use auxiliary/scanner/http/http_version
run
use auxiliary/scanner/http/robots_txt
run
use auxiliary/scanner/http/dir_scanner
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run
use auxiliary/scanner/http/files_dir
run
use auxiliary/scanner/http/ssl
run
use auxiliary/scanner/http/http_header
run
use auxiliary/scanner/http/http_put
run
use auxiliary/scanner/http/options
run
use auxiliary/scanner/http/webdav_scanner
run
use auxiliary/scanner/http/webdav_internal_ip
run
use auxiliary/scanner/http/web_crawl
set DEPTH 2
run
EOF

    # WordPress Scanner Resource
    cat > "$MSF_RESOURCE_DIR/wordpress.rc" << EOF
use auxiliary/scanner/http/wordpress_scanner
setg THREADS 5
setg TIMEOUT 15
run
EOF

    echo -e "${YELLOW}[*] Resource scripts created.${NC}"
}

###############################################################################################################################

# Function to create advanced password brute force resource scripts
f_create_brute_resources() {
    echo -e "${BLUE}[*] Preparing brute force attack resource scripts.${NC}"

    # API Key Brute Force
    cat > "$MSF_RESOURCE_DIR/api_key_brute.rc" << EOF
use auxiliary/scanner/http/http_login
setg VERBOSE false
setg STOP_ON_SUCCESS true
setg BLANK_PASSWORDS false
setg USER_AS_PASS false
setg HEADER X-API-Key
run
EOF

    # Basic Auth Brute Force
    cat > "$MSF_RESOURCE_DIR/basic_auth_brute.rc" << EOF
use auxiliary/scanner/http/http_login
setg VERBOSE false
setg STOP_ON_SUCCESS true
setg AUTH_TYPE Basic
setg BLANK_PASSWORDS true
setg USER_AS_PASS true
setg USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt
run
EOF

    # JWT Brute Force
    cat > "$MSF_RESOURCE_DIR/jwt_brute.rc" << EOF
use auxiliary/scanner/http/jwt_scanner
setg VERBOSE false
setg BRUTEFORCE true
setg KEY_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
run
EOF

    # Web Form Brute Force
    cat > "$MSF_RESOURCE_DIR/web_form_brute.rc" << EOF
use auxiliary/scanner/http/http_login
setg VERBOSE false
setg STOP_ON_SUCCESS true
setg BLANK_PASSWORDS true
setg USER_AS_PASS true
setg USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt
run
EOF

    echo -e "${YELLOW}[*] Brute force resource scripts created.${NC}"
}

###############################################################################################################################

# Function to create advanced exploit resource scripts
f_create_exploit_resources() {
    echo -e "${BLUE}[*] Preparing exploit resource scripts.${NC}"

    # API & Web Service Exploits
    cat > "$MSF_RESOURCE_DIR/api_exploits.rc" << EOF
use exploit/multi/http/zabbix_script_exec
check

use exploit/multi/http/splunk_upload_app_exec
check

use exploit/multi/http/mantisbt_php_exec
check

use exploit/multi/http/vtiger_php_exec
check

use exploit/multi/http/processmaker_exec
check

use exploit/multi/http/graphite_pickle_exec
check

use exploit/multi/http/saltstack_salt_api_cmd_exec
check

use exploit/multi/http/solarwinds_orion_authenticated_rce
check
EOF

    # Web Application Exploits
    cat > "$MSF_RESOURCE_DIR/web_exploits.rc" << EOF
use exploit/multi/http/jenkins_script_console
check

use exploit/multi/http/tomcat_mgr_deploy
check

use exploit/multi/http/jboss_maindeployer
check

use exploit/multi/http/struts2_content_type_ognl
check

use exploit/multi/http/struts2_rest_xstream
check

use exploit/unix/webapp/wp_admin_shell_upload
check

use exploit/unix/webapp/drupal_drupalgeddon2
check

use exploit/multi/http/apache_mod_cgi_bash_env_exec
check

use exploit/multi/http/rails_secret_deserialization
check

use exploit/multi/http/rails_xml_yaml_code_exec
check

use exploit/multi/http/gitlab_shell_exec
check

use exploit/multi/http/phpmailer_arg_injection
check
EOF

    echo -e "${YELLOW}[*] Exploit resource scripts created.${NC}"
}

###############################################################################################################################

# Function to run web/API security scans
f_run_web_api_scan() {
    local TARGET_URL=$1
    local TARGET_IP=$2
    local OUTPUT_DIR=$3

    echo -e "${BLUE}[*] Running advanced web and API security scans against $TARGET_URL.${NC}"

    # Create output directory
    mkdir -p "$OUTPUT_DIR/msf_web_api"

    # Extract host info
    DOMAIN=$(echo "$TARGET_URL" | sed -E 's|^https?://||' | sed -E 's|/.*$||')

    # Generate master resource file with target information
    cat > "$MSF_RESOURCE_DIR/master_web.rc" << EOF
workspace -a web_api_scan_${DATESTAMP//\-/_}
setg RHOSTS $TARGET_IP
setg RHOST $TARGET_IP
setg VHOST $DOMAIN
setg DOMAIN $DOMAIN
setg SSL $(echo "$TARGET_URL" | grep -q "^https" && echo true || echo false)
setg SRVPORT $(echo "$TARGET_URL" | grep -q "^https" && echo 443 || echo 80)
setg HttpUsername admin
setg HttpPassword admin
setg URI /
setg TARGETURI /
setg VERBOSE false
setg THREADS 5
EOF

    # Initialize report file
    echo "=========================================================" > "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "      METASPLOIT WEB & API SECURITY SCAN REPORT          " >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "=========================================================" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "Target: $TARGET_URL" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "IP: $TARGET_IP" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "Date: $DATESTAMP $TIMESTAMP" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "=========================================================" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"

    # Function to run a scan with a resource file and store results
    run_scan() {
        local resource_file=$1
        local output_name=$2

        echo -e "${BLUE}[*] Running $output_name scan.${NC}"

        # Update the report
        echo "= $output_name Scan Results =" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
        echo "" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"

        # Create combined resource file
        cat "$MSF_RESOURCE_DIR/master_web.rc" > "$MSF_RESOURCE_DIR/tmp.rc"
        echo "spool $OUTPUT_DIR/msf_web_api/${output_name// /_}.txt" >> "$MSF_RESOURCE_DIR/tmp.rc"
        cat "$MSF_RESOURCE_DIR/$resource_file" >> "$MSF_RESOURCE_DIR/tmp.rc"
        echo "spool off" >> "$MSF_RESOURCE_DIR/tmp.rc"
        echo "exit -y" >> "$MSF_RESOURCE_DIR/tmp.rc"

        # Run Metasploit with the resource file
        msfconsole -q -r "$MSF_RESOURCE_DIR/tmp.rc"

        # Extract findings from the output
        if [ -f "$OUTPUT_DIR/msf_web_api/${output_name// /_}.txt" ]; then
            grep -i -E "(vulnerability|exploit|credential|found|successful|available|accessible)" "$OUTPUT_DIR/msf_web_api/${output_name// /_}.txt" | sort -u > "$OUTPUT_DIR/msf_web_api/${output_name// /_}_findings.txt"

            # Add findings to the report
            if [ -s "$OUTPUT_DIR/msf_web_api/${output_name// /_}_findings.txt" ]; then
                cat "$OUTPUT_DIR/msf_web_api/${output_name// /_}_findings.txt" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
            else
                echo "No significant findings." >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
            fi
        else
            echo "Scan did not produce output." >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
        fi

        echo "" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
        echo "" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    }

    # Detect web application technologies
    echo -e "${BLUE}[*] Detecting web technologies.${NC}"
    curl -s -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" -o "/tmp/page.html" "$TARGET_URL"

    # Run relevant scans based on detected technologies
    run_scan "web_vulns.rc" "Web Vulnerability"

    # Check for Apache
    if curl -s -I "$TARGET_URL" | grep -i "server: apache"; then
        echo -e "${YELLOW}[!] Apache detected. Running Apache-specific tests.${NC}"
        run_scan "apache_vulns.rc" "Apache Security"
    fi

    # Check for Drupal
    if grep -i -E "(drupal|sites/all)" "/tmp/page.html"; then
        echo -e "${YELLOW}[!] Drupal detected. Running Drupal-specific tests.${NC}"
        run_scan "drupal.rc" "Drupal Security"
    fi

    # Check for Jenkins
    if grep -i "jenkins" "/tmp/page.html" || curl -s "$TARGET_URL/jenkins/" | grep -i "jenkins"; then
        echo -e "${YELLOW}[!] Jenkins detected. Running Jenkins-specific tests.${NC}"
        run_scan "jenkins_vulns.rc" "Jenkins Security"
    fi

    # Check for Tomcat
    if grep -i -E "(tomcat|jakarta)" "/tmp/page.html" || curl -s -I "$TARGET_URL" | grep -i "server: tomcat"; then
        echo -e "${YELLOW}[!] Tomcat detected. Running Tomcat-specific tests.${NC}"
        run_scan "tomcat_vulns.rc" "Tomcat Security"
    fi

    # Check for WordPress
    if grep -i -E "(wp-content|wp-includes|wordpress)" "/tmp/page.html"; then
        echo -e "${YELLOW}[!] WordPress detected. Running WordPress-specific tests.${NC}"
        run_scan "wordpress.rc" "WordPress Security"
    fi

    # Run API security tests
    echo -e "${BLUE}[*] Running API security tests.${NC}"
    run_scan "api_security.rc" "API Security"

    # Check for GraphQL
    if curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}' "$TARGET_URL/graphql" | grep -q "__schema" || \
       curl -s -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}' "$TARGET_URL/api/graphql" | grep -q "__schema"; then
        echo -e "${YELLOW}[!] GraphQL detected. Running GraphQL-specific tests.${NC}"
        run_scan "graphql.rc" "GraphQL Security"
    fi

    # Check for OAuth/OpenID
    if grep -i -E "(oauth|openid|connect|token|authorize)" "/tmp/page.html"; then
        echo -e "${YELLOW}[!] OAuth/OpenID detected. Running OAuth-specific tests.${NC}"
        run_scan "oauth_openid.rc" "OAuth Security"
    fi

    # Run brute force tests on authentication mechanisms
    echo -e "${BLUE}[*] Running authentication testing.${NC}"
    run_scan "web_form_brute.rc" "Web Authentication"
    run_scan "basic_auth_brute.rc" "HTTP Basic Authentication"
    run_scan "api_key_brute.rc" "API Key Authentication"

    # Run exploit checks
    echo -e "${BLUE}[*] Running exploit checks.${NC}"
    run_scan "web_exploits.rc" "Web Exploit Checks"
    run_scan "api_exploits.rc" "API Exploit Checks"

    # Finalize report
    echo "=========================================================" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "                     END OF REPORT                        " >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"
    echo "=========================================================" >> "$OUTPUT_DIR/msf_web_api/scan_report.txt"

    # Clean up temporary files
    rm -f "/tmp/page.html" "$MSF_RESOURCE_DIR/tmp.rc"

    echo -e "${YELLOW}[*] Web and API security scan complete. Results saved to $OUTPUT_DIR/msf_web_api/scan_report.txt${NC}"
}

###############################################################################################################################

# Main function
f_msf_web_api_main(){
    echo -e "${BLUE}MSF Web and API Security Scanner${NC}"
    echo
    echo "1. Scan a URL for web app and API vulnerabilities"
    echo "2. Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case $CHOICE in
        1)
           echo
           echo -n "Enter target URL (e.g., http://target.com): "
           read -r TARGET_URL

           if [ -z "$TARGET_URL" ]; then
               echo
               echo -e "${RED}[!] No target specified.${NC}"
               echo
               f_terminate
           fi

           # Extract IP address
           DOMAIN=$(echo "$TARGET_URL" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
           TARGET_IP=$(host "$DOMAIN" | grep "has address" | head -1 | awk '{print $4}')

           if [ -z "$TARGET_IP" ]; then
               echo
               echo -e "${RED}[!] Could not resolve domain to IP address.${NC}"
               echo -n "Enter target IP address manually: "
               read -r TARGET_IP

               if [ -z "$TARGET_IP" ]; then
                   echo
                   echo -e "${RED}[!] No IP address specified.${NC}"
                   echo
                   f_terminate
               fi
           fi

           # Create resource scripts
           f_create_web_resources
           f_create_brute_resources
           f_create_exploit_resources

           # Run the scan
           f_run_web_api_scan "$TARGET_URL" "$TARGET_IP" "$OUTPUT"
           ;;
        2) f_main ;;
        *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; clear && f_banner && f_msf_web_api_main ;;
    esac
}

# Run the script
f_msf_web_api_main
