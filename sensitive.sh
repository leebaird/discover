#!/usr/bin/env bash

# by ibrahimsql - Sensitive Information Detector
# Discover framework compatibility module

clear
f_banner

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

# Function to scan files for sensitive info
f_scan_files(){
    local SCAN_DIR=$1
    local OUTPUT_DIR=$2

    echo
    echo -e "${BLUE}[*] Scanning $SCAN_DIR for sensitive information.${NC}"

    # Create results directory
    mkdir -p "$OUTPUT_DIR/sensitive_info"

    # API Keys and credentials patterns
    echo -e "${BLUE}[*] Searching for API keys and credentials.${NC}"
    grep -r -E "(api[_]?key|api[_]?token|secret|key|password|client[_]?id|client[_]?secret|access[_]?token|auth).*[=:][\"\'][0-9a-zA-Z\-_]{16,}[\"\']" "$SCAN_DIR" --include="*.{js,jsx,ts,tsx,php,py,rb,java,json,xml,yaml,yml,conf,config,env,ini,properties}" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/api_keys.txt"

    # AWS Keys
    echo -e "${BLUE}[*] Searching for AWS access keys.${NC}"
    grep -r -E "(AWS|aws).*(access|secret).*[=:][\"\'][A-Za-z0-9/\+]{20,}[\"\']" "$SCAN_DIR" --include="*.{js,jsx,ts,tsx,php,py,rb,java,json,xml,yaml,yml,conf,config,env,ini,properties}" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/aws_keys.txt"

    # Google API Keys
    echo -e "${BLUE}[*] Searching for Google API keys.${NC}"
    grep -r -E "AIza[0-9A-Za-z-_]{35}" "$SCAN_DIR" --include="*.{js,jsx,ts,tsx,php,py,rb,java,json,xml,yaml,yml,html,htm}" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/google_api_keys.txt"

    # Private keys and certificates
    echo -e "${BLUE}[*] Searching for private keys and certificates.${NC}"
    grep -r -A 3 -B 3 "BEGIN (RSA |DSA |EC |OPENSSH |)PRIVATE KEY" "$SCAN_DIR" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/private_keys.txt"

    # Database connection strings
    echo -e "${BLUE}[*] Searching for database connection strings.${NC}"
    grep -r -E "(mongodb|postgresql|mysql|redis|sqlserver)://[^\s]+" "$SCAN_DIR" --include="*.{js,jsx,ts,tsx,php,py,rb,java,json,xml,yaml,yml,conf,config,env,ini,properties}" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/db_connections.txt"

    # Tokens (JWT, OAuth, etc)
    echo -e "${BLUE}[*] Searching for authentication tokens..${NC}"
    grep -r -E "(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+|bearer\s+[a-zA-Z0-9_-]+)" "$SCAN_DIR" --include="*.{js,jsx,ts,tsx,php,py,rb,java,json,xml,yaml,yml,conf,config,env,log,txt}" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/auth_tokens.txt"

    # Credit card numbers
    echo -e "${BLUE}[*] Searching for credit card numbers.${NC}"
    grep -r -E "[4-5][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" "$SCAN_DIR" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/credit_cards.txt"

    # Social Security Numbers (SSN)
    echo -e "${BLUE}[*] Searching for SSNs.${NC}"
    grep -r -E "[0-9]{3}[-: ][0-9]{2}[-: ][0-9]{4}" "$SCAN_DIR" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/ssn.txt"

    # TC Kimlik Numaraları (Turkish National ID)
    echo -e "${BLUE}[*] Searching for TC Kimlik numbers.${NC}"
    grep -r -E "\b[1-9][0-9]{10}\b" "$SCAN_DIR" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/tc_kimlik.txt"

    # Email addresses
    echo -e "${BLUE}[*] Searching for email addresses.${NC}"
    grep -r -E "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}" "$SCAN_DIR" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/emails.txt"

    # Config files that might contain sensitive info
    echo -e "${BLUE}[*] Searching for config files.${NC}"
    find "$SCAN_DIR" -type f -name "*.conf" -o -name "*.config" -o -name "*.env" -o -name "*.ini" -o -name ".env*" 2>/dev/null > "$OUTPUT_DIR/sensitive_info/config_files.txt"

    # Compile summary
    echo -e "${BLUE}[*] Generating summary report.${NC}"
    {
        echo "Sensitive Information Report"
        echo "-------------------------"
        echo "Date: $DATESTAMP $TIMESTAMP"
        echo "Target Directory: $SCAN_DIR"
        echo "-------------------------"
        echo
        echo "[*] API Keys and Credentials:"
        if [ -s "$OUTPUT_DIR/sensitive_info/api_keys.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/api_keys.txt") potential matches"
            head -n 10 "$OUTPUT_DIR/sensitive_info/api_keys.txt" | sed 's/^/  - /'
            if [ "$(wc -l < "$OUTPUT_DIR/sensitive_info/api_keys.txt")" -gt 10 ]; then
                echo "  (More results in file.)"
            fi
        else
            echo "  None found."
        fi

        echo
        echo "[*] AWS Access Keys:"
        if [ -s "$OUTPUT_DIR/sensitive_info/aws_keys.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/aws_keys.txt") potential matches"
            head -n 10 "$OUTPUT_DIR/sensitive_info/aws_keys.txt" | sed 's/^/  - /'
            if [ "$(wc -l < "$OUTPUT_DIR/sensitive_info/aws_keys.txt")" -gt 10 ]; then
                echo "  (More results in file.)"
            fi
        else
            echo "  None found."
        fi
        echo

        echo "[*] Google API Keys:"
        if [ -s "$OUTPUT_DIR/sensitive_info/google_api_keys.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/google_api_keys.txt") potential matches"
            head -n 10 "$OUTPUT_DIR/sensitive_info/google_api_keys.txt" | sed 's/^/  - /'
            if [ "$(wc -l < "$OUTPUT_DIR/sensitive_info/google_api_keys.txt")" -gt 10 ]; then
                echo "  (More results in file.)"
            fi
        else
            echo "  None found."
        fi

        echo
        echo "[*] Private Keys and Certificates:"
        if [ -s "$OUTPUT_DIR/sensitive_info/private_keys.txt" ]; then
            echo "  Found potential private keys in $(grep -c "BEGIN" "$OUTPUT_DIR/sensitive_info/private_keys.txt") locations"
        else
            echo "  None found."
        fi

        echo
        echo "[*] Database Connection Strings:"
        if [ -s "$OUTPUT_DIR/sensitive_info/db_connections.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/db_connections.txt") potential matches"
            head -n 10 "$OUTPUT_DIR/sensitive_info/db_connections.txt" | sed 's/^/  - /'
            if [ "$(wc -l < "$OUTPUT_DIR/sensitive_info/db_connections.txt")" -gt 10 ]; then
                echo "  (More results in file.)"
            fi
        else
            echo "  None found."
        fi

        echo
        echo "[*] Authentication Tokens:"
        if [ -s "$OUTPUT_DIR/sensitive_info/auth_tokens.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/auth_tokens.txt") potential matches"
        else
            echo "  None found."
        fi

        echo
        echo "[*] Credit Card Numbers:"
        if [ -s "$OUTPUT_DIR/sensitive_info/credit_cards.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/credit_cards.txt") potential matches"
            echo "  WARNING: This is highly sensitive information!"
        else
            echo "  None found."
        fi

        echo
        echo "[*] TC Kimlik Numbers:"
        if [ -s "$OUTPUT_DIR/sensitive_info/tc_kimlik.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/tc_kimlik.txt") potential matches"
            echo "  WARNING: This is highly sensitive information!"
        else
            echo "  None found."
        fi

        echo
        echo "[*] Email Addresses:"
        if [ -s "$OUTPUT_DIR/sensitive_info/emails.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/emails.txt") potential matches"
        else
            echo "  None found."
        fi

        echo
        echo "[*] Configuration Files:"
        if [ -s "$OUTPUT_DIR/sensitive_info/config_files.txt" ]; then
            echo "  Found $(wc -l < "$OUTPUT_DIR/sensitive_info/config_files.txt") potential configuration files"
            head -n 10 "$OUTPUT_DIR/sensitive_info/config_files.txt" | sed 's/^/  - /'
            if [ "$(wc -l < "$OUTPUT_DIR/sensitive_info/config_files.txt")" -gt 10 ]; then
                echo "  (More results in file.)"
            fi
        else
            echo "  None found."
        fi
    } > "$OUTPUT_DIR/sensitive_info_summary.txt"

    echo
    echo -e "${YELLOW}[*] Scan complete. Results saved to $OUTPUT_DIR/sensitive_info_summary.txt${NC}"
    echo
}

# Function to scan web for sensitive info
f_scan_web(){
    local TARGET_URL=$1
    local OUTPUT_DIR=$2

    echo
    echo -e "${BLUE}[*] Scanning $TARGET_URL for exposed sensitive information.${NC}"

    # Create results directory
    mkdir -p "$OUTPUT_DIR/web_sensitive"

    # Download robots.txt
    echo -e "${BLUE}[*] Checking robots.txt for sensitive paths.${NC}"
    wget -q "$TARGET_URL/robots.txt" -O "$OUTPUT_DIR/web_sensitive/robots.txt"

    if [ -s "$OUTPUT_DIR/web_sensitive/robots.txt" ]; then
        grep -i "disallow:" "$OUTPUT_DIR/web_sensitive/robots.txt" | grep -iE ".*(admin|backup|config|db|database|auth|password|user|login|private|secret|key).*" > "$OUTPUT_DIR/web_sensitive/sensitive_paths.txt"
    fi

    # Check for common sensitive URLs
    echo -e "${BLUE}[*] Checking for common sensitive URLs.${NC}"

    # Create a list of common sensitive paths
    cat > "$OUTPUT_DIR/web_sensitive/paths_to_check.txt" << EOF
# Admin and Control Panels
/admin/
/administrator/
/admincp/
/adminer.php
/phpmyadmin/
/myadmin/
/manager/
/portal/
/webadmin/
/control/
/panel/
/cpanel/
/dashboard/

# API Documentation
/api/docs/
/swagger/
/swagger-ui/
/api-docs/
/apidoc/
/doc/
/docs/

# Authentication
/.htpasswd
/.htaccess
/passwd
/shadow

# AWS/Cloud
/.aws/
/.boto
/s3cfg
/credentials

# Content Management Systems
/wp-admin/
/wp-content/debug.log
/wp-includes/
/joomla.xml
/administrator/
/typo3/
/drupal/

# Data Dumps and Backups
/backup/
/backups/
/dump/
/dumps/
/sql/
/db_backup/
/database_backup/
/*.sql
/*.bak
/*.backup
/*.old

# Django
/settings.py
/local_settings.py
/manage.py

# Docker
/Dockerfile
/docker-compose.yml
/.dockerignore
/docker/

# Environment and Configuration
/.env
/.env.backup
/.env.dev
/.env.development
/.env.local
/.env.prod
/.env.production
/.env.staging
/.env.test
/environment.js
/environment.ts
/env.js
/env.json

# Git
/.git/config
/.git/HEAD
/.gitignore
/.git-credentials

# Laravel
/storage/logs/laravel.log
/storage/framework/sessions
/artisan

# Logs and Debug
/logs/
/log/
/error_log
/access_log
/debug.log
/error.log

# Node.js and Package Managers
/.npmrc
/.yarnrc
/package.json
/package-lock.json
/yarn.lock
/pnpm-lock.yaml
/bower.json
/node_modules/.cache

# PHP
/composer.json
/composer.lock
/vendor/

# Rails
/config/secrets.yml
/config/master.key
/config/credentials.yml.enc
/config/database.yml
/db/schema.rb

# Status Pages
/server-status
/server-info
/status
/phpinfo.php
/info.php
/status.php
/system_info.php
/sysinfo.php

# Symfony
/app/config/parameters.yml
/var/cache/dev/
/var/logs/

# System Files
/system_files/
/system/
/sys/
/proc/
/etc/
/usr/
/var/

# Temporary Files
/temp/
/tmp/
/cache/

# Test/Development
/test/
/tests/
/testing/
/demo/
/dev/
/development/
/staging/
/beta/

# Version Control
/.svn/entries
/.svn/wc.db
/.hg/
/.bzr/

# Web Application Config
/wp-config.php
/config.php
/configuration.php
/database.php
/db.php
/db_config.php
/dbconfig.php
/settings.php
/setup.php
/inc/config.php
/api/config.php
/admin/config.php
/administrator/config.php
/cfg/config.php
/conf/config.php
/etc/config.php
/config/config.php
/config/database.php
/config/db.php
/config/app.php
/config/secrets.php
/config/auth.php
/config/mail.php
/config/services.php
/config/settings.json
/config/parameters.yml
/app/config/parameters.yml

# Web Server Configs
/nginx.conf
/apache.conf
/.well-known/
EOF

    # Check each path, ignoring comment lines
    while read -r path; do
        # Skip comment lines and empty lines
        [[ "$path" =~ ^\s*# || -z "$path" ]] && continue

        url="${TARGET_URL%/}$path"
        echo -ne "${BLUE}[*] Checking: $path${NC}\r"

        status=$(curl -s -o /dev/null -w "%{http_code}" "$url" --connect-timeout 5 -m 10)

        # If status is 200, 403, or 401, it might be interesting
        if [[ "$status" == "200" || "$status" == "403" || "$status" == "401" ]]; then
            echo -e "\n${YELLOW}[!] Found: $url ($status)${NC}"
            echo "$url ($status)" >> "$OUTPUT_DIR/web_sensitive/found_paths.txt"

            # For 200 responses, save the content to analyze later
            if [[ "$status" == "200" ]]; then
                # Create safe filename from URL
                safe_name=$(echo "$path" | tr '/' '_')
                curl -s "$url" > "$OUTPUT_DIR/web_sensitive/content$safe_name"

                # Check for sensitive data in the response
                grep -i -E "(api[-_]?key|password|secret|token|credential|key)" "$OUTPUT_DIR/web_sensitive/content$safe_name" > "$OUTPUT_DIR/web_sensitive/sensitive_content_$safe_name" 2>/dev/null

                if [ -s "$OUTPUT_DIR/web_sensitive/sensitive_content_$safe_name" ]; then
                    echo -e "${RED}[!] Sensitive data found in $url${NC}"
                    echo "$url" >> "$OUTPUT_DIR/web_sensitive/sensitive_data_files.txt"
                fi
            fi
        fi
    done < "$OUTPUT_DIR/web_sensitive/paths_to_check.txt"

    echo
	echo -e "\n${BLUE}[*] URL scanning complete.${NC}"

    # Check for information disclosure in HTTP headers
    echo -e "${BLUE}[*] Checking for information disclosure in HTTP headers.${NC}"
    curl -s -I "$TARGET_URL" > "$OUTPUT_DIR/web_sensitive/http_headers.txt"

    # Check for exposed emails in website source
    echo -e "${BLUE}[*] Checking for exposed emails in website content.${NC}"
    wget -q --user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" -O "$OUTPUT_DIR/web_sensitive/index.html" "$TARGET_URL"

    grep -oE "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}" "$OUTPUT_DIR/web_sensitive/index.html" > "$OUTPUT_DIR/web_sensitive/emails.txt"

    # Compile summary
    echo -e "${BLUE}[*] Generating summary report.${NC}"
    {
      echo "Web Sensitive Information Report"
      echo "-------------------------------"
      echo "Date: $DATESTAMP $TIMESTAMP"
      echo "Target URL: $TARGET_URL"
      echo "-------------------------------"
      echo

      echo "[*] Sensitive Paths from robots.txt:"
      if [ -s "$OUTPUT_DIR/web_sensitive/sensitive_paths.txt" ]; then
          echo "  Found $(wc -l < "$OUTPUT_DIR/web_sensitive/sensitive_paths.txt") potentially sensitive paths"
          cat "$OUTPUT_DIR/web_sensitive/sensitive_paths.txt" | sed 's/^/  - /'
      else
          echo "  None found or robots.txt not available."
      fi

      echo
      echo "[*] Found Sensitive URLs:"
      if [ -s "$OUTPUT_DIR/web_sensitive/found_paths.txt" ]; then
          echo "  Found $(wc -l < "$OUTPUT_DIR/web_sensitive/found_paths.txt") potentially sensitive URLs"
          cat "$OUTPUT_DIR/web_sensitive/found_paths.txt" | sed 's/^/  - /'
      else
          echo "  None found."
      fi

      echo
      echo "[*] HTTP Headers Information:"
      if [ -s "$OUTPUT_DIR/web_sensitive/http_headers.txt" ]; then
          echo "  Server Information:"
          grep -i "server:" "$OUTPUT_DIR/web_sensitive/http_headers.txt" | sed 's/^/  - /'
          echo "  X-Headers (may contain system information):"
          grep -i "^x-" "$OUTPUT_DIR/web_sensitive/http_headers.txt" | sed 's/^/  - /'
      else
          echo "  Could not retrieve HTTP headers."
      fi

      echo
      echo "[*] Exposed Email Addresses:"
      if [ -s "$OUTPUT_DIR/web_sensitive/emails.txt" ]; then
          echo "  Found $(wc -l < "$OUTPUT_DIR/web_sensitive/emails.txt") email addresses"
          cat "$OUTPUT_DIR/web_sensitive/emails.txt" | sort -u | sed 's/^/  - /'
      else
          echo "  None found."
      fi

    } > "$OUTPUT_DIR/web_sensitive_summary.txt"

    echo
    echo -e "${YELLOW}[*] Web scan complete. Results saved to $OUTPUT_DIR/web_sensitive_summary.txt${NC}"
    echo
}

# Main function
f_sensitive_main(){
    NAME="$DATESTAMP_$TIMESTAMP"

    echo -e "${BLUE}Sensitive Information Detector${NC}"
    echo
    echo "1. File or folder"
    echo "2. URL"
    echo "3. Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
        1)
           echo
           echo -n "Enter path to scan: "
           read -r SCAN_DIR

           if [ ! -d "$SCAN_DIR" ]; then
               echo
               echo -e "${RED}[!] This file or folder does not exist.${NC}"
               echo
               exit 1
           fi

           f_scan_files "$SCAN_DIR" "$NAME" ;;
        2)
           echo
           echo -n "Enter URL to scan (e.g., https://example.com): "
           read -r TARGET_URL

           if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
               echo
               echo -e "${RED}[!] Invalid URL.${NC}"
               echo
               exit 1
           fi

           f_scan_web "$TARGET_URL" "$NAME" ;;
        3) f_main ;;
        *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; clear && f_banner && f_sensitive_main ;;
    esac
}

# Run the script
f_sensitive_main
