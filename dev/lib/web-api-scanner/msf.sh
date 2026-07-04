# Metasploit resource generation and single-session execution

WEBAPI_MSF_WORDLIST_RESOLVED=""
WEBAPI_MSF_USERPASS_RESOLVED=""
WEBAPI_MSF_PASSWORDS_RESOLVED=""
WEBAPI_MSF_MODULES_ROOT=""
WEBAPI_API_FORMATS=()

f_webapi_resolve_msf_data_file(){
    local leaf="$1"
    local override="${2:-}"
    local candidates=() msf_bin msf_root

    if [ -n "$override" ] && [ -f "$override" ]; then
        printf '%s' "$override"
        return 0
    fi

    candidates=(
        "/usr/share/metasploit-framework/data/wordlists/${leaf}"
        "/opt/metasploit-framework/embedded/framework/data/wordlists/${leaf}"
    )
    if command -v msfconsole >/dev/null 2>&1; then
        msf_bin=$(command -v msfconsole)
        msf_root=$(cd "$(dirname "$msf_bin")/.." && pwd)
        candidates+=(
            "${msf_root}/share/metasploit-framework/data/wordlists/${leaf}"
            "${msf_root}/framework/data/wordlists/${leaf}"
            "${msf_root}/data/wordlists/${leaf}"
        )
    fi

    local c
    for c in "${candidates[@]}"; do
        [ -f "$c" ] && { printf '%s' "$c"; return 0; }
    done
    return 1
}

f_webapi_msf_find_modules_root(){
    local candidates=() msf_bin msf_root
    candidates=(
        "/usr/share/metasploit-framework/modules"
        "/opt/metasploit-framework/embedded/framework/modules"
    )
    if command -v msfconsole >/dev/null 2>&1; then
        msf_bin=$(command -v msfconsole)
        msf_root=$(cd "$(dirname "$msf_bin")/.." && pwd)
        candidates+=(
            "${msf_root}/share/metasploit-framework/modules"
            "${msf_root}/framework/modules"
            "${msf_root}/modules"
        )
    fi
    local c
    for c in "${candidates[@]}"; do
        [ -d "$c" ] && { WEBAPI_MSF_MODULES_ROOT="$c"; return 0; }
    done
    WEBAPI_MSF_MODULES_ROOT=""
    return 1
}

f_webapi_msf_module_exists(){
    local mod="$1"
    local path="${WEBAPI_MSF_MODULES_ROOT}/${mod}.rb"
    [ -n "$WEBAPI_MSF_MODULES_ROOT" ] && [ -f "$path" ]
}

f_webapi_msf_prune_resource(){
    local src="$1" dst="$2"
    local line mod allow=0
    : > "$dst"
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            use\ *)
                mod=$(printf '%s' "$line" | awk '{print $2}')
                if [ "$WEBAPI_DRY_RUN" = "1" ] || [ -z "$WEBAPI_MSF_MODULES_ROOT" ] || f_webapi_msf_module_exists "$mod"; then
                    printf '%s\n' "$line" >> "$dst"
                    allow=1
                else
                    f_webapi_log "Skip unavailable module: $mod"
                    f_webapi_record_finding info "${WEBAPI_DOMAIN:-target}" "${WEBAPI_URL:-}" module_unavailable \
                        "MSF module not installed: $mod" "msf_engine/resources"
                    allow=0
                fi
                ;;
            check|run)
                [ "$allow" = "1" ] && printf '%s\n' "$line" >> "$dst"
                ;;
            set\ *|setg\ *)
                [ "$allow" = "1" ] && printf '%s\n' "$line" >> "$dst"
                ;;
            "")
                printf '\n' >> "$dst"
                ;;
            *)
                printf '%s\n' "$line" >> "$dst"
                ;;
        esac
    done < "$src"
}

f_webapi_load_api_path_formats(){
    local target_url="$1"
    local endpoints_file="${WEBAPI_SCAN_DIR}/api_scanner/all_endpoints.txt"
    WEBAPI_API_FORMATS=("/api/%s" "/v1/%s" "/v2/%s" "/rest/%s")
    [ -n "$WEBAPI_SCAN_DIR" ] && [ -f "$endpoints_file" ] || return 0
    while IFS= read -r fmt; do
        [ -n "$fmt" ] && WEBAPI_API_FORMATS+=("$fmt")
    done < <(python3 - "$endpoints_file" "$target_url" <<'PY'
import sys
from urllib.parse import urlparse

path_file, base = sys.argv[1], sys.argv[2]
base_host = urlparse(base).netloc
formats = set()
with open(path_file, encoding='utf-8', errors='replace') as fh:
    for line in fh:
        u = line.strip().split()[0] if line.strip() else ''
        if not u.startswith('http'):
            continue
        p = urlparse(u)
        if base_host and p.netloc and p.netloc != base_host:
            continue
        parts = [x for x in p.path.split('/') if x]
        if len(parts) >= 2:
            formats.add('/' + '/'.join(parts[:2]) + '/%s')
        elif len(parts) == 1:
            formats.add('/' + parts[0] + '/%s')
for f in sorted(formats):
    print(f)
PY
)
    f_webapi_log "API brute_dirs formats: ${#WEBAPI_API_FORMATS[@]}"
}

f_webapi_msf_write_api_security_rc(){
    local fmt
    f_webapi_load_api_path_formats "$1"
    {
        echo "use auxiliary/scanner/http/soap_xml"
        echo "run"
        echo "use auxiliary/scanner/http/brute_dirs"
        echo "set DICTIONARY ${WEBAPI_MSF_WORDLIST_RESOLVED}"
        for fmt in "${WEBAPI_API_FORMATS[@]}"; do
            echo "set FORMAT ${fmt}"
            echo "run"
        done
    } > "${WEBAPI_MSF_RESOURCE_DIR}/api_security.rc"
}

f_webapi_msf_resolve_wordlists(){
    local missing=()
    WEBAPI_MSF_WORDLIST_RESOLVED=$(f_webapi_resolve_msf_data_file "directory.txt" "${WEBAPI_MSF_WORDLIST:-}") || missing+=("directory.txt")
    WEBAPI_MSF_USERPASS_RESOLVED=$(f_webapi_resolve_msf_data_file "http_default_userpass.txt" "${WEBAPI_MSF_USERPASS:-}") || missing+=("http_default_userpass.txt")
    WEBAPI_MSF_PASSWORDS_RESOLVED=$(f_webapi_resolve_msf_data_file "common_passwords.txt" "${WEBAPI_MSF_PASSWORDS:-}") || missing+=("common_passwords.txt")

    if [ ${#missing[@]} -gt 0 ] && [ "$WEBAPI_PASSIVE" != "1" ] && [ "$WEBAPI_DRY_RUN" != "1" ]; then
        echo -e "${RED}[!] Missing Metasploit wordlists: ${missing[*]}${NC}"
        echo -e "${YELLOW}[*] Set WEBAPI_MSF_WORDLIST / WEBAPI_MSF_USERPASS / WEBAPI_MSF_PASSWORDS or install Metasploit.${NC}"
        return 1
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        WEBAPI_MSF_WORDLIST_RESOLVED="${WEBAPI_MSF_WORDLIST_RESOLVED:-/usr/share/metasploit-framework/data/wordlists/directory.txt}"
        WEBAPI_MSF_USERPASS_RESOLVED="${WEBAPI_MSF_USERPASS_RESOLVED:-/usr/share/metasploit-framework/data/wordlists/http_default_userpass.txt}"
        WEBAPI_MSF_PASSWORDS_RESOLVED="${WEBAPI_MSF_PASSWORDS_RESOLVED:-/usr/share/metasploit-framework/data/wordlists/common_passwords.txt}"
        f_webapi_log "Wordlist placeholders used (dry-run/passive): ${missing[*]}"
    else
        f_webapi_log "MSF wordlists: dir=${WEBAPI_MSF_WORDLIST_RESOLVED} userpass=${WEBAPI_MSF_USERPASS_RESOLVED}"
    fi
    return 0
}

f_webapi_msf_write_resources(){
    local target_url="${1:-$WEBAPI_URL}"
    f_webapi_msf_resolve_wordlists || return 1
    f_webapi_msf_find_modules_root || f_webapi_log "MSF modules root not found; skipping module availability checks"
    f_webapi_say "${BLUE}[*] Writing Metasploit resource scripts.${NC}"

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/web_recon.rc" <<'EOF'
use auxiliary/scanner/http/http_version
run
use auxiliary/scanner/http/robots_txt
run
use auxiliary/scanner/http/http_header
run
use auxiliary/scanner/http/ssl
run
use auxiliary/scanner/http/options
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/web_active.rc" <<EOF
use auxiliary/scanner/http/dir_scanner
set DICTIONARY ${WEBAPI_MSF_WORDLIST_RESOLVED}
run
use auxiliary/scanner/http/files_dir
run
use auxiliary/scanner/http/http_put
run
use auxiliary/scanner/http/webdav_scanner
run
use auxiliary/scanner/http/webdav_internal_ip
run
use auxiliary/scanner/http/web_crawl
set DEPTH 2
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/apache_vulns.rc" <<'EOF'
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

    f_webapi_msf_write_api_security_rc "$target_url"

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/drupal.rc" <<'EOF'
use auxiliary/scanner/http/drupal_scanner
setg THREADS 5
setg TIMEOUT 15
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/graphql.rc" <<'EOF'
use auxiliary/scanner/http/graphql_introspection
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/jenkins_vulns.rc" <<'EOF'
use auxiliary/scanner/http/jenkins_enum
run
use auxiliary/scanner/http/jenkins_command
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/oauth_openid.rc" <<'EOF'
use auxiliary/gather/oauth_key_leak
run
use auxiliary/scanner/http/oauth_token
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/jwt.rc" <<'EOF'
use auxiliary/scanner/http/jwt_scanner
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/sqli.rc" <<'EOF'
use auxiliary/scanner/http/blind_sql_query
run
use auxiliary/scanner/http/sql_injection
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/tomcat_vulns.rc" <<'EOF'
use auxiliary/scanner/http/tomcat_mgr_login
run
use auxiliary/admin/http/tomcat_administration
run
use auxiliary/admin/http/tomcat_utf8_traversal
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/wordpress.rc" <<'EOF'
use auxiliary/scanner/http/wordpress_scanner
setg THREADS 5
setg TIMEOUT 15
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/web_form_brute.rc" <<EOF
use auxiliary/scanner/http/http_login
set VERBOSE false
set STOP_ON_SUCCESS true
set BLANK_PASSWORDS true
set USER_AS_PASS true
set USERPASS_FILE ${WEBAPI_MSF_USERPASS_RESOLVED}
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/basic_auth_brute.rc" <<EOF
use auxiliary/scanner/http/http_login
set VERBOSE false
set STOP_ON_SUCCESS true
set AUTH_TYPE Basic
set BLANK_PASSWORDS true
set USER_AS_PASS true
set USERPASS_FILE ${WEBAPI_MSF_USERPASS_RESOLVED}
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/api_key_brute.rc" <<'EOF'
use auxiliary/scanner/http/http_login
set VERBOSE false
set STOP_ON_SUCCESS true
set BLANK_PASSWORDS false
set USER_AS_PASS false
set HEADER X-API-Key
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/jwt_brute.rc" <<EOF
use auxiliary/scanner/http/jwt_scanner
set VERBOSE false
set BRUTEFORCE true
set KEY_FILE ${WEBAPI_MSF_PASSWORDS_RESOLVED}
run
EOF

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/web_exploits.rc" <<'EOF'
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

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/api_exploits.rc" <<'EOF'
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

    local rc
    for rc in "${WEBAPI_MSF_RESOURCE_DIR}"/*.rc; do
        [ -f "$rc" ] || continue
        [[ "$rc" == */master.rc ]] && continue
        f_webapi_msf_prune_resource "$rc" "${rc}.pruned"
        mv "${rc}.pruned" "$rc"
    done
}

f_webapi_msf_write_master(){
    local target_url="$1" target_ip="$2" domain="$3"
    local ssl_flag port_flag workspace threads
    workspace="web_api_scan_$(date +%Y%m%d_%H%M%S)"
    threads=$(f_webapi_msf_threads_for_tier)
    WEBAPI_DOMAIN="$domain"

    if f_webapi_is_https "$target_url"; then
        ssl_flag=true
        port_flag=443
    else
        ssl_flag=false
        port_flag=80
    fi

    cat > "${WEBAPI_MSF_RESOURCE_DIR}/master.rc" <<EOF
workspace -a ${workspace}
setg RHOSTS ${target_ip}
setg RHOST ${target_ip}
setg VHOST ${domain}
setg DOMAIN ${domain}
setg SSL ${ssl_flag}
setg SRVPORT ${port_flag}
setg URI /
setg TARGETURI /
setg VERBOSE false
setg THREADS ${threads}
EOF
    if [ -n "$WEBAPI_PROXY" ]; then
        printf 'setg Proxies %s\n' "$WEBAPI_PROXY" >> "${WEBAPI_MSF_RESOURCE_DIR}/master.rc"
    fi
    if [ -n "$WEBAPI_BEARER_TOKEN" ]; then
        printf 'setg HttpHeaders Authorization: Bearer %s\n' "$WEBAPI_BEARER_TOKEN" >> "${WEBAPI_MSF_RESOURCE_DIR}/master.rc"
    fi
    if [ -n "$WEBAPI_COOKIE_FILE" ] && [ -f "$WEBAPI_COOKIE_FILE" ]; then
        printf 'setg COOKIEJAR %s\nsetg VALIDCOOKIES true\n' "$WEBAPI_COOKIE_FILE" >> "${WEBAPI_MSF_RESOURCE_DIR}/master.rc"
    fi
}

f_webapi_msf_phase_resource(){
    local phase="$1"
    case "$phase" in
        web_recon) echo "web_recon.rc" ;;
        web_active) echo "web_active.rc" ;;
        apache_security) echo "apache_vulns.rc" ;;
        api_security) echo "api_security.rc" ;;
        drupal_security) echo "drupal.rc" ;;
        graphql_security) echo "graphql.rc" ;;
        jenkins_security) echo "jenkins_vulns.rc" ;;
        oauth_security) echo "oauth_openid.rc" ;;
        jwt_security) echo "jwt.rc" ;;
        sqli_security) echo "sqli.rc" ;;
        tomcat_security) echo "tomcat_vulns.rc" ;;
        wordpress_security) echo "wordpress.rc" ;;
        web_auth_brute) echo "web_form_brute.rc" ;;
        basic_auth_brute) echo "basic_auth_brute.rc" ;;
        api_key_brute) echo "api_key_brute.rc" ;;
        jwt_brute) echo "jwt_brute.rc" ;;
        web_exploit_checks) echo "web_exploits.rc" ;;
        api_exploit_checks) echo "api_exploits.rc" ;;
        *) return 1 ;;
    esac
}

f_webapi_msf_phase_label(){
    local phase="$1"
    case "$phase" in
        web_recon) echo "Web Recon" ;;
        web_active) echo "Web Active Enumeration" ;;
        apache_security) echo "Apache Security" ;;
        api_security) echo "API Security" ;;
        drupal_security) echo "Drupal Security" ;;
        graphql_security) echo "GraphQL Security" ;;
        jenkins_security) echo "Jenkins Security" ;;
        oauth_security) echo "OAuth Security" ;;
        jwt_security) echo "JWT Security" ;;
        sqli_security) echo "SQL Injection" ;;
        tomcat_security) echo "Tomcat Security" ;;
        wordpress_security) echo "WordPress Security" ;;
        web_auth_brute) echo "Web Authentication Brute" ;;
        basic_auth_brute) echo "HTTP Basic Auth Brute" ;;
        api_key_brute) echo "API Key Brute" ;;
        jwt_brute) echo "JWT Brute" ;;
        web_exploit_checks) echo "Web Exploit Checks" ;;
        api_exploit_checks) echo "API Exploit Checks" ;;
        *) echo "$phase" ;;
    esac
}

f_webapi_msf_build_phase_session(){
    local phase="$1"
    local session_rc="${OUTPUT_DIR}/msf_engine/session_${phase}.rc"
    local resource spool_file

    resource=$(f_webapi_msf_phase_resource "$phase") || return 1
    spool_file="${OUTPUT_DIR}/msf_engine/spool/${phase}.txt"
    cat "${WEBAPI_MSF_RESOURCE_DIR}/master.rc" > "$session_rc"
    {
        echo "spool ${spool_file}"
        cat "${WEBAPI_MSF_RESOURCE_DIR}/${resource}"
        echo "spool off"
        echo "exit -y"
    } >> "$session_rc"
}

f_webapi_msf_build_session_manifest(){
    local -n phases_ref=$1
    local session_rc="${OUTPUT_DIR}/msf_engine/session.rc" phase
    {
        echo "# Planned phases (${#phases_ref[@]}); executed individually with timeouts"
        for phase in "${phases_ref[@]}"; do
            echo "# - ${phase}"
        done
    } > "$session_rc"
}

f_webapi_msf_parse_spool(){
    local phase="$1" spool_file="$2" domain="$3" target_url="$4"
    local label count=0 hit line parser
    label=$(f_webapi_msf_phase_label "$phase")
    parser="${WEBAPI_ROOT}/lib/web-api-scanner/msf_parse.py"

    [ -f "$spool_file" ] || {
        f_webapi_append_phase_result "$phase" "no_output" "0"
        return 0
    }

    local phase_hits="${OUTPUT_DIR}/msf_engine/spool/${phase}_hits.jsonl"
    : > "$phase_hits"
    count=$(python3 "$parser" "$spool_file" \
        --phase "$phase" \
        --phase-label "$label" \
        --domain "$domain" \
        --target "$target_url" \
        -o "$phase_hits" 2>/dev/null || echo 0)
    [ -n "$count" ] || count=0

    if [ -s "$phase_hits" ]; then
        while IFS= read -r hit; do
            [ -n "$hit" ] || continue
            f_webapi_record_hit_from_parser "$hit"
        done < "$phase_hits"
        cat "$phase_hits" >> "$WEBAPI_HITS_JSONL"
    fi

    f_webapi_append_phase_result "$phase" "ok" "$count"
    f_webapi_checkpoint_mark "$phase"
}

f_webapi_msf_run_one_phase(){
    local phase="$1" domain="$2" target_url="$3"
    local session_rc="${OUTPUT_DIR}/msf_engine/session_${phase}.rc"
    local spool_file="${OUTPUT_DIR}/msf_engine/spool/${phase}.txt"
    local rc=0

    f_webapi_msf_build_phase_session "$phase" || return 1
    f_webapi_say "${BLUE}[*] Phase: $(f_webapi_msf_phase_label "$phase") (${phase})${NC}"
    if command -v timeout >/dev/null 2>&1; then
        timeout --foreground "${WEBAPI_PHASE_TIMEOUT}" msfconsole -q -r "$session_rc" >> "$WEBAPI_SCAN_LOG" 2>&1 || rc=$?
        [ "$rc" -eq 124 ] && f_webapi_log "Phase timeout: $phase"
    else
        msfconsole -q -r "$session_rc" >> "$WEBAPI_SCAN_LOG" 2>&1 || rc=$?
    fi
    f_webapi_msf_parse_spool "$phase" "$spool_file" "$domain" "$target_url"
    f_webapi_sleep_between_phases
    return 0
}

f_webapi_msf_run_session(){
    local phases_name="$1"
    local -n phases_ref=$phases_name
    local domain="$2" target_url="$3"
    local phase rc=0

    f_webapi_msf_build_session_manifest "$phases_name"

    if [ "$WEBAPI_DRY_RUN" = "1" ]; then
        f_webapi_log "Dry-run: skipping msfconsole"
        for phase in "${phases_ref[@]}"; do
            f_webapi_msf_build_phase_session "$phase" || true
            f_webapi_append_phase_result "$phase" "dry_run" "0"
            f_webapi_checkpoint_mark "$phase"
        done
        return 0
    fi

    f_webapi_say "${BLUE}[*] Running ${#phases_ref[@]} MSF phases (per-phase timeout=${WEBAPI_PHASE_TIMEOUT}s).${NC}"
    for phase in "${phases_ref[@]}"; do
        f_webapi_msf_run_one_phase "$phase" "$domain" "$target_url" || rc=1
    done
    return "$rc"
}