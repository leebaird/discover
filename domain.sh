#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

DISCOVER="${DISCOVER:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
export DISCOVER

shopt -u expand_aliases 2>/dev/null || true

DISCOVER_SOURCE_ONLY=1 source "$DISCOVER/discover.sh"

f_regdomain_die(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $1${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
}

f_regdomain_warn(){
    echo
    echo -e "${YELLOW}[!] $1${NC}"
    echo
}

f_regdomain_log_error(){
    local domain="$1"
    local reason="$2"

    if [ -z "$REGDOMAIN_TMPDIR" ] || [ ! -d "$REGDOMAIN_TMPDIR" ]; then
        return
    fi

    (
        flock -x 203
        printf '%s,%s\n' "$domain" "$reason" >> "$REGDOMAIN_TMPDIR/errors.log"
    ) 203>"$REGDOMAIN_TMPDIR/errors.lock"
}

f_regdomain_filter_privacy_email(){
    local email="$1"
    local localpart

    if [[ "$email" == *'@abuse.'* || "$email" == abuse@* || "$email" == *'anonymize.com'* || "$email" == *'buydomains.com'* || "$email" == *'cloudflareregistrar.com'* || "$email" == *'contact-form'* || "$email" == *'contact.gandi.net'* || "$email" == *'csl-registrar.com'* || "$email" == *'domaindiscreet.com'* || "$email" == *'gname.com'* || "$email" == *'identity-protect.org'* || "$email" == *'meshdigital.com'* || "$email" == *'mydomainprovider.com'* || "$email" == *'myprivatename.com'* || "$email" == *'networksolutionsprivateregistration'* || "$email" == *'please'* || "$email" == *'p.o-w-o.info'* || "$email" == *'privacy'* || "$email" == *'Redacted'* || "$email" == *'redacted'* || "$email" == *'select@'* || "$email" == *'tieredaccess.com'* || "$email" == *'whoisproxy.org'* ]]; then
        email=''
    fi

    if [ -n "$email" ]; then
        localpart="${email%%@*}"
        if [[ "$localpart" =~ ^[0-9a-f]{20,}$ ]]; then
            email=''
        fi
    fi

    printf '%s' "$email"
}

f_regdomain_read_report(){
    echo
    echo -n "Enter the location of your previous passive scan: "
    read -r DISCOVER_REPORT

    DISCOVER_REPORT="${DISCOVER_REPORT#"${DISCOVER_REPORT%%[![:space:]]*}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT%"${DISCOVER_REPORT##*[![:space:]]}"}"
    DISCOVER_REPORT="${DISCOVER_REPORT/#\~/$HOME}"

    if [ -z "$DISCOVER_REPORT" ] \
        || [ -f "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT" ] \
        || [ ! -r "$DISCOVER_REPORT" ] \
        || [ ! -x "$DISCOVER_REPORT" ] \
        || [ ! -d "$DISCOVER_REPORT/pages" ] \
        || [ ! -f "$DISCOVER_REPORT/pages/registered-domains.htm" ]; then
        f_regdomain_die "Passive scan not found."
    fi
}

f_regdomain_build_rows(){
    local RESULTS_FILE="$1"
    local ROWS_FILE="$2"

    if [ ! -s "$RESULTS_FILE" ]; then
        printf '                <tr><td colspan="2">No registration data found.</td></tr>\n' > "$ROWS_FILE"
        return 0
    fi

    python3 - "$RESULTS_FILE" "$ROWS_FILE" <<'PY'
import csv
import html
import sys

results_path, rows_path = sys.argv[1], sys.argv[2]
lines = []
with open(results_path, newline="") as handle:
    for row in csv.reader(handle):
        if len(row) < 2:
            continue
        domain, email = row[0].strip(), row[1].strip() if len(row) > 1 else ""
        if domain.lower() == "domain" or not domain:
            continue
        lines.append(
            "                <tr>"
            f"<td>{html.escape(domain)}</td>"
            f"<td>{html.escape(email)}</td>"
            "</tr>"
        )

if not lines:
    lines.append('                <tr><td colspan="2">No registration data found.</td></tr>')

with open(rows_path, "w") as handle:
    handle.write("\n".join(lines) + "\n")
PY
}

f_regdomain_patch_table(){
    local ROWS_FILE="$1"
    local TARGET_FILE="$2"

    [ -f "$TARGET_FILE" ] || return 0

    python3 - "$ROWS_FILE" "$TARGET_FILE" <<'PY'
import re
import sys

rows = open(sys.argv[1]).read()
path = sys.argv[2]
text = open(path).read()
new_text, count = re.subn(
    r"(<tbody>).*?(</tbody>)",
    r"\1\n" + rows + r"            \2",
    text,
    count=1,
    flags=re.S,
)
if count:
    open(path, "w").write(new_text)
PY
}

f_regdomain_write_report(){
    local RESULTS_FILE="$1"
    local REPORT_PAGE="$2"
    local ROWS_FILE="$3"

    f_regdomain_build_rows "$RESULTS_FILE" "$ROWS_FILE"
    f_regdomain_patch_table "$ROWS_FILE" "$REPORT_PAGE"
}

f_regdomain_read_file(){
    echo
    echo -n "Enter the location of your reversewhois.io file: "
    read -r LOCATION

    LOCATION="${LOCATION#"${LOCATION%%[![:space:]]*}"}"
    LOCATION="${LOCATION%"${LOCATION##*[![:space:]]}"}"

    if [ -z "$LOCATION" ]; then
        f_regdomain_die "No file location provided."
    fi

    LOCATION="${LOCATION/#\~/$HOME}"

    if [ ! -f "$LOCATION" ]; then
        f_regdomain_die "Input file not found: $LOCATION"
    fi

    if [ ! -r "$LOCATION" ]; then
        f_regdomain_die "Input file is not readable: $LOCATION"
    fi

    if ! grep -q '^[0-9]' "$LOCATION" 2>/dev/null; then
        f_regdomain_die "No reversewhois.io entries found. Paste must include numbered rows (lines starting with a digit)."
    fi
}

f_regdomain_extract_search_email(){
    local input="$1"
    local email

    email=$(grep -vi '^[0-9]' "$input" | grep -oiE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | head -1 | tr '[:upper:]' '[:lower:]')
    f_regdomain_filter_privacy_email "$email"
}

f_regdomain_parse_whois_email(){
    local whois_data="$1"
    local regemail

    regemail=$(
        grep -iE '^(Registry Registrant Email|Registrant Email):' <<< "$whois_data" \
            | grep -oiE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
            | head -1 \
            | tr '[:upper:]' '[:lower:]'
    )
    f_regdomain_filter_privacy_email "$regemail"
}

f_regdomain_check_lookup_network(){
    RDAP_SKIP=0

    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        if ! curl -4 -fsS --max-time 5 "https://rdap.org/domain/example.com" >/dev/null 2>"$REGDOMAIN_TMPDIR/rdap.test.err"; then
            RDAP_SKIP=1
            f_regdomain_warn "RDAP unreachable over IPv4. Skipping RDAP; using WHOIS only."
        fi
    else
        RDAP_SKIP=1
    fi

    if ! timeout 8 whois -H example.com >/dev/null 2>"$REGDOMAIN_TMPDIR/whois.test.err"; then
        if [ -s "$REGDOMAIN_TMPDIR/whois.test.err" ]; then
            sed 's/^/    /' "$REGDOMAIN_TMPDIR/whois.test.err" | head -3
            echo
        fi
        f_regdomain_die "WHOIS lookups are unreachable. Check network connectivity and try again."
    fi
}

f_regdomain_fetch_rdap_email(){
    local domain="$1"
    local json regemail

    [ "${RDAP_SKIP:-0}" -eq 1 ] && return 1
    command -v jq >/dev/null 2>&1 || return 1
    command -v curl >/dev/null 2>&1 || return 1

    json=$(curl -4 -fsS --max-time 5 "https://rdap.org/domain/${domain}" 2>/dev/null)
    if [ -z "$json" ] || echo "$json" | jq -e '.errorCode' >/dev/null 2>&1; then
        return 1
    fi

    if ! echo "$json" | jq -e '.ldhName // .handle // .unicodeName' >/dev/null 2>&1; then
        return 1
    fi

    regemail=$(echo "$json" | jq -r '([.entities[]? | select(.roles[]? == "registrant") | .vcardArray[1][]? | select(.[0] == "email") | .[3]] | first) // empty' | tr '[:upper:]' '[:lower:]')
    regemail=$(f_regdomain_filter_privacy_email "$regemail")
    printf '%s' "$regemail"
    return 0
}

f_regdomain_whois_lookup(){
    local domain="$1"
    local whois_raw whois_data whois_exit

    (
        flock -x 200
        sleep "$WHOIS_DELAY"
        whois_raw=$(timeout 10 whois -H "$domain" 2>/dev/null)
        whois_exit=$?
        whois_data=$(grep -Eiv '(^#|please query the|personal data|redacted for privacy|you agree to)' <<< "$whois_raw" | sed '/^$/d')

        if [ "$whois_exit" -eq 124 ]; then
            f_regdomain_log_error "$domain" "whois timed out"
        elif [ "$whois_exit" -ne 0 ]; then
            f_regdomain_log_error "$domain" "whois failed (exit $whois_exit)"
        elif [ -z "$whois_data" ]; then
            f_regdomain_log_error "$domain" "whois returned no data"
        fi

        printf '%s' "$whois_data"
    ) 200>"$WHOIS_LOCK"
}

f_regdomain_process_domain(){
    local regdomain="$1"
    local default_email="$2"
    local regemail whois_data attempt

    if regemail=$(f_regdomain_fetch_rdap_email "$regdomain"); then
        if [ -z "$regemail" ]; then
            for attempt in 1 2 3; do
                whois_data=$(f_regdomain_whois_lookup "$regdomain")
                regemail=$(f_regdomain_parse_whois_email "$whois_data")
                [ -n "$regemail" ] && break
                [ "$attempt" -lt 3 ] && sleep 1
            done
        fi
    else
        for attempt in 1 2 3; do
            whois_data=$(f_regdomain_whois_lookup "$regdomain")
            regemail=$(f_regdomain_parse_whois_email "$whois_data")
            [ -n "$regemail" ] && break
            [ "$attempt" -lt 3 ] && sleep 1
        done
    fi

    if [ -z "$regemail" ] && [ -n "$default_email" ]; then
        regemail="$default_email"
    fi

    if [ -z "$regemail" ]; then
        f_regdomain_log_error "$regdomain" "no registration email"
    fi

    printf '%s,%s' "$regdomain" "$regemail"
}

f_regdomain_wait_for_slot(){
    while true; do
        if (
            flock -x 300
            running=$(cat "$REGDOMAIN_TMPDIR/running" 2>/dev/null)
            running=${running:-0}
            if [ "$running" -lt "$WHOIS_JOBS" ]; then
                echo $((running + 1)) > "$REGDOMAIN_TMPDIR/running"
                exit 0
            fi
            exit 1
        ) 300>"$REGDOMAIN_TMPDIR/running.lock"; then
            return 0
        fi

        wait -n 2>/dev/null || sleep 0.3
    done
}

f_regdomain_release_slot(){
    (
        flock -x 300
        running=$(cat "$REGDOMAIN_TMPDIR/running" 2>/dev/null)
        running=${running:-1}
        if [ "$running" -gt 0 ]; then
            echo $((running - 1)) > "$REGDOMAIN_TMPDIR/running"
        else
            echo 0 > "$REGDOMAIN_TMPDIR/running"
        fi
    ) 300>"$REGDOMAIN_TMPDIR/running.lock"
}

f_regdomain_report_progress(){
    local total="$1"
    local phase="${2:-done}"
    local started completed

    (
        flock -x 201
        started=$(cat "$REGDOMAIN_TMPDIR/started" 2>/dev/null)
        started=${started:-0}
        completed=$(cat "$REGDOMAIN_TMPDIR/progress" 2>/dev/null)
        completed=${completed:-0}

        if [ "$phase" = "start" ]; then
            started=$((started + 1))
            echo "$started" > "$REGDOMAIN_TMPDIR/started"
            printf 'Lookup %s of %s (%s completed)\r' "$started" "$total" "$completed" >&2
        else
            completed=$((completed + 1))
            echo "$completed" > "$REGDOMAIN_TMPDIR/progress"
            started=$(cat "$REGDOMAIN_TMPDIR/started" 2>/dev/null)
            started=${started:-0}
            if [ "$completed" -eq 1 ] || [ $((completed % 25)) -eq 0 ]; then
                echo "[*] Lookup progress: $completed of $total completed"
            fi
            printf 'Lookup %s of %s (%s completed)\r' "$started" "$total" "$completed" >&2
        fi
    ) 201>"$REGDOMAIN_TMPDIR/progress.lock"
}

f_firefox_running(){
    pgrep -x firefox >/dev/null 2>&1 \
        || pgrep -x firefox-bin >/dev/null 2>&1 \
        || pgrep -x firefox-esr >/dev/null 2>&1 \
        || pgrep -f '/[f]irefox/' >/dev/null 2>&1
}

f_firefox_check(){
    if f_firefox_running; then
        echo
        echo "[!] Close all Firefox instances before running script."
        echo
        return 1
    fi
}

f_firefox_user_agents(){
    USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.86"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:145.0) Gecko/20100101 Firefox/145.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/147.0.6778.73 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 15; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.6778.39 Mobile Safari/537.36"
    "Mozilla/5.0 (Android 15; Mobile; rv:145.0) Gecko/145.0 Firefox/145.0"
    )
}

f_breaches() {
    local USER_AGENTS BREACH_URLS url USER_AGENT

    f_firefox_user_agents

    BREACH_URLS=(
    "https://app.dehashed.com"
    "https://intelx.io"
    "https://leak-lookup.com"
    "https://leakcheck.io"
    "https://leakradar.io"
    "https://www.proxynova.com/tools/comb"
    "https://snusbase.com"
    )

    for url in "${BREACH_URLS[@]}"; do
        USER_AGENT="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$USER_AGENT" 2>/dev/null &
        sleep 1
    done
}

f_google_dorks() {
    local USER_AGENTS GOOGLE_URLS GOOGLE_INTEXT_EXCLUDE url USER_AGENT

    GOOGLE_INTEXT_EXCLUDE='-intext:%22MANAGEMENT%27S+DISCUSSION+AND+ANALYSIS%22+-intext:%22General+Services+Administration%22+-intext:public'

    f_firefox_user_agents

    GOOGLE_URLS=(
    "https://www.google.com/search?q=%22$COMPANYURL%22+logo"
    "https://www.google.com/search?q=site:http://s3.amazonaws.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://blob.core.windows.net+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:dev.azure.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://drive.google.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://googleapis.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:pastebin.com+%22$DOMAIN%22+password"
    "https://www.google.com/search?q=site:$DOMAIN+username+OR+password+OR+login+-Find+$GOOGLE_INTEXT_EXCLUDE"
    "https://www.google.com/search?q=site:$DOMAIN+ext:(doc+|docx+|xls+|xlsx+|ppt+|pptx)+$GOOGLE_INTEXT_EXCLUDE"
    "https://www.google.com/search?q=site:$DOMAIN+(filetype:pdf+OR+filetype:txt)+$GOOGLE_INTEXT_EXCLUDE"
    "https://www.google.com/search?q=site:$DOMAIN+%22index+of/%22+OR+%22parent+directory%22+$GOOGLE_INTEXT_EXCLUDE"
    "https://www.google.com/search?q=site:$DOMAIN+(%22highly+confidential%22+OR+%22restricted+access%22+OR+%22sensitive+data%22+OR+%22social+security+number%22+OR+%22passport+number%22+OR+%22employee+details%22+OR+%22salary+report%22+OR+%22performance+review%22+OR+%22personal+information%22+OR+%22internal+use+only%22+OR+%22proprietary+and+confidential%22)+$GOOGLE_INTEXT_EXCLUDE"
    "https://www.google.com/search?q=site:$DOMAIN+intitle%3Alogin+%7C+inurl%3Alogin+%7C+intitle%3Asignin+%7C+inurl%3Asignin+%7C+inurl%3Asecure+$GOOGLE_INTEXT_EXCLUDE"
    "https://www.google.com/search?q=site:$DOMAIN+ext:log+%7C+ext:txt+%7C+ext:conf+%7C+ext:cnf+%7C+ext:ini+%7C+ext:env+%7C+ext:sh+%7C+ext:bak+%7C+ext:backup+%7C+ext:swp+%7C+ext:old+%7C+ext:~+%7C+ext:git+%7C+ext:svn+%7C+ext:htpasswd+%7C+ext:htaccess+%7C+ext:json"
    )

    for url in "${GOOGLE_URLS[@]}"; do
        USER_AGENT="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$USER_AGENT" 2>/dev/null
        sleep $((RANDOM % 8 + 8))
    done
}

f_web_search() {
    local USER_AGENTS OTHER_URLS url USER_AGENT

    f_firefox_user_agents

    OTHER_URLS=(
    "https://dnsdumpster.com"
    "https://dockets.justia.com/search?parties=%22$COMPANYURL%22&cases=mostrecent"
    "https://intelx.io/?s=%40$DOMAIN&b=leaks.public.wikileaks,leaks.public.general,dumpster,documents.public.scihub"
    "https://networksdb.io/search/org/%22$COMPANYURL%22"
    "https://pentest-tools.com"
    "https://www.shodan.io/search?query=$DOMAIN"
    "https://viewdns.info"
    )

    for url in "${OTHER_URLS[@]}"; do
        USER_AGENT="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$USER_AGENT" 2>/dev/null &
        sleep $((RANDOM % 4 + 3))
    done
}

f_domain_menu(){
    clear
    f_banner

    echo -e "${BLUE}RECON${NC}"
    echo
    echo "1.  Passive"
    echo "2.  Breaches"
    echo "3.  Find registered domains"
    echo "4.  Google dorks"
    echo "5.  Web search"
    echo
    echo "6.  Import names"
    echo "7.  Import subdomains"
    echo
    echo "8.  Active"
    echo "9.  Previous menu"
    echo
    echo -n "Choice: "
    read -r CHOICE

    case "$CHOICE" in
    1) "$DISCOVER"/passive.sh && exit ;;
    98) "$DISCOVER"/passive.sh 98 && exit ;;
    99) "$DISCOVER"/passive.sh 99 && exit ;;
    2)  f_runlocally
        clear
        f_banner

        echo -e "${BLUE}Breaches.${NC}"
        f_breaches
        echo
        exit
        ;;
    3)  clear
        f_banner

        echo -e "${BLUE}Find registered domains.${NC}"

        for CMD in awk column flock python3 sort timeout whois; do
            if ! command -v "$CMD" >/dev/null 2>&1; then
                f_regdomain_die "$CMD is not installed. Run Discover update to install dependencies."
            fi
        done

        f_regdomain_read_report
        echo
        echo "Open a browser to https://www.reversewhois.io/"
        echo "Enter your domain and solve the captcha."
        echo "Select all > copy all of the text and paste into a new file."
        f_regdomain_read_file
        echo

        TMPDIR=$(mktemp -d)
        f_regdomain_cancel(){
            echo
            echo "[!] Scan cancelled."
            rm -rf "$TMPDIR" 2>/dev/null
            exit 130
        }
        trap f_regdomain_cancel INT TERM
        trap 'rm -rf "$TMPDIR"' EXIT
        REGDOMAIN_TMPDIR="$TMPDIR"
        export REGDOMAIN_TMPDIR TMPDIR

        WHOIS_DELAY="${WHOIS_DELAY:-1}"
        WHOIS_JOBS="${WHOIS_JOBS:-2}"
        WHOIS_LOCK="$TMPDIR/whois.lock"
        export WHOIS_DELAY WHOIS_LOCK

        grep '^[0-9]' "$LOCATION" | awk '{print $2}' | sed -e 's/^[0-9]*\.//' -e 's/\.$//' | grep -Ev '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | sort -u > "$TMPDIR/domains"
        TOTAL=$(wc -l < "$TMPDIR/domains" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

        if [ "$TOTAL" -eq 0 ]; then
            f_regdomain_die "No domains found in file."
        fi

        SEARCH_EMAIL=$(f_regdomain_extract_search_email "$LOCATION")
        if [ -n "$SEARCH_EMAIL" ]; then
            echo "[*] Using search email from paste: $SEARCH_EMAIL"
        fi

        if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
            f_regdomain_warn "jq or curl is not installed. RDAP lookups will be skipped; using WHOIS only."
            RDAP_SKIP=1
            export RDAP_SKIP
        fi

        echo "[*] Found $TOTAL domains in reversewhois file."
        echo "[*] Checking WHOIS/RDAP connectivity."
        f_regdomain_check_lookup_network
        export RDAP_SKIP

        echo "[*] Looking up registration emails ($WHOIS_JOBS parallel workers)."
        echo 0 > "$TMPDIR/progress"
        echo 0 > "$TMPDIR/started"
        echo 0 > "$TMPDIR/running"
        : > "$TMPDIR/errors.log"
        touch "$WHOIS_LOCK" "$TMPDIR/results"
        printf 'Lookup 0 of %s (0 completed)\r' "$TOTAL" >&2

        while read -r REGDOMAIN; do
            f_regdomain_wait_for_slot
            f_regdomain_report_progress "$TOTAL" start

            {
                result=$(f_regdomain_process_domain "$REGDOMAIN" "$SEARCH_EMAIL")
                (
                    flock -x 202
                    printf '%s\n' "$result" >> "$REGDOMAIN_TMPDIR/results"
                ) 202>"$REGDOMAIN_TMPDIR/results.lock"
                f_regdomain_report_progress "$TOTAL" done
                f_regdomain_release_slot
            } &
        done < "$TMPDIR/domains"

        wait
        echo >&2

        if [ -s "$TMPDIR/results" ]; then
            sort -t, -k1,1 -u "$TMPDIR/results" -o "$TMPDIR/results"
        fi

        RESULT_COUNT=$(wc -l < "$TMPDIR/results" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
        RESULT_COUNT=${RESULT_COUNT:-0}

        if [ "$RESULT_COUNT" -ne "$TOTAL" ]; then
            f_regdomain_die "Lookup incomplete. Expected $TOTAL domains, wrote $RESULT_COUNT."
        fi

        EMAIL_COUNT=$(awk -F, 'NF > 1 && $2 != "" { count++ } END { print count + 0 }' "$TMPDIR/results")

        if [ "$EMAIL_COUNT" -eq 0 ]; then
            if [ -s "$TMPDIR/errors.log" ]; then
                echo "[*] Lookup errors:"
                column -t -s ',' "$TMPDIR/errors.log" 2>/dev/null || cat "$TMPDIR/errors.log"
                echo
            fi
            f_regdomain_die "No registration emails found. Check network connectivity and WHOIS/RDAP access."
        fi

        if [ "$EMAIL_COUNT" -lt "$TOTAL" ]; then
            SKIPPED=$((TOTAL - EMAIL_COUNT))
            f_regdomain_warn "$SKIPPED of $TOTAL domains had no registration email."
        fi

        ROWS_FILE="$TMPDIR/registered-domains-rows.html"
        f_regdomain_write_report "$TMPDIR/results" "$DISCOVER_REPORT/pages/registered-domains.htm" "$ROWS_FILE"

        echo "$MEDIUM"
        echo
        echo "[*] Scan complete. Found $EMAIL_COUNT of $TOTAL domains with registration emails."
        echo
        echo -e "The HTML report was updated in ${YELLOW}$DISCOVER_REPORT${NC}"
        echo
        unset LOCATION DISCOVER_REPORT
        exit 0
        ;;
    4)  f_runlocally
        f_firefox_check || { f_domain_menu; return; }
        clear
        f_banner

        echo -e "${BLUE}Google dorks.${NC}"
        f_company_domain
        f_google_dorks
        echo
        exit
        ;;
    5)  f_runlocally
        f_firefox_check || { f_domain_menu; return; }
        clear
        f_banner

        echo -e "${BLUE}Web search.${NC}"
        f_company_domain
        f_web_search
        echo
        exit
        ;;
    6) "$DISCOVER"/import-names.sh && exit ;;
    7) "$DISCOVER"/import-subdomains.sh && exit ;;
    8) "$DISCOVER"/active.sh && exit ;;
    9) exec "$DISCOVER"/discover.sh ;;
    *) f_error ;;
    esac
}

f_domain_menu
