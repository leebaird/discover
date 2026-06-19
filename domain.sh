#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

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

    if [[ "$email" == *'abuse'* || "$email" == *'anonymize.com'* || "$email" == *'buydomains.com'* || "$email" == *'cloudflareregistrar.com'* || "$email" == *'contact-form'* || "$email" == *'contact.gandi.net'* || "$email" == *'csl-registrar.com'* || "$email" == *'domaindiscreet.com'* || "$email" == *'dynadot.com'* || "$email" == *'email'* || "$email" == *'gname.com'* || "$email" == *'google.com'* || "$email" == *'identity-protect.org'* || "$email" == *'meshdigital.com'* || "$email" == *'mydomainprovider.com'* || "$email" == *'myprivatename.com'* || "$email" == *'networksolutionsprivateregistration'* || "$email" == *'please'* || "$email" == *'p.o-w-o.info'* || "$email" == *'privacy'* || "$email" == *'Redacted'* || "$email" == *'redacted'* || "$email" == *'select'* || "$email" == *'tieredaccess.com'* ]]; then
        email=''
    fi

    printf '%s' "$email"
}

f_regdomain_normalize_org(){
    local org="$1"

    org=$(sed 's/     //g; s/administration/Administration/g; s/Anonymize, Inc/Anonymize Inc/g; s/By /by /g; s/, Corp/ Corp/g; s/Data Protected//g; s/family/Family/g; s/Identity Protect Limited//g; s/Identity Protection Service//g; s/, Inc. / Inc/g; s/, Inc/ Inc/g; s/, Inc /Inc/g; s/Inc./Inc/g; s/INFORMATION SYSTEMS AND MANAGEMENT CONSLANTS/Information Systems and Management Consultants/g; s/INSTITUTE/Institute/g; s/, LLC/ LLC/g; s/MEMORIAL/Memorial/g; s/, N.A./ N.A./g; s/N\/A//g; s/Not Disclosed//g; s/None//g; s/NULL//g; s/ (NYHQ)//g; s/Redacted for privacy//g; s/S.L./SL/g; s/Statutory Masking Enabled//g; s/UNIVERSITY/University/g; s/(US) //g; s/WEST VIRGINIA/West Virginia/g' <<< "$org")

    if [[ "$org" == *'Privacy'* || "$org" == *'PRIVACY'* ]]; then
        org=''
    fi

    printf '%s' "$org"
}

f_regdomain_normalize_registrar(){
    local registrar="$1"

    registrar=$(sed 's/Co.,/Co./g; s/Corp.,/Corp/g; s/Hongkong/Hong Kong/g; s/Identity Protection Service//g; s/Gransy,/Gransy/g; s/, Inc/ Inc/g; s/Inc./Inc/g; s/IncUSA/Inc/g; s/KEY-SYSTEMS/Key-Systems/g; s/Limited,/Ltd /g; s/, LLC/ LLC/g; s/Ltd./Ltd/g; s/, Ltd/ Ltd/g; s/MARKMONITOR/MarkMonitor/g; s/MarkMonitor./MarkMonitor /g; s/Registrar://g; s/REGISTRAR OF DOMAIN NAMES//g; s/s.l./SL/g; s/, S.L./SL/g; s/technologies/Technologies/g; s/technology/Technology/g; s/^[ \t]*//' <<< "$registrar" | head -n1)

    if [[ "$registrar" == 'Domains' ]]; then
        registrar=''
    fi

    printf '%s' "$registrar"
}

f_regdomain_parse_whois_data(){
    local whois_data="$1"
    local regemail regorg registrar

    regemail=$(grep 'Registrant Email:' <<< "$whois_data" | cut -d ' ' -f3 | tr '[:upper:]' '[:lower:]')
    regemail=$(f_regdomain_filter_privacy_email "$regemail")

    regorg=$(grep 'Registrant Organization:' <<< "$whois_data" | cut -d ':' -f2 | cut -d ' ' -f2-)
    regorg=$(f_regdomain_normalize_org "$regorg")

    registrar=$(grep 'Registrar:' <<< "$whois_data" | cut -d ' ' -f2-)
    registrar=$(f_regdomain_normalize_registrar "$registrar")

    printf '%s|%s|%s' "$regemail" "$regorg" "$registrar"
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

f_regdomain_fetch_rdap_fields(){
    local domain="$1"
    local json regemail regorg registrar

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

    regorg=$(echo "$json" | jq -r '([.entities[]? | select(.roles[]? == "registrant") | .vcardArray[1][]? | select(.[0] == "org") | .[3]] | first) // ([.entities[]? | select(.roles[]? == "registrant") | .vcardArray[1][]? | select(.[0] == "fn") | .[3]] | first) // empty')
    regorg=$(f_regdomain_normalize_org "$regorg")

    registrar=$(echo "$json" | jq -r '([.entities[]? | select(.roles[]? == "registrar") | .vcardArray[1][]? | select(.[0] == "fn") | .[3]] | first) // empty')
    registrar=$(f_regdomain_normalize_registrar "$registrar")

    printf '%s|%s|%s' "$regemail" "$regorg" "$registrar"
}

f_regdomain_whois_lookup(){
    local domain="$1"
    local whois_raw whois_data whois_exit

    (
        flock -x 200
        sleep "$WHOIS_DELAY"
        whois_raw=$(timeout 10 whois -H "$domain" 2>/dev/null)
        whois_exit=$?
        whois_data=$(grep -Eiv '(#|please query|personal data|redacted|whois|you agree)' <<< "$whois_raw" | sed '/^$/d')

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
    local ipaddr="$2"
    local fields regemail regorg registrar result

    if fields=$(f_regdomain_fetch_rdap_fields "$regdomain"); then
        IFS='|' read -r regemail regorg registrar <<< "$fields"
        if [ -z "$regemail" ] && [ -z "$regorg" ] && [ -z "$registrar" ]; then
            fields=$(f_regdomain_parse_whois_data "$(f_regdomain_whois_lookup "$regdomain")")
            IFS='|' read -r regemail regorg registrar <<< "$fields"
        fi
    else
        fields=$(f_regdomain_parse_whois_data "$(f_regdomain_whois_lookup "$regdomain")")
        IFS='|' read -r regemail regorg registrar <<< "$fields"
    fi

    result=$(echo "$regdomain,$ipaddr,$regemail,$regorg,$registrar" | grep -v ',,,,' || true)
    if [ -z "$result" ]; then
        f_regdomain_log_error "$regdomain" "no registration data"
    fi

    printf '%s' "$result"
}

f_regdomain_batch_dns(){
    local domains_file="$1"
    local output_file="$2"
    local dns_jobs="${DNS_JOBS:-16}"
    local total

    if ! command -v dig >/dev/null 2>&1; then
        return 1
    fi

    total=$(wc -l < "$domains_file" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
    echo 0 > "$REGDOMAIN_TMPDIR/dns.progress"
    printf '  DNS 0/%s\r' "$total" >&2

    if ! xargs -P "$dns_jobs" -a "$domains_file" -I{} bash -c '
        domain="{}"
        ip=$(dig +short +time=2 +tries=1 "$domain" 2>/dev/null | grep -Eiv "(0.0.0.0|127.0.0.1|127.0.0.6)" | sed "/[a-z]/d" | tr "\n" " " | sed "s/ $//")
        printf "%s,%s\n" "$domain" "$ip"
        (
            flock -x 304
            n=$(($(cat "$REGDOMAIN_TMPDIR/dns.progress" 2>/dev/null || echo 0) + 1))
            echo "$n" > "$REGDOMAIN_TMPDIR/dns.progress"
            printf "  DNS %s/%s\r" "$n" "'"$total"'" >&2
        ) 304>"$REGDOMAIN_TMPDIR/dns.progress.lock"
    ' > "$output_file"; then
        return 1
    fi

    echo >&2

    if [ ! -s "$output_file" ]; then
        return 1
    fi

    return 0
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
        printf '                <tr><td colspan="5">No registration data found.</td></tr>\n' > "$ROWS_FILE"
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
        if len(row) < 1:
            continue
        while len(row) < 5:
            row.append("")
        domain, ipaddr, email, org, registrar = [cell.strip() for cell in row[:5]]
        if domain.lower() == "domain" or not domain:
            continue
        if not any((ipaddr, email, org, registrar)):
            continue
        lines.append(
            "                <tr>"
            f"<td>{html.escape(domain)}</td>"
            f"<td>{html.escape(ipaddr)}</td>"
            f"<td>{html.escape(email)}</td>"
            f"<td>{html.escape(org)}</td>"
            f"<td>{html.escape(registrar)}</td>"
            "</tr>"
        )

if not lines:
    lines.append('                <tr><td colspan="5">No registration data found.</td></tr>')

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
    local REPORT_DIR="$2"
    local ROWS_FILE="$3"

    f_regdomain_build_rows "$RESULTS_FILE" "$ROWS_FILE"
    f_regdomain_patch_table "$ROWS_FILE" "$REPORT_DIR/pages/registered-domains.htm"
    f_regdomain_patch_table "$ROWS_FILE" "$REPORT_DIR/data/registered-domains.htm"
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

clear
f_banner

echo -e "${BLUE}RECON${NC}"
echo
echo "1.  Passive"
echo "2.  Find registered domains"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1) "$DISCOVER"/passive.sh && exit ;;
    2)  clear
        f_banner

        echo -e "${BLUE}Find registered domains.${NC}"

        for CMD in awk column dig flock python3 sort timeout whois xargs; do
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

        ERROR_LOG=""

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

        WHOIS_DELAY="${WHOIS_DELAY:-0.5}"
        WHOIS_JOBS="${WHOIS_JOBS:-4}"
        WHOIS_LOCK="$TMPDIR/whois.lock"
        export WHOIS_DELAY WHOIS_LOCK

        grep '^[0-9]' "$LOCATION" | awk '{print $2}' | sort -u > "$TMPDIR/domains"
        TOTAL=$(wc -l < "$TMPDIR/domains" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

        if [ "$TOTAL" -eq 0 ]; then
            f_regdomain_die "No domains found in file."
        fi

        if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
            f_regdomain_warn "jq or curl is not installed. RDAP lookups will be skipped; using WHOIS only."
            RDAP_SKIP=1
            export RDAP_SKIP
        fi

        echo "[*] Resolving $TOTAL domains in parallel."
        f_regdomain_batch_dns "$TMPDIR/domains" "$TMPDIR/dns.map"
        DNS_RC=$?

        if [ "$DNS_RC" -ne 0 ]; then
            f_regdomain_die "DNS resolution failed. Check that dig is installed and working."
        fi

        echo "[*] DNS complete."

        MAP_TOTAL=$(wc -l < "$TMPDIR/dns.map" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
        if [ "$MAP_TOTAL" -ne "$TOTAL" ]; then
            f_regdomain_die "DNS mapping failed. Expected $TOTAL entries, got $MAP_TOTAL."
        fi

        echo "[*] Checking WHOIS/RDAP connectivity."
        f_regdomain_check_lookup_network
        export RDAP_SKIP

        echo "[*] Looking up registration data ($WHOIS_JOBS parallel workers)."
        echo 0 > "$TMPDIR/progress"
        echo 0 > "$TMPDIR/started"
        echo 0 > "$TMPDIR/running"
        : > "$TMPDIR/errors.log"
        touch "$WHOIS_LOCK" "$TMPDIR/results"
        printf 'Lookup 0 of %s (0 completed)\r' "$TOTAL" >&2

        while IFS=, read -r REGDOMAIN IPADDR; do
            f_regdomain_wait_for_slot
            f_regdomain_report_progress "$TOTAL" start

            {
                result=$(f_regdomain_process_domain "$REGDOMAIN" "$IPADDR")
                if [ -n "$result" ]; then
                    (
                        flock -x 202
                        printf '%s\n' "$result" >> "$REGDOMAIN_TMPDIR/results"
                    ) 202>"$REGDOMAIN_TMPDIR/results.lock"
                fi
                f_regdomain_report_progress "$TOTAL" done
                f_regdomain_release_slot
            } &
        done < "$TMPDIR/dns.map"

        wait
        echo >&2

        RESULT_COUNT=$(wc -l < "$TMPDIR/results" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
        RESULT_COUNT=${RESULT_COUNT:-0}

        if [ "$RESULT_COUNT" -eq 0 ]; then
            if [ -s "$TMPDIR/errors.log" ]; then
                echo "[*] Lookup errors:"
                column -t -s ',' "$TMPDIR/errors.log" 2>/dev/null || cat "$TMPDIR/errors.log"
                echo
            fi
            f_regdomain_die "No registration data collected. Check network connectivity and input file format."
        fi

        if [ "$RESULT_COUNT" -lt "$TOTAL" ]; then
            SKIPPED=$((TOTAL - RESULT_COUNT))
            f_regdomain_warn "$SKIPPED of $TOTAL domains produced no registration data."
        fi

        sort -t, -k1,1 "$TMPDIR/results" > "$TMPDIR/tmp3"

        mkdir -p "$HOME/data" || f_regdomain_die "Cannot create $HOME/data."

        REPORT_TXT="$HOME/data/registered-domains.txt"
        echo "Domain,IP Address,Registration Email,Registration Org,Registrar" > "$TMPDIR/tmp4"
        # Drop rows that are bare IPs (malformed reversewhois.io paste lines).
        if ! cat "$TMPDIR/tmp4" "$TMPDIR/tmp3" | grep -Ev '^\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | column -t -s ',' | sed 's/[ \t]*$//' > "$REPORT_TXT"; then
            f_regdomain_die "Failed to write report to $REPORT_TXT."
        fi

        if [ -s "$TMPDIR/errors.log" ]; then
            ERROR_LOG="$HOME/data/registered-domains-errors-$(date +%H:%M).txt"
            cp "$TMPDIR/errors.log" "$ERROR_LOG"
        fi

        ROWS_FILE="$TMPDIR/registered-domains-rows.html"
        f_regdomain_write_report "$TMPDIR/tmp3" "$DISCOVER_REPORT" "$ROWS_FILE"

        echo "$MEDIUM"
        echo
        echo "[*] Scan complete. Found $RESULT_COUNT of $TOTAL domains with registration data."
        echo
        echo -e "The text report is located at ${YELLOW}$REPORT_TXT${NC}"
        echo -e "The HTML report was updated in ${YELLOW}$DISCOVER_REPORT${NC}"
        if [ -n "$ERROR_LOG" ]; then
            echo -e "Lookup errors logged at ${YELLOW}$ERROR_LOG${NC}"
        fi
        echo
        unset LOCATION DISCOVER_REPORT
        exit 0
        ;;
    3) f_main ;;
    *) f_error ;;
esac