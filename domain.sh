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

f_regdomain_filter_email(){
    local EMAIL="$1"

    if [[ "$EMAIL" == *'abuse'* || "$EMAIL" == *'anonymize.com'* || "$EMAIL" == *'buydomains.com'* || "$EMAIL" == *'cloudflareregistrar.com'* || "$EMAIL" == *'contact-form'* || "$EMAIL" == *'contact.gandi.net'* || "$EMAIL" == *'csl-registrar.com'* || "$EMAIL" == *'domaindiscreet.com'* || "$EMAIL" == *'dynadot.com'* || "$EMAIL" == *'gname.com'* || "$EMAIL" == *'google.com'* || "$EMAIL" == *'identity-protect.org'* || "$EMAIL" == *'meshdigital.com'* || "$EMAIL" == *'mydomainprovider.com'* || "$EMAIL" == *'myprivatename.com'* || "$EMAIL" == *'networksolutionsprivateregistration'* || "$EMAIL" == *'please'* || "$EMAIL" == *'p.o-w-o.info'* || "$EMAIL" == *'privacy'* || "$EMAIL" == *'Redacted'* || "$EMAIL" == *'redacted'* || "$EMAIL" == *'select'* || "$EMAIL" == *'tieredaccess.com'* ]]; then
        EMAIL=''
    fi

    printf '%s' "$EMAIL"
}

f_regdomain_get_email(){
    local REGDOMAIN="$1"
    local JSON REGEMAIL WHOIS_RAW WHOIS_DATA LABEL CANDIDATE

    if [ "${RDAP_SKIP:-0}" -eq 0 ] && command -v jq >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
        (
            flock -x 203
            sleep "$RDAP_DELAY"
            JSON=$(curl -4 -fsS --max-time 5 "https://rdap.org/domain/${REGDOMAIN}" 2>/dev/null)
        ) 203>"$RDAP_LOCK"
        if [ -n "$JSON" ] && ! echo "$JSON" | jq -e '.errorCode' >/dev/null 2>&1 && echo "$JSON" | jq -e '.ldhName // .handle // .unicodeName' >/dev/null 2>&1; then
            REGEMAIL=$(echo "$JSON" | jq -r '([.entities[]? | select(.roles[]? == "registrant") | .vcardArray[1][]? | select(.[0] == "email") | .[3]] + [.entities[]? | select(.roles[]? == "administrative") | .vcardArray[1][]? | select(.[0] == "email") | .[3]] + [.entities[]? | select(.roles[]? == "technical") | .vcardArray[1][]? | select(.[0] == "email") | .[3]] | first) // empty' | tr '[:upper:]' '[:lower:]')
            REGEMAIL=$(f_regdomain_filter_email "$REGEMAIL")
            if [ -n "$REGEMAIL" ]; then
                printf '%s' "$REGEMAIL"
                return 0
            fi
        fi
    fi

    (
        flock -x 200
        sleep "$WHOIS_DELAY"
        WHOIS_RAW=$(timeout 10 whois -H "$REGDOMAIN" 2>/dev/null)
        WHOIS_DATA=$(grep -Eiv '(#|please query|personal data|redacted|whois|you agree)' <<< "$WHOIS_RAW" | sed '/^$/d')
        REGEMAIL=''
        for LABEL in 'Registrant Email:' 'Admin Email:' 'Tech Email:'; do
            CANDIDATE=$(grep -m1 "$LABEL" <<< "$WHOIS_DATA" | sed "s/^[^:]*${LABEL}[[:space:]]*//" | tr '[:upper:]' '[:lower:]')
            CANDIDATE=$(f_regdomain_filter_email "$CANDIDATE")
            if [ -n "$CANDIDATE" ] && [[ "$CANDIDATE" == *'@'* ]]; then
                REGEMAIL="$CANDIDATE"
                break
            fi
        done
        printf '%s' "$REGEMAIL"
    ) 200>"$WHOIS_LOCK"
}

f_regdomain_acquire_slot(){
    local RUNNING

    while true; do
        if (
            flock -x 300
            RUNNING=$(cat "$REGDOMAIN_TMPDIR/running" 2>/dev/null)
            RUNNING=${RUNNING:-0}
            if [ "$RUNNING" -lt "$WHOIS_JOBS" ]; then
                echo $((RUNNING + 1)) > "$REGDOMAIN_TMPDIR/running"
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
    local RUNNING

    (
        flock -x 300
        RUNNING=$(cat "$REGDOMAIN_TMPDIR/running" 2>/dev/null)
        RUNNING=${RUNNING:-1}
        if [ "$RUNNING" -gt 0 ]; then
            echo $((RUNNING - 1)) > "$REGDOMAIN_TMPDIR/running"
        else
            echo 0 > "$REGDOMAIN_TMPDIR/running"
        fi
    ) 300>"$REGDOMAIN_TMPDIR/running.lock"
}

f_regdomain_tick(){
    local TOTAL="$1"
    local N

    (
        flock -x 201
        N=$(($(cat "$REGDOMAIN_TMPDIR/counter" 2>/dev/null || echo 0) + 1))
        echo "$N" > "$REGDOMAIN_TMPDIR/counter"
        printf '\r[*] %s of %s' "$N" "$TOTAL" >&2
    ) 201>"$REGDOMAIN_TMPDIR/counter.lock"
}

f_regdomain_read_file(){
    echo
    echo -n "Enter the location of your file: "
    read -r LOCATION

    if [ -z "$LOCATION" ]; then
        f_regdomain_die "No file location provided."
    fi

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
        echo
        echo "Open a browser to https://www.reversewhois.io/"
        echo "Enter your domain and solve the captcha."
        echo "Select all > copy all of the text and paste into a new file."

        for CMD in awk column flock sort timeout whois; do
            if ! command -v "$CMD" >/dev/null 2>&1; then
                f_regdomain_die "$CMD is not installed. Run Discover update to install dependencies."
            fi
        done

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

        WHOIS_DELAY="${WHOIS_DELAY:-0.5}"
        WHOIS_JOBS="${WHOIS_JOBS:-4}"
        if ! [[ "$WHOIS_JOBS" =~ ^[1-9][0-9]*$ ]]; then
            f_regdomain_die "WHOIS_JOBS must be a positive integer (got: $WHOIS_JOBS)."
        fi
        WHOIS_LOCK="$TMPDIR/whois.lock"
        RDAP_DELAY="${RDAP_DELAY:-0.25}"
        RDAP_LOCK="$TMPDIR/rdap.lock"
        export WHOIS_DELAY WHOIS_LOCK RDAP_DELAY RDAP_LOCK

        grep '^[0-9]' "$LOCATION" | awk '{print $2}' | sort -u > "$TMPDIR/domains"
        TOTAL=$(wc -l < "$TMPDIR/domains" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

        if [ "$TOTAL" -eq 0 ]; then
            f_regdomain_die "No domains found in file."
        fi

        RDAP_SKIP=0
        if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
            RDAP_SKIP=1
        fi
        export RDAP_SKIP

        echo "[*] Checking WHOIS/RDAP connectivity."
        if [ "$RDAP_SKIP" -eq 0 ] && ! curl -4 -fsS --max-time 5 "https://rdap.org/domain/example.com" >/dev/null 2>"$REGDOMAIN_TMPDIR/rdap.test.err"; then
            RDAP_SKIP=1
            export RDAP_SKIP
        fi
        if ! timeout 8 whois -H example.com >/dev/null 2>"$REGDOMAIN_TMPDIR/whois.test.err"; then
            f_regdomain_die "WHOIS lookups are unreachable. Check network connectivity and try again."
        fi

        echo "[*] Looking up registration emails."
        echo 0 > "$TMPDIR/running"
        echo 0 > "$TMPDIR/counter"
        : > "$TMPDIR/results"
        touch "$WHOIS_LOCK" "$RDAP_LOCK"

        while read -r REGDOMAIN; do
            f_regdomain_acquire_slot

            {
                REGEMAIL=$(f_regdomain_get_email "$REGDOMAIN")
                if [ -n "$REGEMAIL" ] && [[ "$REGEMAIL" == *'@'* ]]; then
                    RESULT="${REGDOMAIN},${REGEMAIL}"
                else
                    RESULT=''
                fi
                if [ -n "$RESULT" ]; then
                    (
                        flock -x 202
                        printf '%s\n' "$RESULT" >> "$REGDOMAIN_TMPDIR/results"
                    ) 202>"$REGDOMAIN_TMPDIR/results.lock"
                fi
                f_regdomain_tick "$TOTAL"
                f_regdomain_release_slot
            } &
        done < "$TMPDIR/domains"

        wait
        echo >&2

        RESULT_COUNT=$(wc -l < "$TMPDIR/results" | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)
        RESULT_COUNT=${RESULT_COUNT:-0}

        mkdir -p "$HOME/data" || f_regdomain_die "Cannot create $HOME/data."

        REPORT_TXT="$HOME/data/registered-domains.txt"

        if [ "$RESULT_COUNT" -eq 0 ]; then
            {
                echo "Domain,Registration Email"
            } | column -t -s ',' | sed 's/[ \t]*$//' > "$REPORT_TXT" || f_regdomain_die "Failed to write $REPORT_TXT."
        else
            {
                echo "Domain,Registration Email"
                sort -t, -k1,1 "$TMPDIR/results"
            } | column -t -s ',' | sed 's/[ \t]*$//' > "$REPORT_TXT" || f_regdomain_die "Failed to write $REPORT_TXT."
        fi

        echo
        echo "$MEDIUM"
        echo
        if [ "$RESULT_COUNT" -eq 0 ]; then
            echo "[!] Scanned $TOTAL domains; no registration emails found (privacy redaction or unavailable)."
        else
            echo "[*] Scan complete. Found $RESULT_COUNT of $TOTAL domains with registration emails."
        fi
        echo
        echo -e "The report is located at ${YELLOW}$REPORT_TXT${NC}"
        echo
        unset LOCATION
        exit 0
        ;;
    3) f_main ;;
    *) f_error ;;
esac
