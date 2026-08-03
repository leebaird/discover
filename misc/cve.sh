#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_cve_trim(){
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

f_cve_normalize(){
    local cve
    cve=$(f_cve_trim "$1")
    cve="${cve^^}"
    printf '%s' "$cve"
}

f_cve_valid(){
    [[ "$1" =~ ^CVE-[0-9]{4}-[0-9]{4,}$ ]]
}

f_cve_fail(){
    local message="$1"

    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $message${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 0
}

f_cve_open_tabs(){
    local cve="$1"
    local cve_id="${cve#CVE-}"   # Exploit-DB wants year-number only (e.g. 2018-7600)
    local url user_agent
    local -a urls

    urls=(
        "https://nvd.nist.gov/vuln/detail/$cve"
        "https://www.rapid7.com/db/?q=$cve&type=nexpose"
        "https://www.tenable.com/cve/$cve"
        "https://www.exploit-db.com/search?cve=$cve_id"
        "https://sploitus.com/?query=$cve"
        "https://cvebase.io/cve/$cve"
        "https://www.google.com/search?q=site:http://github.com+%22$cve%22"
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=$cve&field_date_added_wrapper=all&field_cve=&sort_by=field_date_added&items_per_page=20&url="
    )

    f_firefox_user_agents

    for url in "${urls[@]}"; do
        user_agent="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$user_agent" 2>/dev/null &
        sleep 1
    done
}

f_runlocally

if ! f_firefox_check; then
    exit 0
fi

clear
f_banner

echo -e "${BLUE}CVE lookup.${NC}"
echo
echo -n "CVE: "
read -r CVE
CVE=$(f_cve_normalize "$CVE")

if [ -z "$CVE" ]; then
    f_cve_fail "No CVE provided."
fi

if ! f_cve_valid "$CVE"; then
    f_cve_fail "Invalid CVE format. Expected CVE-YYYY-NNNN."
fi

echo "[*] Opening CVE resources for $CVE."
echo
f_cve_open_tabs "$CVE"

exit 0
