#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

DISCOVER="${DISCOVER:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if ! declare -f f_banner >/dev/null 2>&1; then
    DISCOVER_SOURCE_ONLY=1 source "$DISCOVER/discover.sh"
fi

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
    local cli_mode="$2"

    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $message${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo

    if [ "$cli_mode" -eq 1 ]; then
        exit 1
    fi

    exit 0
}

f_cve_open_tabs(){
    local cve="$1"
    local url user_agent
    local -a urls

    urls=(
        "https://nvd.nist.gov/vuln/detail/$cve"
        "https://www.cve.org/CVERecord?id=$cve"
        "https://www.cvedetails.com/cve/$cve"
        "https://vulners.com/search?query=$cve"
        "https://www.tenable.com/cve/$cve"
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=$cve"
        "https://app.opencve.io/cve/$cve"
        "https://www.exploit-db.com/search?q=$cve"
        "https://github.com/advisories?query=$cve"
        "https://www.first.org/epss/?cve=$cve"
        "https://www.rapid7.com/db/?q=$cve&type=nexpose"
    )

    f_firefox_user_agents

    for url in "${urls[@]}"; do
        user_agent="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$user_agent" 2>/dev/null &
        sleep 1
    done
}

CLI_MODE=0
CVE=''

if [ -n "${1:-}" ]; then
    CLI_MODE=1
    CVE=$(f_cve_normalize "$1")
else
    clear
    f_banner

    echo -e "${BLUE}CVE lookup${NC}"
    echo
    echo -n "CVE: "
    read -r CVE
    echo
    CVE=$(f_cve_normalize "$CVE")
fi

f_runlocally

if ! f_firefox_check; then
    if [ "$CLI_MODE" -eq 1 ]; then
        exit 1
    fi
    exit 0
fi

if [ -z "$CVE" ]; then
    if [ "$CLI_MODE" -eq 1 ]; then
        f_cve_fail "No CVE provided." 1
    fi
    f_error
fi

if ! f_cve_valid "$CVE"; then
    f_cve_fail "Invalid CVE format. Expected CVE-YYYY-NNNN." "$CLI_MODE"
fi

echo "[*] Opening CVE resources for $CVE."
f_cve_open_tabs "$CVE"

if [ "$CLI_MODE" -eq 1 ]; then
    exit 0
fi

exit 0
