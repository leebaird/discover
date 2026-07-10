#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Special thanks to:
# Jay Townsend (@jay_townsend1) - everything, conversion from Backtrack to Kali
# Jason Ashton (@ninewires) - Penetration Testers Framework (PTF) compatibility, bug crusher, and bash ninja
#
# Dev modules by Yiğit ibrahim (ibrahimsql)
#
# Thanks to:
# Ben Wood (@DilithiumCore) - regex master
# Dave Klug - planning, testing, and bug reports
# Jason Arnold (@jasonarnold) - original concept and planning, co-author of crack-wifi
# John Kim - Python guru, bug smasher, and parsers
# Eric Milam (@Brav0Hax) - total re-write using functions
# Hector Portillo - report framework v3
# Ian Norden (@iancnorden) - report framework v2
# Martin Bos (@cantcomputer) - IDS evasion techniques
# Matt Banick - original development
# Numerous people on freenode IRC - #bash and #sed (e36freak)
# Rob Dixon (@304geek) - report framework concept
# Robert Clowser (@dyslexicjedi)- all things
# Saviour Emmanuel - Nmap parser
# Securicon, LLC. - for sponsoring development of parsers
# Steve Copland - report framework v1
# Arthur Kay (@arthurakay) - Python scripts
# Brett Fitzpatrick (@brettfitz) - SQL query
# Robleh Esa (@RoblehEsa) - SQL queries

# OPSEC: change your default nmap user agent located on line 160 at /usr/share/nmap/nselib/http.lua 

###############################################################################################################################

# Global variables
DATESTAMP=$(date +"%B %d, %Y")
DISCOVER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECON_DIR="$DISCOVER/recon"
SCAN_DIR="$DISCOVER/scan"
WEB_DIR="$DISCOVER/web"
MISC_DIR="$DISCOVER/misc"
MYIP=$(ip addr | grep 'global' | grep -Eiv '(:|docker|tun0)' | cut -d '/' -f1 | awk '{print $2}')
PWD=$(pwd)
SIP='sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4'
TIMESTAMP=$(date +"%-I:%M %p %Z")
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.86"

LARGE='==============================================================================================================================='
MEDIUM='=================================================================='
SMALL='========================================'

# Colors
BLUE='\033[1;34m'
GREEN='\033[1;32m'
NC='\033[0m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

###############################################################################################################################

# Export variables
export DATESTAMP DISCOVER RECON_DIR SCAN_DIR WEB_DIR MISC_DIR MYIP PWD SIP TIMESTAMP USER_AGENT
export LARGE MEDIUM SMALL
export BLUE GREEN NC RED YELLOW

###############################################################################################################################

f_terminate(){
    OUTPUT_DIR=$HOME/data/cancelled-$(date +%H:%M)
    mkdir -p "$OUTPUT_DIR"
    echo
    echo "[!] Terminating."
    echo
    echo -e "${YELLOW}Saving data to $OUTPUT_DIR.${NC}"

    cd "$DISCOVER"/ || exit

    if [ -d "$NAME" ]; then
        mv "$NAME" "$OUTPUT_DIR"
    fi

    mv tmp* "$OUTPUT_DIR" 2>/dev/null

    echo
    echo "[*] Saving complete."
    echo
    exit 1
}

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

###############################################################################################################################

f_banner(){
    echo
    echo -e "${YELLOW}
 _____  ___  _____  _____  _____  _    _  _____  _____
|     \  |  |____  |      |     |  \  /  |____  |____/
|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_

by Lee Baird${NC}"
    echo
    echo
}

export -f f_banner

###############################################################################################################################

f_check(){
    ping -c 1 -W 3 8.8.8.8 > /dev/null 2>&1

    if [ $? -ne 0 ]; then
        f_banner
        echo "[!] There is no network connection."
        echo
        exit 1
    fi
}

export -f f_check

###############################################################################################################################

f_invalid(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] Invalid choice or entry.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    sleep 2
    return 1
}

f_run_script(){
    "$@"
    local status=$?

    if [ "$status" -eq 0 ]; then
        exit 0
    fi
}

f_run_submenu(){
    "$@"
    local status=$?

    if [ "$status" -eq 2 ]; then
        exit 0
    fi
}

f_error(){
    f_invalid
    exec "$DISCOVER/discover.sh"
}

f_return_main(){
    exit 4
}

f_dev_die(){
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] $1${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 1
}

f_dev_previous(){
    exit 2
}

export -f f_invalid f_error f_return_main f_dev_die f_dev_previous f_run_script f_run_submenu

###############################################################################################################################

f_runlocally(){
    if [ -z "$DISPLAY" ]; then
        echo
        echo -e "${RED}$MEDIUM${NC}"
        echo
        echo -e "${RED}[!] This option must be ran locally.${NC}"
        echo
        echo -e "${RED}$MEDIUM${NC}"
        echo
        exit 1
    fi
}

export -f f_runlocally

###############################################################################################################################

f_firefox_running(){
    pgrep -x firefox >/dev/null 2>&1 \
        || pgrep -x firefox-bin >/dev/null 2>&1 \
        || pgrep -x firefox-esr >/dev/null 2>&1 \
        || pgrep -f '/[f]irefox/' >/dev/null 2>&1
}

f_firefox_check(){
    if f_firefox_running; then
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        echo -e "${RED}[!] Close all Firefox instances before running script.${NC}"
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        sleep 2
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

export -f f_firefox_running f_firefox_check f_firefox_user_agents

###############################################################################################################################

f_company_domain(){
    echo
    echo "$MEDIUM"
    echo
    echo "Usage"
    echo
    echo "Company: Target"
    echo "Domain:  target.com"
    echo
    echo "$MEDIUM"
    echo
    echo -n "Company: "
    read -r COMPANY
    COMPANY="${COMPANY#"${COMPANY%%[![:space:]]*}"}"
    COMPANY="${COMPANY%"${COMPANY##*[![:space:]]}"}"

    if [ -z "$COMPANY" ]; then
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        echo -e "${RED}[!] A company name is required.${NC}"
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        sleep 2
        exit 1
    fi

    echo -n "Domain:  "
    read -r DOMAIN
    DOMAIN="${DOMAIN#"${DOMAIN%%[![:space:]]*}"}"
    DOMAIN="${DOMAIN%"${DOMAIN##*[![:space:]]}"}"

    if [ -z "$DOMAIN" ]; then
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        echo -e "${RED}[!] A domain is required.${NC}"
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        sleep 2
        exit 1
    fi

    if [[ ! "$DOMAIN" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,63}$ ]]; then
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        echo -e "${RED}[!] Invalid domain.${NC}"
        echo
        echo -e "${RED}$SMALL${NC}"
        echo
        sleep 2
        exit 1
    fi

    COMPANYURL=$( printf "%s\n" "$COMPANY" | tr '[:upper:]' '[:lower:]' | sed 's/ /%20/g; s/\&/%26/g; s/\,/%2C/g' )
    export COMPANY DOMAIN COMPANYURL
}

export -f f_company_domain

###############################################################################################################################

source "$SCAN_DIR/nmap.sh"

###############################################################################################################################

f_update(){
    echo
    echo -e "${BLUE}Updating Discover.${NC}"
    git pull
    echo

    if command -v grok &> /dev/null; then
        echo -e "${BLUE}Updating Grok.${NC}"
        grok update
        echo
    fi

    # shellcheck disable=SC2166
    cd "$HOME" || exit

    if [ ! -f ~/.local/bin/uv ]; then
        echo -e "${YELLOW}Installing uv.${NC}"
        curl -LsSf https://astral.sh/uv/install.sh | sh
        echo
        echo -e "${YELLOW}Close your Terminal then rerun Discover update.${NC}"
        echo
        exit
    else
        echo -e "${BLUE}Updating uv.${NC}"
        uv self update
        echo
    fi

    if [ -d "$HOME/theHarvester/.git" ]; then
        echo -e "${BLUE}Updating theHarvester.${NC}"
        cd "$HOME/theHarvester" || exit ; git pull
        uv sync
        echo
    else
        echo -e "${YELLOW}Installing theHarvester.${NC}"
        git clone https://github.com/laramies/theHarvester "$HOME/theHarvester"
        cd "$HOME/theHarvester" || exit
        uv sync
        echo
    fi

    sudo "$MISC_DIR/update.sh"

    if [ -f "$DISCOVER/notes/build.py" ]; then
        echo -e "${BLUE}Rebuilding notes site.${NC}"
        python3 "$DISCOVER/notes/build.py" || true
        echo
    fi

    exit
}

export -f f_update

###############################################################################################################################

f_notes(){
    echo
    echo "[*] Building notes site."
    if ! python3 "$DISCOVER/notes/build.py"; then
        echo -e "${RED}[!] Notes build failed.${NC}"
        echo
        sleep 2
        return 0
    fi
    echo "[*] Opening notes in browser."
    if command -v xdg-open &> /dev/null; then
        xdg-open "$DISCOVER/notes/index.htm" >/dev/null 2>&1 &
    elif command -v sensible-browser &> /dev/null; then
        sensible-browser "$DISCOVER/notes/index.htm" >/dev/null 2>&1 &
    else
        echo "$DISCOVER/notes/index.htm"
    fi
    echo
    exit 0
}

export -f f_notes

###############################################################################################################################

f_dev_run(){
    local script="$1"
    local status

    "$script"
    status=$?
    if [ "$status" -eq 0 ]; then
        exit 0
    fi
    if [ "$status" -eq 2 ]; then
        f_dev
        return 0
    fi
    if [ "$status" -eq 3 ]; then
        exit 1
    fi
    return 0
}

f_dev(){
    clear
    f_banner

    echo -e "${BLUE}Dev scripts originally by ${YELLOW}ibrahimsql${NC}"
    echo
    echo "1. API Security"
    echo "2. Cloud Security"
    echo "3. Container Security"
    echo "4. OAuth and JWT Security"
    echo "5. Open Redirect Scanner"
    echo "6. Sensitive Information"
    echo "7. WAF Detection"
    echo "8. Web and API Security"
    echo "9. Previous menu"
    echo

    echo -n "Choice: "
    read -r CHOICE
    CHOICE="${CHOICE//$'\r'/}"
    CHOICE="${CHOICE#"${CHOICE%%[![:space:]]*}"}"
    CHOICE="${CHOICE%"${CHOICE##*[![:space:]]}"}"

    if [ -z "$CHOICE" ]; then
        f_invalid
        return 0
    fi

    case "$CHOICE" in
        9) return 0 ;;
        *)
            if [ ! -d "$HOME"/data ]; then
                mkdir -p "$HOME"/data
            fi

            case "$CHOICE" in
                1) f_dev_run "$DISCOVER/dev/api-scanner.sh" ;;
                2) f_dev_run "$DISCOVER/dev/cloud-scanner.sh" ;;
                3) f_dev_run "$DISCOVER/dev/container-scanner.sh" ;;
                4) f_dev_run "$DISCOVER/dev/oauth-jwt-scanner.sh" ;;
                5) f_dev_run "$DISCOVER/dev/open-redirect.sh" ;;
                6) f_dev_run "$DISCOVER/dev/sensitive-scanner.sh" ;;
                7) f_dev_run "$DISCOVER/dev/waf-detect.sh" ;;
                8) f_dev_run "$DISCOVER/dev/web-api-scanner.sh" ;;
                *) f_invalid; return 0 ;;
            esac
            ;;
    esac
}

export -f f_dev

###############################################################################################################################

f_main(){
    clear
    f_check
    f_banner

    echo -e "${BLUE}RECON${NC}"
    echo "1.  Domain"
    echo "2.  Person"
    echo
    echo -e "${BLUE}SCANNING${NC}"
    echo "3.  Generate target list"
    echo "4.  CIDR"
    echo "5.  List"
    echo "6.  IP, range, or URL"
    echo "7.  Rerun Nmap scripts and MSF aux"
    echo
    echo -e "${BLUE}WEB${NC}"
    echo "8.  Insecure direct object reference"
    echo "9.  Open multiple tabs in Firefox"
    echo "10. Nikto"
    echo "11. SSL"
    echo
    echo -e "${BLUE}MISC${NC}"
    echo "12. Generate a malicious payload"
    echo "13. Start a Metasploit listener"
    echo "14. CVE lookup"
    echo "15. Parse XML"
    echo "16. Dev"
    echo "17. Notes"
    echo "18. Update"
    echo "19. Exit"
    echo

    echo
    echo -n "Choice: "
    read -r CHOICE
    CHOICE="${CHOICE#"${CHOICE%%[![:space:]]*}"}"
    CHOICE="${CHOICE%"${CHOICE##*[![:space:]]}"}"

    case "$CHOICE" in
        16) f_dev ;;
        17) f_notes ;;
        18) f_update ;;
        19) echo && exit ;;
        *)
            if [ ! -d "$HOME"/data ]; then
                mkdir -p "$HOME"/data
            fi

            case "$CHOICE" in
                # RECON
                1) unset LOCATION; f_run_submenu "$RECON_DIR/domain.sh" ;;
                2) f_run_script "$RECON_DIR/person.sh" ;;

                # SCANNING
                3) f_run_script "$SCAN_DIR/generateTargets.sh" ;;
                4) f_cidr ;;    # Located in nmap.sh
                5) f_list ;;    # Located in nmap.sh
                6) f_single ;;  # Located in nmap.sh
                7) f_rerun ;;   # Located in nmap.sh

                # WEB
                8) f_run_script "$WEB_DIR/directObjectRef.sh" ;;
                9) f_run_script "$WEB_DIR/multiTabs.sh" ;;
                10) f_run_script "$WEB_DIR/nikto.sh" ;;
                11) f_run_script "$WEB_DIR/ssl.sh" ;;

                # MISC
                12) f_run_script "$MISC_DIR/payload.sh" ;;
                13) f_run_script "$MISC_DIR/listener.sh" ;;
                14) f_run_script "$MISC_DIR/cve.sh" ;;
                15) f_run_script "$MISC_DIR/parse.sh" ;;

                99) f_run_script "$DISCOVER/old/newModules.sh" ;;
                *) f_invalid ;;
            esac
            ;;
    esac
}

export -f f_main

# Run the script
if [[ -z "${DISCOVER_SOURCE_ONLY:-}" ]]; then
    while true; do
        f_main
    done
fi
