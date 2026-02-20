#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Colors
BLUE='\033[1;34m'
NC='\033[0m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

###############################################################################################################################

if [ $# -eq 0 ]; then
    echo
    echo "Usage:"
    echo "  $0 www.example.com           # Use free sources"
    echo "  $0 www.example.com api       # Use API sources"
    echo
    exit 1
fi

DOMAIN="$1"
USE_API=false

if [ $# -eq 1 ]; then
    USE_API=false
elif [ $# -eq 2 ] && [ "$2" = "api" ]; then
    USE_API=true
else
    echo
    echo -e "${RED}[!] Invalid argument.${NC}"
    echo
    echo "Usage:"
    echo "  $0 www.example.com           # Use free sources"
    echo "  $0 www.example.com api       # Use API sources"
    echo
    exit 1
fi

# Validate domain
if [[ ! $DOMAIN =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]+[aeiouy][a-zA-Z]*\.[a-zA-Z]{2,}$ ]]; then
    echo
    echo -e "${RED}[!] '$DOMAIN' does not look like a valid domain.${NC}"
    echo
    exit 1
fi

TH_DIR="$HOME/theHarvester"
WORK_DIR="$HOME/${DOMAIN}-test"

sources_no_api=(baidu certspotter chaos commoncrawl crtsh duckduckgo gitlab hudsonrock otx rapiddns robtex subdomaincenter subdomainfinderc99 thc threatcrowd urlscan waybackarchive yahoo)
sources_api=(bevigil bitbucket brave bufferoverun builtwith censys criminalip dehashed dnsdumpster fofa fullhunt github-code hackertarget haveibeenpwned hunter hunterhow intelx leakix leaklookup netlas onyphe pentesttools projectdiscovery rocketreach securityscorecard securityTrails tomba venacus virustotal whoisxml zoomeye)
# windvane (broken)

###############################################################################################################################

mkdir -p "$WORK_DIR" || { echo -e "${RED}[!] Cannot create $WORK_DIR${NC}" >&2; exit 2; }

cd "$TH_DIR" || { echo -e "${RED}[!] Cannot cd to $TH_DIR${NC}" >&2; exit 3; }

echo
echo "[*] Updating packages."
uv sync || echo -e "${YELLOW}Warning: uv sync failed – continuing...${NC}"
# shellcheck disable=SC1091
source .venv/bin/activate || { echo -e "${RED}[!] Failed to activate venv.${NC}" >&2; exit 4; }

echo

if $USE_API; then
    sources=("${sources_api[@]}")
    total=${#sources_api[@]}
    echo -e "${BLUE}[*] Running $total API sources.${NC}"
    echo
else
    sources=("${sources_no_api[@]}")
    total=${#sources_no_api[@]}
    echo -e "${BLUE}[*] Running $total free sources.${NC}"
    echo
fi

###############################################################################################################################

COUNT=0

run_harvester() {
    local source="$1"
    ((COUNT++))

    printf "    %-22s  (%2d / %2d)\n" "$source" "$COUNT" "$total"

    theHarvester -d "$DOMAIN" -b "$source" -n -r | sed '/^$/d; /:$/d' | sort -u > "z${source}.tmp" 2>/dev/null || true

    if [ -s "z${source}.tmp" ]; then
        mv "z${source}.tmp" "z${source}"
    else
        rm -f "z${source}.tmp"
        printf "      └─ (no results)\n"
    fi
}

for src in "${sources[@]}"; do
    run_harvester "$src"
done

###############################################################################################################################

if ls z* >/dev/null 2>&1; then
    mv z* "$WORK_DIR/" 2>/dev/null || true
    echo
    echo -e "${BLUE}[*] Finished.${NC}"
    echo
    echo -e "[*] Results saved to ${YELLOW}$WORK_DIR${NC}"
else
    echo
    echo -e "${YELLOW}[*] No results files were created.${NC}"
fi

deactivate

