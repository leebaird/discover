#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

SMALL='========================================'

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${YELLOW}Crawl\n\nby Lee Baird\n${NC}"
echo
echo "Find subdomains linked to the homepage."
echo
echo "Usage: target.com"
echo

echo -n "Domain: "
read -r DOMAIN

# Check for no answer
if [ -z "$DOMAIN" ]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] No domain entered.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
fi

# Check for a valid domain
if [[ ! "$DOMAIN" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,63}$ ]]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] Invalid domain.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
fi

# Download the homepage HTML
if ! wget -q "$DOMAIN" -O index.html; then
    echo
    echo -e "${RED}[!] Failed to download www.$DOMAIN.${NC}"
    rm -f index.html
    echo
    exit 1
fi

# Extract subdomains
grep 'href=' index.html | cut -d '/' -f3 | grep "$DOMAIN" | grep -Ev "www.$DOMAIN|>" | cut -d '"' -f1 | sort -u > tmp

if [ ! -s tmp ]; then
    echo
    echo -e "${RED}[!] No subdomains found.${NC}"
    rm -f index.html tmp
    echo
    exit 1
else
    echo
    echo "$SMALL"
    echo
    sed 's/\?.*//' tmp | sort -u | column -t
    echo
fi

# Clean up
rm -f index.html tmp
