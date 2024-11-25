#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

SMALL='========================================'

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${YELLOW}DNS Transfer\n\nBy Lee Baird\n${NC}"
echo
echo "Check for DNS zone transfer."
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

echo
echo "$SMALL"
echo

# Perform DNS zone transfer check
for i in $(host -t ns "$DOMAIN" | cut -d ' ' -f4 | sed 's/\.\s*$//'); do
    echo "[*] Checking name server: $i"

    # Check if the DNS zone transfer is successful
    if host -l "$DOMAIN" "$i" > /dev/null 2>&1; then
        host -l "$DOMAIN" "$i"
    else
        echo -e "${RED}[!] Failed.${NC}"
        echo
    fi
done
