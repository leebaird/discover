#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

SMALL='========================================'

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${YELLOW}Subdomains from SSL\n\nby Lee Baird\n${NC}"
echo
echo -n "Enter a domain: "
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
if [[ ! "$DOMAIN" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$ ]]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] Invalid domain.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
fi

# Run sslyze and extract subdomains
sslyze "$DOMAIN" --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > tmp

# Extract and format subject alternative names
grep 'X509v3 Subject Alternative Name:' tmp | sed 's/      X509v3 Subject Alternative Name:   //g; s/, DNS:/\n/g; s/www.//g; s/DNS://g' > tmp2

# Remove trailing whitespace from each line
sed 's/[ \t]*$//' tmp2 | sort -u > tmp3

# Display the extracted subdomains
echo
echo "$SMALL"
echo
echo "Extracted Subdomains:"
cat tmp3

# Clean up
rm tmp*
