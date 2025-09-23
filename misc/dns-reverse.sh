#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

MEDIUM='=================================================================='

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${YELLOW}DNS Reverse\n\nby Lee Baird\n${NC}"
echo
echo "Perform a PTR DNS query on a Class C range and return FQDNs."
echo
echo "Usage: 192.168.1"
echo
echo -n "Class: "
read -r CLASS

# Check if class is empty or invalid
if [[ -z "$CLASS" || ! "$CLASS" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; then
    echo
    echo "$MEDIUM"
    echo
    echo -e "${RED}[!] Invalid choice or entry.${NC}"
    echo
    exit 1
fi

echo
echo "$MEDIUM"
echo

# Perform PTR DNS query on each IP in the Class C range
for i in {1..254}; do
    # Check if the host command returns a valid PTR record
    if RESULT=$(host "$CLASS.$i" | grep 'name pointer'); then
        echo "$RESULT" | cut -d ' ' -f1,5
    else
        echo -e "${RED}[!] No PTR record for $CLASS.$i${NC}"
    fi
done
