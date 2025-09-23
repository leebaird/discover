#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

MEDIUM='=================================================================='

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo
echo -e "${YELLOW}Ping Sweep\n\nby Lee Baird\n${NC}"
echo
echo "Ping sweep a Class C."
echo
echo "Usage: 192.168.1"
echo
echo -n "Class: "
read -r CLASS

# Check for a valid Class C
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
echo "[*] Pinging each IP in $CLASS.0/24."

# Ping sweep with controlled concurrency
for i in $(seq 1 254); do
    ping -c1 -W 1 "$CLASS.$i" | grep 'bytes from' | awk -F'[: ]+' '{print "[*] Active IP:", $4}' &
    # Limit concurrent pings
    if (( i % 10 == 0 )); then
        wait
    fi
done

# Wait for all background processes to complete
wait
echo
echo "$MEDIUM"
echo
echo -e "${BLUE}Ping sweep complete.${NC}"
echo
