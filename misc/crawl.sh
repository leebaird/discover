#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo "Crawl"
echo
echo
echo "By Lee Baird"
echo
echo "Find all of the subdomains linked to the homepage."
echo
echo "Usage: target.com"
echo

echo -n "Domain: "
read -r domain

if [ -z "$domain" ]; then
    echo
    echo $medium
    echo
    echo "[!] Invalid choice."
    echo
    echo
    exit 1
fi

echo
echo $medium
echo

if ! wget -q www."$domain" -O index.html; then
    echo
    echo "[!] Failed to download www.$domain."
    echo
    exit 1
fi

grep 'href=' index.html | cut -d '/' -f3 | grep "$domain" | grep -Ev "www.$domain|>" | cut -d '"' -f1 | sort -u > tmp

if [ ! -s tmp ]; then
    echo
    echo "[*] No subdomains found."
    echo
    exit 1
else
    echo $medium
    echo
    sed 's/\?.*//' tmp | sort -u | column -t
fi

rm index.html tmp

echo
echo
