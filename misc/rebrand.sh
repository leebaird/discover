#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo -n "Enter the location of your folder: "
read -r location

# Check for no answer
if [ -z "$location" ]; then
    echo
    echo $medium
    echo
    echo "[!] No answer."
    echo
    exit 1
fi

# Check for wrong answer
if [ ! -d "$location" ]; then
    echo
    echo $medium
    echo
    echo "[!] Wrong location."
    echo
    exit 1
fi

cd "$location"

sed -i 's|href="https://github.com/leebaird/discover"|href="https://www.acme.org"|g' index.htm
cd pages/
sed -i 's|href="https://github.com/leebaird/discover"|href="https://www.acme.org"|g' *.htm

firefox ../index.htm &
