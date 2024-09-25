#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

medium='=================================================================='

clear
echo
echo "Ping Sweep"
echo
echo
echo "By Lee Baird"
echo
echo "Ping sweep a Class C."
echo
echo "Usage: 192.168.1"
echo

echo -n "Class: "
read -r class

if [ -z "$class" ]; then
    echo
    echo $medium
    echo
    echo "[!] Invalid choice."
    echo
    exit 1
fi

echo
echo $medium
echo

for x in $(seq 1 254); do
    ping -c1 "$class"."$x" | grep 'bytes from' | cut -d ' ' -f4 | cut -d ':' -f1 &
done
