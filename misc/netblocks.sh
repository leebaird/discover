#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

clear
echo
echo "Netblocks"
echo
echo
echo "By Lee Baird"
echo
echo "This returns a list of Class A owners. Takes about 100 sec."
echo

for x in $(seq 1 255); do
    whois "$x".0.0.0 | grep -E 'CIDR|OrgName' >> tmp
    echo >> tmp
done

grep -Ev '%|No address' tmp > tmp2
cat -s tmp2 > netblocks.txt

rm tmp*

echo
echo
