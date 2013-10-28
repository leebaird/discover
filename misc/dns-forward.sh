#!/bin/bash

clear
echo
echo DNS Forward
echo
echo
echo By Lee Baird
echo
echo "Show IP addresses of subdomains."
echo
echo Usage: target.com
echo

read -p "Domain: " domain

if [ -z $domain ]; then
     echo
     echo "#########################"
     echo
     echo "Invalid choice."
     echo
     exit
fi

echo
echo "#########################"
echo

for x in $(cat /pentest/enumeration/dns/dnsenum/dns.txt); do
     host $x.$domain | grep 'has address' | cut -d ' ' -f4 >> tmp
done

cat tmp | sort -nu

rm tmp
echo
echo
