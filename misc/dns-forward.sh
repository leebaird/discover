#!/usr/bin/bash

# by Lee Baird (@discoverscripts)

medium='=================================================================='

clear
echo
echo "DNS Forward"
echo
echo
echo "By Lee Baird"
echo
echo "Show IP addresses of subdomains."
echo
echo "Usage: target.com"
echo

read -p "Domain: " domain

if [ -z $domain ]; then
     echo
     echo $medium
     echo
     echo "Invalid choice."
     echo
     echo
     exit 1
fi

echo
echo $medium
echo

for x in $(cat /usr/share/dnsenum/dns.txt); do
     host $x.$domain | grep 'has address' | cut -d ' ' -f1,4 >> tmp
done

column -t tmp | sort -u

rm tmp

echo
echo
