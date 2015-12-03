#!/bin/bash

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

read -p "Domain: " domain

if [ -z $domain ]; then
     echo
     echo "========================================"
     echo
     echo "Invalid choice."
     echo
     echo
     exit
fi

echo
echo "========================================"
echo

wget -q www.$domain

if [ ! -e index.html ]; then
     echo
     exit
fi

grep 'href=' index.html | cut -d '/' -f3 | grep $domain | cut -d '"' -f1 > tmp

for x in $(cat tmp); do
     host $x | grep 'has address' | cut -d ' ' -f1,4 >> tmp2
done

if [ -e tmp2 ]; then
     cat tmp2 | grep $domain | column -t | sort -u
fi

rm index.html tmp*

echo
echo
