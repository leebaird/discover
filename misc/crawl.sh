#!/bin/bash

clear
echo
echo "Crawl"
echo
echo
echo "By Lee Baird"
echo
echo "Returns a list of IP external web servers that are linked from home page."
echo
echo "Usage: target.com"
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

wget -q www.$domain

grep 'href=' index.html | cut -d '/' -f3 | grep $domain | cut -d '"' -f1 | sort -u > tmp

for x in $(cat tmp); do
     host $x | grep 'has address' | cut -d ' ' -f1,4 >> tmp2
done

column -t tmp2 | sort -u

rm index.html tmp*

echo
echo

