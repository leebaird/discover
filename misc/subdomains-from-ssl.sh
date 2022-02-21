#!/usr/bin/bash

clear
echo
echo
echo -n "Enter a domain: "
read domain

# Check for no answer
if [[ -z $domain ]]; then
     echo
     echo "[!] You didn't enter a domain."
     echo
     echo
     exit
fi

sslyze $domain --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers > tmp

grep 'X509v3 Subject Alternative Name:' tmp | sed 's/      X509v3 Subject Alternative Name:   //g' | sed 's/, DNS:/\n/g' | sed 's/www.//g' | sed 's/DNS://g' > tmp2

# Remove trailing whitespace from each line
sed 's/[ \t]*$//' tmp2 | sort -u > tmp3

echo
cat tmp3
rm tmp*
echo
echo
