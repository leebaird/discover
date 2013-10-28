#!/bin/bash

clear
echo
echo DNS Transfer
echo
echo
echo By Lee Baird
echo
echo "Check for DNS zone transfer."
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

for x in $(host -t ns $domain | awk '{print $4}'); do
     host -l $domain $x
done

echo
echo
