#!/bin/bash

clear
echo
echo DNS Reverse
echo
echo
echo By Lee Baird
echo
echo "Perform a PTR DNS query on a Class C range and return FQDNs."
echo
echo Usage: 192.168.1
echo

read -p "Class: " class

if [ -z $class ]; then
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

for x in `seq 1 254`; do
     host $class.$x | grep 'name pointer' | cut -d ' ' -f5
done

echo
echo
