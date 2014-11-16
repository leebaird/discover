#!/bin/bash
clear

echo
echo
echo "1. CIDR"
echo "2. IP or URL"
echo "3. List"
echo
echo -n "Choice: "
read choice

case $choice in
     1) 
     echo -n "Enter a CIDR: "
     read cidr

     # Check for no response
     if [ -z $cidr ]; then
          echo 
          echo "You did not enter a CIDR."
          exit
     fi

     nmap -Pn -n -T4 --open -sV --stats-every 10s -oA scan $location
     ;;

     2) 
     echo -n "Enter a IP or URL: "
     read target

     # Check for no response
     if [ -z $target ]; then
          echo 
          echo "You did not enter anything."
          exit
     fi

     nmap -Pn -n -T4 --open -sV --stats-every 10s -oA scan $target

     3) echo
     echo -n "Enter location of the exclusion list: "
     read location

     # Check for no response
     if [ -z $location ];then
          echo 
          echo "You did not enter a location."
          exit
     fi

     # Check for wrong location
     if [ ! -f $location ];then
          echo 
          echo "The file does not exist."
          exit
     fi

     nmap -Pn -n -T4 --open -sV --stats-every 10s -oA scan $location
     ;;

     *) echo "You have entered a wrong choice."
esac

