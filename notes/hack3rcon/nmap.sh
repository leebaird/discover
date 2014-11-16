#!/bin/bash
clear

echo
echo
echo "1. CIDR, IP or URL"
echo "2. List"
echo "3. Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     echo
     echo -n "Enter a CIDR, IP or URL: "
     read target

     # Check for no response
     if [ -z $target ]; then
          echo
          echo "You did not enter anything."
          exit
     fi

     nmap -Pn -n -T4 --open -sV --stats-every 10s $target -oN scan.txt
     ;;

     2)
     echo
     echo -n "Enter the location of your list: "
     read location

     # Check for no response
     if [ -z $location ]; then
          echo
          echo "You did not enter a location."
          exit
     fi

     # Check for wrong location
     if [ ! -f $location ]; then
          echo
          echo "The file does not exist."
          exit
     fi

     nmap -Pn -n -T4 --open -sV --stats-every 10s -iL $location -oN scan.txt
     ;;

     3) ./main.sh ;;

     *) echo; echo "Invalid choice."; echo
esac
