#!/bin/bash
clear

echo
echo
echo "Welcome to Hack3rcon5."
echo "This is my master script."
echo
echo
echo "1. Recon domain"
echo "2. Recon people"
echo "3. Open a list of URLs in Firefox"
echo "4. Open a domain's robot.txt in Firefox"
echo "5. Nmap"
echo
echo -n "Choice: "
read choice

echo $choice

case $choice in
     1) ./recon-domain.sh ;;
     2) ./recon-people.sh ;;
     3) ./open-list.sh ;;
     4) ./robots.sh ;;
     5) ./nmap.sh ;;
     *) echo; echo "Invalid choice."; echo
esac
