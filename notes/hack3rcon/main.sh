#!/bin/bash
clear

echo
echo
echo "Welcome to Hack3rcon5."
echo "This is my master script."
echo
echo
echo "1. Recon people"
echo "2. Recon domain"
echo "3. Open list in Firefox"
echo "4. Open a domain's robot.txt in Firefox"
echo
echo -n "Choice: "
read choice

echo $choice

case $choice in
     1) ./recon-people.sh;;
     2) ./recon-domain.sh;;
     3) ./open-list.sh;;
     4) ./robots.sh;;
     *) echo "You have entered a wrong choice."
esac

