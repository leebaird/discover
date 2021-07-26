#!/bin/bash

cp /home/kali/.Xauthority /root/.Xauthority

f_runlocally
clear
f_banner

echo -e "${BLUE}Open multiple tabs in Firefox with:${NC}"
echo
echo "1.  List"
echo "2.  Directories from robots.txt."
echo "3.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1) f_location
     echo -n "Use an https prefix? (y/N) "
     read prefix

     XAUTHORITY=/root/.Xauthority sudo firefox &
     sleep 2

     if [ -z $prefix ]; then
          for i in $(cat $location); do
               XAUTHORITY=/root/.Xauthority sudo firefox -new-tab $i &
               sleep 1
          done
     elif [ "$prefix" == "y" ]; then
          for i in $(cat $location); do
               XAUTHORITY=/root/.Xauthority sudo firefox -new-tab https://$i &
               sleep 1
          done
     else
          f_error
     fi
     ;;

     2)
     echo
     echo $medium
     echo
     echo "Usage: target.com or target-IP"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [[ -z $domain ]]; then
          f_error
     fi

     wget -q $domain/robots.txt

     # Check if the file is empty
     if [ ! -s robots.txt ]; then
          echo
          echo -e "${RED}$medium${NC}"
          echo
          echo -e "${RED}                          *** No robots file discovered. ***${NC}"
          echo
          echo -e "${RED}$medium${NC}"
          sleep 2
          f_main
     fi

     grep 'Disallow' robots.txt | awk '{print $2}' > tmp

     XAUTHORITY=/root/.Xauthority sudo firefox &
     sleep 2

     for i in $(cat tmp); do
          XAUTHORITY=/root/.Xauthority sudo firefox -new-tab http://$domain$i &
          sleep 1
     done

     rm robots.txt
     mv tmp $home/data/$domain-robots.txt

     echo
     echo $medium
     echo
     echo "***Scan complete.***"
     echo
     echo
     echo -e "The new report is located at ${YELLOW}$home/data/$domain-robots.txt${NC}\n"
     echo
     echo
     ;;

     3) f_main;;
     *) f_error;;
esac
}

