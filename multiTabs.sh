#!/bin/bash

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
     echo -n "Use SSL? (y/N) "
     read ssl

     $web &
     sleep 2

     if [ -z $ssl ]; then
          for i in $(cat $location); do
               $web http://$i &
               sleep 1
          done
     elif [ "$ssl" == "y" ]; then
          for i in $(cat $location); do
               $web https://$i &
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

     $web &
     sleep 2

     for i in $(cat tmp); do
          $web http://$domain$i &
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

