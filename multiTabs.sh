#!/usr/bin/bash

f_runlocally
clear
f_banner

echo -e "${BLUE}Open multiple tabs in Firefox with:${NC}"
echo
echo "1.  List"
echo "2.  Files in a directory"
echo "3.  Directories in robots.txt"
echo "4.  Previous menu"
echo
echo -n "Choice: "
read choice

case $choice in
     1)
     f_location
     echo
     echo -n "Use an https prefix? (y/N) "
     read prefix

     if [ -z $prefix ]; then
          for i in $(cat $location); do
               xdg-open http://$i &
               sleep 1
          done
     elif [ "$prefix" == "y" ]; then
          for i in $(cat $location); do
               xdg-open https://$i &
               sleep 1
          done
     else
          f_error
     fi
     
     exit
     ;;

     2)
     echo
     echo $medium
     echo
     echo -n "Enter the location of your directory: "
     read -e location

     # Check for no answer
     if [ -z $location ]; then
          f_error
     fi

     # Check for wrong answer
     if [ ! -d $location ]; then
          f_error
     fi

     cd $location

     for i in $(ls -l | awk '{print $9}'); do
          xdg-open $i &
          sleep 1
     done
     
     exit
     ;;

     3)
     echo
     echo $medium
     echo
     echo "Usage: target.com or target-IP"
     echo
     echo -n "Domain: "
     read domain

     # Check for no answer
     if [ -z $domain ]; then
          f_error
     fi

     curl -kLs $domain/robots.txt -o robots.txt

     # Check if the file is empty
     if [ ! -s robots.txt ]; then
          echo
          echo -e "${RED}$medium${NC}"
          echo
          echo -e "${RED}                          *** No robots.txt file discovered. ***${NC}"
          echo
          echo -e "${RED}$medium${NC}"
          sleep 2
          f_main
     fi

     grep 'Disallow' robots.txt | awk '{print $2}' > tmp

     for i in $(cat tmp); do
          xdg-open http://$domain$i &
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
     exit
     ;;

     4) f_main;;
     *) f_error;;
esac
}
