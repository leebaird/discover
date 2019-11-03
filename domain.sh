#!/bin/bash

clear
f_banner

echo -e "${BLUE}RECON${NC}"
echo
echo "1.  Passive"
echo "2.  Active"
echo "3.  Import names into an existing recon-ng workspace"
echo "4.  Previous menu"
echo
echo -n "Choice: "
read recon

case $recon in
     1) $discover/passive.sh && exit;;

     2) $discover/active.sh && exit;;

     3)
     clear
     f_banner

     echo -e "${BLUE}Import names into an existing recon-ng workspace.${NC}"
     echo
     echo "Example: last, first"
     f_location
     echo "last_name#first_name" > /tmp/names.csv
     sed 's/, /#/' $location  >> /tmp/names.csv

     echo -n "Use Workspace: "
     read -e workspace

     # Check for no answer
     if [[ -z $workspace ]]; then
          f_error
     fi

     # Check for wrong answer
     if [ ! -d /root/.recon-ng/workspaces/$workspace ]; then
          f_error
     fi

     if [ ! -d $home/data/$workspace ]; then
          mkdir -p $home/data/$workspace
     fi

     echo "workspaces select $workspace" > tmp.rc
     cat $discover/resource/recon-ng-import-names.rc >> tmp.rc
     cat $discover/resource/recon-ng-cleanup.rc >> tmp.rc
     sed -i "s/yyy/$workspace/g" tmp.rc

     recon-ng -r $discover/tmp.rc
     rm tmp.rc

     grep '@' emails | cut -d ' ' -f4 | egrep -v '(email|SELECT|username)' | sort -u > $home/data/$workspace/emails.txt
     sed '1,4d' /tmp/names | head -n -5 > $home/data/$workspace/names.txt
     sed '1,4d' /tmp/usernames | head -n -5 > $home/data/$workspace/usernames.txt
     cd /tmp/; rm emails names* usernames 2>/dev/null

     echo
     echo $medium
     echo
     echo -e "The new files are located at ${YELLOW}$home/data/$workspace/${NC}\n"
     echo
     echo
     exit
     ;;

     4) f_main;;

     *) f_error;;
esac

