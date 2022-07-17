#!/usr/bin/bash

clear
f_banner

echo -e "${BLUE}RECON${NC}"
echo
echo "1.  Passive"
echo "2.  Active"
echo "3.  Find registered domains"
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

     echo -e "${BLUE}Find registered domains.${NC}"
     echo
     echo 'Open a browser to https://www.reversewhois.io/'
     echo 'Enter your domain and solve the captcha.'
     echo 'Select all > copy all of the text and paste into a new file.'

     f_location
     echo
     sed '1,10d' $location | head -n -27 | awk '{print $2}' | sort -u > tmp
     total=$(wc -l tmp | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

     while read regdomain; do
          ipaddr=$(dig +short $regdomain | sed '/[a-z]/d')
          whois -H "$regdomain" | grep -iv 'whois' > tmp2
          wait

          regemail=$(grep 'Registrant Email:' tmp2 | cut -d ' ' -f3 | tr 'A-Z' 'a-z')

          if [[ $regemail == *'contact-form'* || $regemail == *'contactprivacy'* || $regemail == *'domainprivacygroup'* || $regemail == *'email:'* || $regemail == *'networksolutionsprivateregistration'* || $regemail == *'please'* || $regemail == *'withheldforprivacy'* ]]; then
               regemail=''
          fi

          regorg=$(grep 'Registrant Organization:' tmp2 | cut -d ':' -f2 | cut -d ' ' -f2-)

          if [[ $regorg == *'Contact Privacy'* || $regorg == *'Privacy service'* ]]; then
               regorg=''
          fi

          registrar=$(grep 'Registrar:' tmp2 | cut -d ' ' -f2- | sed 's/Registrar://g' | sed 's/^[ \t]*//' | head -n1)

          echo "$regdomain,$ipaddr,$regemail,$regorg,$registrar" >> tmp3
          let number=number+1
          echo -ne "     ${YELLOW}$number ${NC}of ${YELLOW}$total ${NC}domains"\\r
          sleep 2
     done < tmp

     echo 'Domain,IP Address,Registration Email,Registration Org,Registrar' > tmp4
     cat tmp4 tmp3 | grep -Ev '^\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | egrep -v '(amazonaws.com|root-servers.net)' | sed 's/CORPORATION/Corporation/g; 
     s/DANESCO TRADING LTD./Danesco Trading Ltd./g; s/GLOBAL/Global/g; s/, LLC/ LLC/g; s/, Inc/ Inc/g; s/REGISTRAR OF DOMAIN NAMES/Registrar of Domain Names/g; 
     s/, UAB/ UAB/g' | column -t -s ',' | sed 's/[ \t]*$//' > $home/data/registered-domains
     rm tmp*

     echo
     echo
     echo $medium
     echo
     echo '***Scan complete.***'
     echo
     echo
     echo -e "The report is located at ${YELLOW}$home/data/registered-domains${NC}\n"
     exit
     ;;

     4) f_main;;

     *) f_error;;
esac
