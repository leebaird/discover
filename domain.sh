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
     grep '^[0-9]' $location | awk '{print $2}' | sort -u > tmp
     total=$(wc -l tmp | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

     while read regdomain; do
          ipaddr=$(dig +short $regdomain | egrep -v '(0.0.0.0|127.0.0.1|127.0.0.6)' | sed '/[a-z]/d')
          whois -H "$regdomain" | egrep -iv '(#|please query|personal data|redacted|whois|you agree)' | sed '/^$/d' > tmp2
          wait

          regemail=$(grep 'Registrant Email:' tmp2 | cut -d ' ' -f3 | tr 'A-Z' 'a-z')

          if [[ $regemail == *'abuse'* || $regemail == *'anonymize.com'* || $regemail == *'buydomains.com'* || $regemail == *'cloudflareregistrar.com'* || $regemail == *'contact-form'* || $regemail == *'contact.gandi.net'* || $regemail == *'csl-registrar.com'* || $regemail == *'domaindiscreet.com'* || $regemail == *'dynadot.com'* || $regemail == *'email'* || $regemail == *'gname.com'* || $regemail == *'google.com'* || $regemail == *'identity-protect.org'* || $regemail == *'meshdigital.com'* || $regemail == *'mydomainprovider.com'* || $regemail == *'myprivatename.com'* || $regemail == *'networksolutionsprivateregistration'* || $regemail == *'please'* || $regemail == *'p.o-w-o.info'* || $regemail == *'privacy'* || $regemail == *'Redacted'* || $regemail == *'redacted'* || $regemail == *'select'* || $regemail == *'tieredaccess.com'* ]]; then
               regemail=''
          fi

          regorg=$(grep 'Registrant Organization:' tmp2 | cut -d ':' -f2 | cut -d ' ' -f2- | sed 's/      //g; s/administration/Administration/g; s/Anonymize, Inc/Anonymize Inc/g; s/By /by /g; s/, Corp/ Corp/g; s/Data Protected//g; s/family/Family/g; s/, Inc. / Inc/g; s/, Inc/ Inc/g; s/, Inc /Inc/g; s/Inc./Inc/g; s/INSTITUTE/Institute/g; s/, LLC/ LLC/g; s/MEMORIAL/Memorial/g; s/, N.A./ N.A./g; s/N\/A//g; s/Not Disclosed//g; s/None//g; s/NULL//g; s/ (NYHQ)//g; s/Redacted for privacy//g; s/S.L./SL/g; s/Statutory Masking Enabled//g; s/UNIVERSITY/University/g; s/(US) //g; s/WEST VIRGINIA/West Virginia/g')

          if [[ $regorg == *'Privacy'* || $regorg == *'PRIVACY'* ]]; then
               regorg=''
          fi

          registrar=$(grep 'Registrar:' tmp2 | cut -d ' ' -f2- | sed 's/Co.,/Co./g; s/Corp.,/Corp/g; s/Hongkong/Hong Kong/g; s/Identity Protection Service//g; s/Gransy,/Gransy/g; s/, Inc/ Inc/g; s/Inc./Inc/g; s/IncUSA/Inc/g; s/KEY-SYSTEMS/Key-Systems/g; s/Limited,/Ltd /g; s/, LLC/ LLC/g; s/Ltd./Ltd/g; s/, Ltd/ Ltd/g; s/MARKMONITOR/MarkMonitor/g; s/MarkMonitor./MarkMonitor /g; s/Registrar://g; s/REGISTRAR OF DOMAIN NAMES//g; s/s.l./SL/g; s/, S.L./SL/g; s/technologies/Technologies/g; s/technology/Technology/g; s/^[ \t]*//' | head -n1)

          if [[ $registrar == 'Domains' ]]; then
               registrar=''
          fi

          echo "$regdomain,$ipaddr,$regemail,$regorg,$registrar" | grep -v ',,,,' >> tmp3
          let number=number+1
          echo -ne "$number of $total domains"\\r
          sleep 2
     done < tmp

     echo 'Domain,IP Address,Registration Email,Registration Org,Registrar' > tmp4
     cat tmp4 tmp3 | grep -Ev '^\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | column -t -s ',' | sed 's/[ \t]*$//' > $home/data/registered-domains
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
