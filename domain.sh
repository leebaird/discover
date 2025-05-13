#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

clear
f_banner

echo -e "${BLUE}RECON${NC}"
echo
echo "1.  Passive"
echo "2.  Find registered domains"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1) "$DISCOVER"/passive.sh && exit ;;
    2)
        clear
        f_banner

        echo -e "${BLUE}Find registered domains.${NC}"
        echo
        echo "Open a browser to https://www.reversewhois.io/"
        echo "Enter your domain and solve the captcha."
        echo "Select all > copy all of the text and paste into a new file."

        f_location
        echo
        grep '^[0-9]' "$LOCATION" | awk '{print $2}' | sort -u > tmp
        TOTAL=$(wc -l tmp | sed -e 's/^[ \t]*//' | cut -d ' ' -f1)

        while read -r REGDOMAIN; do
            IPADDR=$(dig +short "$REGDOMAIN" | grep -Eiv '(0.0.0.0|127.0.0.1|127.0.0.6)' | sed '/[a-z]/d')
            whois -H "$REGDOMAIN" | grep -Eiv '(#|please query|personal data|redacted|whois|you agree)' | sed '/^$/d' > tmp2
            wait

            REGEMAIL=$(grep 'Registrant Email:' tmp2 | cut -d ' ' -f3 | tr '[:upper:]' '[:lower:]')

            if [[ "$REGEMAIL" == *'abuse'* || "$REGEMAIL" == *'anonymize.com'* || "$REGEMAIL" == *'buydomains.com'* || "$REGEMAIL" == *'cloudflareregistrar.com'* || "$REGEMAIL" == *'contact-form'* || "$REGEMAIL" == *'contact.gandi.net'* || "$REGEMAIL" == *'csl-registrar.com'* || "$REGEMAIL" == *'domaindiscreet.com'* || "$REGEMAIL" == *'dynadot.com'* || "$REGEMAIL" == *'email'* || "$REGEMAIL" == *'gname.com'* || "$REGEMAIL" == *'google.com'* || "$REGEMAIL" == *'identity-protect.org'* || "$REGEMAIL" == *'meshdigital.com'* || "$REGEMAIL" == *'mydomainprovider.com'* || "$REGEMAIL" == *'myprivatename.com'* || "$REGEMAIL" == *'networksolutionsprivateregistration'* || "$REGEMAIL" == *'please'* || "$REGEMAIL" == *'p.o-w-o.info'* || "$REGEMAIL" == *'privacy'* || "$REGEMAIL" == *'Redacted'* || "$REGEMAIL" == *'redacted'* || "$REGEMAIL" == *'select'* || "$REGEMAIL" == *'tieredaccess.com'* ]]; then
                REGEMAIL=''
            fi

            REGORG=$(grep 'Registrant Organization:' tmp2 | cut -d ':' -f2 | cut -d ' ' -f2- | sed 's/     //g; s/administration/Administration/g; s/Anonymize, Inc/Anonymize Inc/g; s/By /by /g; s/, Corp/ Corp/g; s/Data Protected//g; s/family/Family/g; s/Identity Protect Limited//g; s/Identity Protection Service//g; s/, Inc. / Inc/g; s/, Inc/ Inc/g; s/, Inc /Inc/g; s/Inc./Inc/g; s/INFORMATION SYSTEMS AND MANAGEMENT CONSLANTS/Information Systems and Management Consultants/g; s/INSTITUTE/Institute/g; s/, LLC/ LLC/g; s/MEMORIAL/Memorial/g; s/, N.A./ N.A./g; s/N\/A//g; s/Not Disclosed//g; s/None//g; s/NULL//g; s/ (NYHQ)//g; s/Redacted for privacy//g; s/S.L./SL/g; s/Statutory Masking Enabled//g; s/UNIVERSITY/University/g; s/(US) //g; s/WEST VIRGINIA/West Virginia/g')

            if [[ "$REGORG" == *'Privacy'* || "$REGORG" == *'PRIVACY'* ]]; then
                    REGORG=''
            fi

            REGISTRAR=$(grep 'Registrar:' tmp2 | cut -d ' ' -f2- | sed 's/Co.,/Co./g; s/Corp.,/Corp/g; s/Hongkong/Hong Kong/g; s/Identity Protection Service//g; s/Gransy,/Gransy/g; s/, Inc/ Inc/g; s/Inc./Inc/g; s/IncUSA/Inc/g; s/KEY-SYSTEMS/Key-Systems/g; s/Limited,/Ltd /g; s/, LLC/ LLC/g; s/Ltd./Ltd/g; s/, Ltd/ Ltd/g; s/MARKMONITOR/MarkMonitor/g; s/MarkMonitor./MarkMonitor /g; s/Registrar://g; s/REGISTRAR OF DOMAIN NAMES//g; s/s.l./SL/g; s/, S.L./SL/g; s/technologies/Technologies/g; s/technology/Technology/g; s/^[ \t]*//' | head -n1)

            if [[ "$REGISTRAR" == 'Domains' ]]; then
                REGISTRAR=''
            fi

            echo "$REGDOMAIN,$IPADDR,$REGEMAIL,$REGORG,$REGISTRAR" | grep -v ',,,,' >> tmp3
            ((NUMBER+1))
            echo -ne "$NUMBER of $TOTAL domains"\\r
            sleep 2
        done < tmp

        echo "Domain,IP Address,Registration Email,Registration Org,Registrar" > tmp4
        cat tmp4 tmp3 | grep -Ev '^\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | column -t -s ',' | sed 's/[ \t]*$//' > "$HOME"/data/registered-domains
        rm tmp*

        echo
        echo "$MEDIUM"
        echo
        echo "[*] Scan complete."
        echo
        echo -e "The report is located at ${YELLOW}$HOME/data/registered-domains${NC}"
        echo
        exit
        ;;
    3) f_main ;;
    *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; "$DISCOVER"/domain.sh ;;
esac
