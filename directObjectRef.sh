#!/usr/bin/bash

clear
f_banner

echo -e "${BLUE}Using Burp, authenticate to a site, map & Spider, then log out.${NC}"
echo -e "${BLUE}Target > Site map > select the URL > right click > Copy URLs in${NC}"
echo -e "${BLUE}this host. Paste the results into a new file.${NC}"

f_location

for i in $(cat $location); do
     curl -sk -w "%{http_code} - %{url_effective} \\n" "$i" -o /dev/null 2>&1 | tee -a tmp
done

cat tmp | sort -u > DirectObjectRef.txt
mv DirectObjectRef.txt $home/data/DirectObjectRef.txt
rm tmp

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The new report is located at ${YELLOW}$home/data/DirectObjectRef.txt${NC}\n"
