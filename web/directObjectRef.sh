#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

clear
f_banner

echo -e "${BLUE}Using Burp, authenticate to a site, map & Spider, then log out.${NC}"
echo -e "${BLUE}Target > Site map > select the URL > right click > Copy URLs in${NC}"
echo -e "${BLUE}this host. Paste the results into a new file.${NC}"

echo
echo -n "Enter the location of your file: "
read -r LOCATION

# Check for no answer
if [ -z "$LOCATION" ]; then
    f_error
fi

# Check for wrong answer
if [ ! -f "$LOCATION" ]; then
    f_error
fi

###############################################################################################################################

while read -r i; do
    curl -sk -w "%{http_code} - %{url_effective} \\n" "$i" -o /dev/null 2>&1 | tee -a tmp
done < "$LOCATION"

cat tmp | sort -u > DirectObjectRef.txt
mv DirectObjectRef.txt "$HOME"/data/DirectObjectRef.txt
rm tmp

echo
echo "$MEDIUM"
echo
echo "[*] Scan complete."
echo
echo -e "The new report is located at ${YELLOW}$HOME/data/DirectObjectRef.txt${NC}"
