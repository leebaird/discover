#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_runlocally
clear
f_banner

# Check if Firefox is running
if pgrep firefox > /dev/null; then
    echo
    echo "[!] Close Firefox before running script."
    echo
    exit 1
fi

echo -e "${BLUE}RECON${NC}"
echo
echo -n "First name: "
read -r FIRST

# Check for no answer
if [ -z "$FIRST" ]; then
    f_error
fi

echo -n "Last name:  "
read -r LAST

# Check for no answer
if [ -z "$LAST" ]; then
    f_error
fi

DASH="${FIRST}-${LAST}"
PLUS="${FIRST}+${LAST}"
SPACE="${FIRST}%20${LAST}"
UNDERSCORE="${FIRST}%5f${LAST}"

URLS=(
    "https://www.whitepages.com/name/${DASH}/"
    "https://www.fastbackgroundcheck.com/people/${DASH}"
    "https://www.411.com/name/${DASH}/"
    "https://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn=${FIRST}&mi=&ln=${LAST}&age=&city=&state="
    "https://www.familytreenow.com/search/genealogy/results?first=${FIRST}&last=${LAST}"
    "https://www.peekyou.com/${UNDERSCORE}"
    "https://www.addresses.com/people/${PLUS}"
    "https://radaris.com/p/${FIRST}/${LAST}-US/"
    "https://www.spokeo.com/${DASH}"
    "https://www.truepeoplesearch.com/results?name=${SPACE}"
    "https://www.usphonebook.com/${DASH}"
    "https://www.facebook.com/public/${DASH}"
    "https://www.youtube.com/results?search_query=${PLUS}"
)

for URL in "${URLS[@]}"; do
    xdg-open "$URL" &
    sleep 2
done

