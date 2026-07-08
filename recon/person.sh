#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_runlocally
clear
f_banner

echo -e "${BLUE}RECON - PERSON${NC}"
echo
echo -e "${BLUE}Uses multiple websites to gather info on a person.${NC}"
echo
echo -n "First name: "
read -r FIRST

if [ -z "$FIRST" ]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] A first name is required.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 1
fi

echo -n "Last name:  "
read -r LAST

if [ -z "$LAST" ]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] A last name is required.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 1
fi

DASH="${FIRST}-${LAST}"
PLUS="${FIRST}+${LAST}"
SPACE="${FIRST}%20${LAST}"

URLS=(
    "https://www.whitepages.com/name/${DASH}/"
    "https://www.fastbackgroundcheck.com/people/${DASH}"
    "https://www.411.com/name/${DASH}/"
    "https://www.advancedbackgroundchecks.com/find/name/${DASH}"
    "https://www.familytreenow.com/search/genealogy/results?first=${FIRST}&last=${LAST}"
    "https://www.addresses.com/people/${PLUS}"
    "https://radaris.com/p/${FIRST}/${LAST}-US/"
    "https://www.spokeo.com/${DASH}"
    "https://www.truepeoplesearch.com/results?name=${SPACE}"
    "https://www.usphonebook.com/${DASH}"
    "https://www.facebook.com/public/${DASH}"
    "https://www.youtube.com/results?search_query=${PLUS}"
)

if ! command -v firefox >/dev/null 2>&1; then
    echo
    echo -e "${RED}[!] Firefox is not installed.${NC}"
    echo
    sleep 2
    exit 1
fi

f_firefox_user_agents

for url in "${URLS[@]}"; do
    user_agent="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
    MOZ_DISABLE_ATK_BRIDGE=1 GTK_A11Y=none firefox "$url" --user-agent="$user_agent" >/dev/null 2>&1 &
    sleep 2
done

exit 0

