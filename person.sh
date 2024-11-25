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

xdg-open https://www.411.com/name/"$FIRST"-"$LAST"/ &
sleep 2
URIPATH="https://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn=${FIRST}&mi=&ln=${LAST}&age=&city=&state="
xdg-open "$URIPATH" &
sleep 2
xdg-open https://www.familytreenow.com/search/genealogy/results?first="$FIRST"&last="$LAST" &
sleep 2
xdg-open https://www.peekyou.com/"$FIRST"%5f"$LAST" &
sleep 2
xdg-open https://www.addresses.com/people/"$FIRST"+"$LAST" &
sleep 2
xdg-open https://www.spokeo.com/"$FIRST"-"$LAST" &
sleep 2
xdg-open https://www.usphonebook.com/"$FIRST"-"$LAST"
sleep 2
xdg-open https://www.youtube.com/results?search_query="$FIRST"+"$LAST" &
