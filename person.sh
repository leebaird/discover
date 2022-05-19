#!/usr/bin/bash

f_runlocally
clear
f_banner

echo -e "${BLUE}RECON${NC}"
echo
echo -n "First name: "
read firstName

# Check for no answer
if [ -z $firstName ]; then
     f_error
fi

echo -n "Last name:  "
read lastName

# Check for no answer
if [ -z $lastName ]; then
     f_error
fi

xdg-open https://www.411.com/name/$firstName-$lastName/ &
sleep 2
uripath="https://www.advancedbackgroundchecks.com/search/results.aspx?type=&fn=${firstName}&mi=&ln=${lastName}&age=&city=&state="
xdg-open $uripath &
sleep 2
xdg-open https://www.linkedin.com/pub/dir/?first=$firstName\&last=$lastName\&search=Search &
sleep 2
xdg-open https://www.peekyou.com/$firstName%5f$lastName &
sleep 2
xdg-open https://www.addresses.com/people/$firstName+$lastName &
sleep 2
xdg-open https://www.spokeo.com/$firstName-$lastName &
sleep 2
xdg-open https://twitter.com/search?q=%22$firstName%20$lastName%22&src=typd &
sleep 2
xdg-open https://www.youtube.com/results?search_query=$firstName+$lastName &
