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

echo -e "${BLUE}Open multiple tabs in Firefox with:${NC}"
echo
echo "1.  List"
echo "2.  Files in a directory"
echo "3.  Directories in robots.txt"
echo "4.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1)
        f_location
        echo
        echo -n "Use an https prefix? (y/N) "
        read -r PREFIX

        if [ -z "$PREFIX" ]; then
            while read -r i; do
                xdg-open http://"$i" &
                sleep 2
            done < "$LOCATION"

        elif [ "$PREFIX" == "y" ]; then
            while read -r i; do
                xdg-open https://"$i" &
                sleep 2
            done < "$LOCATION"

        else
            f_error
        fi

        exit
        ;;
    2)
        echo
        echo "$MEDIUM"
        echo
        echo -n "Enter the location of your directory: "
        read -r LOCATION

        # Check for no answer
        if [ -z "$LOCATION" ]; then
            f_error
        fi

        # Check for wrong answer
        if [ ! -d "$LOCATION" ]; then
            f_error
        fi

        cd "$LOCATION" || exit

        # option 1
        for i in $(ls -l | awk '{print $9}'); do
            xdg-open "$i" &
            sleep 2
        done

        exit
        ;;
    3)
        echo
        echo "$MEDIUM"
        echo
        echo "Usage: target.com or target-IP"
        echo
        echo -n "Domain: "
        read -r DOMAIN

        # Check for no answer
        if [ -z "$DOMAIN" ]; then
            f_error
        fi

        curl -kLs "$DOMAIN"/robots.txt -o robots.txt

        if ! curl -kLs "$DOMAIN"/robots.txt -o robots.txt; then
            echo
            echo -e "${RED}[!] Failed to connect to $DOMAIN.${NC}"
            echo
            exit 1
        fi

        grep -i 'disallow' robots.txt | awk '{print $2}' | grep -iv disallow | sort -u > tmp

        while read -r i; do
            xdg-open "https://$DOMAIN$i" &
            sleep 2
        done < tmp

        rm robots.txt
        mv tmp "$HOME"/data/"$DOMAIN"-robots.txt

        echo
        echo "$MEDIUM"
        echo
        echo "[*] Scan complete."
        echo
        echo -e "The new report is located at ${YELLOW}$HOME/data/$DOMAIN-robots.txt${NC}"
        echo
        exit
        ;;
    4) f_main ;;
    *) f_error ;;
esac
