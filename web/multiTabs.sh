#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_runlocally
clear
f_banner

f_firefox_tabs(){
    local -a urls=()
    local url

    for url in "$@"; do
        [ -n "$url" ] && urls+=("$url")
    done

    if [ ${#urls[@]} -eq 0 ]; then
        echo
        echo "[!] No URLs to open."
        echo
        return 1
    fi

    if ! command -v firefox >/dev/null 2>&1; then
        echo
        echo -e "${RED}[!] firefox is not installed.${NC}"
        echo
        return 1
    fi

    echo
    echo "[*] Opening ${#urls[@]} tabs in Firefox."
    echo

    MOZ_DISABLE_ATK_BRIDGE=1 GTK_A11Y=none firefox --new-window "${urls[@]}" >/dev/null 2>&1 &
}

f_firefox_tabs_from_list(){
    local scheme="$1"
    local file="$2"
    local -a urls=()
    local line

    while IFS= read -r line || [ -n "$line" ]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [ -z "$line" ] && continue
        if [[ "$line" =~ ^https?:// ]]; then
            urls+=("$line")
        else
            urls+=("${scheme}://${line}")
        fi
    done < "$file"

    f_firefox_tabs "${urls[@]}"
}

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
            f_firefox_tabs_from_list "http" "$LOCATION"
        elif [ "$PREFIX" == "y" ]; then
            f_firefox_tabs_from_list "https" "$LOCATION"
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

        if [ -z "$LOCATION" ]; then
            f_error
        fi

        if [ ! -d "$LOCATION" ]; then
            f_error
        fi

        LOCATION="$(cd "$LOCATION" && pwd)"
        urls=()
        for i in "$LOCATION"/*; do
            [ -f "$i" ] || continue
            urls+=("file://$i")
        done

        f_firefox_tabs "${urls[@]}"
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

        if [ -z "$DOMAIN" ]; then
            f_error
        fi

        if ! curl -kLs "$DOMAIN"/robots.txt -o robots.txt; then
            echo
            echo -e "${RED}[!] Failed to connect to $DOMAIN.${NC}"
            echo
            exit 1
        fi

        grep -i 'disallow' robots.txt | awk '{print $2}' | grep -iv disallow | sort -u > tmp

        urls=()
        while IFS= read -r i || [ -n "$i" ]; do
            [ -z "$i" ] && continue
            urls+=("https://$DOMAIN$i")
        done < tmp

        f_firefox_tabs "${urls[@]}"

        rm robots.txt
        mv tmp "$HOME"/data/"$DOMAIN"-robots.txt

        echo
        echo "$MEDIUM"
        echo
        echo "[*] Scan complete."
        echo
        echo -e "New report located at ${YELLOW}$HOME/data/$DOMAIN-robots.txt${NC}"
        echo
        exit
        ;;
    4) f_return_main ;;
    *) f_invalid; exit ;;
esac