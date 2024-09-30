#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

# Check for regular user
if [ "$EUID" == 0 ]; then
    echo
    echo "[!] This option cannot be ran as root."
    echo
    exit   # In this case do not use exit 1, it will break the script
fi

clear
f_banner

echo -e "${BLUE}Run multiple instances of Nikto in parallel.${NC}"
echo
echo "1.  List of IPs"
echo "2.  List of IP:port"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read -r choice

case "$choice" in
    1)
        f_location

        echo
        echo -n "Port (default 80): "
        read -r port
        echo

        # Set default port to 80 if not provided
        if [ -z "$port" ]; then
            port=80
        fi

        # Validate number and port number
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            f_error
        fi

        mkdir -p "$HOME/data/nikto-$port"

        while IFS= read -r line; do
            xdotool key ctrl+shift+t
            xdotool type "nikto -h $line -port $port -no404 -maxtime 15m -Format htm --output $HOME/data/nikto-$port/$line.htm ; exit"
            sleep 1
            xdotool key Return
        done < "$location"
        ;;

    2)
        f_location

        mkdir -p "$HOME/data/nikto"

        while IFS=: read -r host port; do
            xdotool key ctrl+shift+t
            sleep 1
            xdotool type "nikto -h $host -port $port -no404 -maxtime 15m -Format htm --output $HOME/data/nikto/$host-$port.htm ; exit"
            sleep 1
            xdotool key Return
        done < "$location"
        ;;

    3) f_main;;

    *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2;"$discover"/nikto.sh;;
esac

echo
echo "$medium"
echo
echo "[*] Scan complete."
echo
echo -e "The new report is located at ${YELLOW}$HOME/data/nikto-$port/${NC}"
