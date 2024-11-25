#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

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
read -r CHOICE

case "$CHOICE" in
    1)  f_location

        echo
        echo -n "Port (default 80): "
        read -r PORT
        echo

        # Set default port to 80 if not provided
        if [ -z "$PORT" ]; then
            PORT=80
        fi

        # Check for a valid port number
        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
            f_error
        fi

        mkdir -p "$HOME/data/nikto-$PORT"

        while IFS= read -r LINE; do
            xdotool key ctrl+shift+t
            xdotool type "nikto -h $LINE -port $PORT -no404 -maxtime 15m -Format htm --output $HOME/data/nikto-$PORT/$LINE.htm ; exit"
            sleep 1
            xdotool key Return
        done < "$LOCATION"
        ;;

    2)  f_location

        mkdir -p "$HOME/data/nikto"

        while IFS=: read -r HOST PORT; do
            xdotool key ctrl+shift+t
            sleep 1
            xdotool type "nikto -h $HOST -port $PORT -no404 -maxtime 15m -Format htm --output $HOME/data/nikto/$HOST-$PORT.htm ; exit"
            sleep 1
            xdotool key Return
        done < "$LOCATION"
        ;;

    3)  f_main ;;

    *) echo; echo -e "${RED}[!] Invalid choice or entry, try again.${NC}"; echo; sleep 2; "$DISCOVER"/nikto.sh ;;
esac

echo
echo "$MEDIUM"
echo
echo "[*] Scan complete."
echo
echo -e "The new report is located at ${YELLOW}$HOME/data/nikto-$PORT/${NC}"
