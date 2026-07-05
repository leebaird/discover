#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

DISCOVER="${DISCOVER:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
export DISCOVER

if ! declare -f f_banner >/dev/null 2>&1; then
    DISCOVER_SOURCE_ONLY=1 source "$DISCOVER/discover.sh"
fi

trap 'pkill -f nikto; exit' INT TERM

# Check for regular user
if [ "$EUID" == 0 ]; then
    echo
    echo "[!] This option cannot be ran as root."
    echo
    exit   # Do not use exit 1 here, it will break the script
fi

if grep -q 'Nikto/@VERSION' /etc/nikto/config.txt; then
    echo
    echo -e "[!] Remove the default user agent string located at ${YELLOW}/etc/nikto/config.txt${NC}"
    echo
    exit 0
fi

if grep -q '^RFIURL=http://cirt.net/rfiinc.txt?' /etc/nikto/config.txt; then
    echo
    echo -e "[!] Comment out RFIURL checks located at ${YELLOW}/etc/nikto/config.txt${NC}"
    echo
    exit 0
fi

f_nikto_select_tool(){
    if command -v ydotool >/dev/null 2>&1 && pgrep ydotoold >/dev/null 2>&1; then
        XDOTOOL="sudo ydotool"
        ENTER="enter"
        return 0
    fi

    if command -v xdotool >/dev/null 2>&1; then
        XDOTOOL="xdotool"
        ENTER="Return"
        return 0
    fi

    echo
    if command -v ydotool >/dev/null 2>&1; then
        echo -e "${YELLOW}[!] ydotool is installed but ydotoold is not running.${NC}"
        echo -e "${YELLOW}[!] Start the daemon (sudo ydotoold &) or install xdotool via Discover Update.${NC}"
    else
        echo -e "${YELLOW}[!] Neither xdotool nor ydotool is installed.${NC}"
        echo -e "${YELLOW}[!] Run the Update option from the main menu.${NC}"
    fi
    echo
    return 1
}

f_nikto_complete(){
    local mode="$1"
    local port="${2:-}"

    echo
    echo "$MEDIUM"
    echo
    echo "[*] Scan complete."
    echo

    if [ "$mode" = "1" ]; then
        echo -e "The new report is located at ${YELLOW}$HOME/data/nikto-$port/${NC}"
    else
        echo -e "The new report is located at ${YELLOW}$HOME/data/nikto/${NC}"
    fi

    echo
}

clear
f_banner

f_nikto_select_tool || exit 0

echo -e "${BLUE}Run multiple instances of Nikto in parallel.${NC}"
echo
echo "1.  List of IPs"
echo "2.  List of IP:port"
echo "3.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE

case "$CHOICE" in
    1)
        f_location

        echo
        echo -n "Port (default 80): "
        read -r PORT
        echo

        if [ -z "$PORT" ]; then
            PORT=80
        fi

        if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
            f_error
            exit 0
        fi

        mkdir -p "$HOME/data/nikto-$PORT"

        while IFS= read -r LINE; do
            [ -z "$LINE" ] && continue
            $XDOTOOL key ctrl+shift+t
            $XDOTOOL type "nikto -h $LINE -port $PORT -no404 -maxtime 15m -Format htm --output $HOME/data/nikto-$PORT/$LINE.htm ; exit"
            sleep 2
            $XDOTOOL key $ENTER
        done < "$LOCATION"

        f_nikto_complete 1 "$PORT"
        ;;

    2)
        f_location

        mkdir -p "$HOME/data/nikto"

        while IFS=: read -r HOST PORT; do
            [ -z "$HOST" ] || [ -z "$PORT" ] && continue
            $XDOTOOL key ctrl+shift+t
            sleep 2
            $XDOTOOL type "nikto -h $HOST -port $PORT -no404 -maxtime 15m -Format htm --output $HOME/data/nikto/$HOST-$PORT.htm ; exit"
            sleep 2
            $XDOTOOL key $ENTER
        done < "$LOCATION"

        f_nikto_complete 2
        ;;

    3)
        f_main
        exit 0
        ;;

    *)
        f_error
        exit 0
        ;;
esac