#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

clear
f_banner

echo -e "${BLUE}Check for SSL certificate issues.${NC}"
echo
echo "List of IP:port."
echo

f_location

echo
echo "$MEDIUM"
echo

echo "Running sslyze."
sslyze --targets_in="$LOCATION" --resum --reneg --heartbleed --certinfo --sslv2 --sslv3 --openssl_ccs > tmp
# Remove the first 20 lines and cleanup
sed '1,20d' tmp | grep -Eiv '(=>|error:|error|is trusted|not supported|ok - supported|opensslerror|server rejected|timeout|unexpected error)' |
# Find FOO, if the next line is blank, delete both lines
awk '/Compression/ { Compression = 1; next }  Compression == 1 && /^$/ { Compression = 0; next }  { Compression = 0 }  { print }' |
awk '/Renegotiation/ { Renegotiation = 1; next }  Renegotiation == 1 && /^$/ { Renegotiation = 0; next }  { Renegotiation = 0 }  { print }' |
awk '/Resumption/ { Resumption = 1; next }  Resumption == 1 && /^$/ { Resumption = 0; next }  { Resumption = 0 }  { print }' |
awk '/SSLV2/ { SSLV2 = 1; next }  SSLV2 == 1 && /^$/ { SSLV2 = 0; next }  { SSLV2 = 0 }  { print }' |
awk '/SSLV3/ { SSLV3 = 1; next }  SSLV3 == 1 && /^$/ { SSLV3 = 0; next }  { SSLV3 = 0 }  { print }' |
awk '/Stapling/ { Stapling = 1; next }  Stapling == 1 && /^$/ { Stapling = 0; next }  { Stapling = 0 }  { print }' |
awk '/Unhandled/ { Unhandled = 1; next }  Unhandled == 1 && /^$/ { Unhandled = 0; next }  { Unhandled = 0 }  { print }' |
# Find a dash (-), if the next line is blank, delete it
awk -v n=-2 'NR==n+1 && !NF{next} /-/ {n=NR}1' |
# Remove double spacing
cat -s > "$HOME"/data/sslyze.txt

###############################################################################################################################

echo "Running sslscan."
echo

START=$(date +%r\ %Z)

echo "$MEDIUM" >> tmp
echo >> tmp

NUMBER=$(wc -l "$LOCATION" | cut -d ' ' -f1)
N=0

while read -r LINE; do
    N=$((N+1))
    echo "$LINE" > ssl_"$LINE"
    echo -n "[$N/$NUMBER]  $LINE"
    sslscan --ipv4 --ssl2 --ssl3 --tlsall --no-colour --connect-timeout=30 "$LINE" > tmp_"$LINE"
    echo
    echo >> ssl_"$LINE"

    if [ -f tmp_"$LINE" ]; then
        ERROR=$(grep 'ERROR:' tmp_"$LINE")

        if [ ! "$ERROR" ]; then
            cat tmp_"$LINE" >> ssl_"$LINE"
            echo "$MEDIUM" >> ssl_"$LINE"
            echo >> ssl_"$LINE"
            cat ssl_"$LINE" >> tmp
        else
            echo -e "${RED}Could not open a connection.${NC}"
            echo "[*] Could not open a connection." >> ssl_"$LINE"
            echo >> ssl_"$LINE"
            echo "$MEDIUM" >> ssl_"$LINE"
            echo >> ssl_"$LINE"
            cat ssl_"$LINE" >> tmp
        fi
    else
        echo -e "${RED}No response.${NC}"
        echo "[*] No response." >> ssl_"$LINE"
        echo >> ssl_"$LINE"
        echo "$MEDIUM" >> ssl_"$LINE"
        echo >> ssl_"$LINE"
        cat ssl_"$LINE" >> tmp
    fi
done < "$LOCATION"

END=$(date +%r\ %Z)

echo "sslscan Report" > tmp2
date +%A" - "%B" "%d", "%Y >> tmp2
echo >> tmp2
echo "Start time   $START" >> tmp2
echo "Finish time  $END" >> tmp2
echo "Scanner IP   $MYIP" >> tmp2

mv tmp2 "$HOME"/data/sslscan.txt

grep -v 'info not available.' tmp >> "$HOME"/data/sslscan.txt
rm tmp* ssl_* 2>/dev/null

###############################################################################################################################

echo
echo "Running nmap."
echo

NUMBER=$(wc -l "$LOCATION" | cut -d ' ' -f1)
N=0

while read -r LINE; do
    N=$((N+1))
    PORT=$(echo "$LINE" | cut -d ':' -f2)
    TARGET=$(echo "$LINE" | cut -d ':' -f1)

    echo -n "[$N/$NUMBER]  $LINE"
    sudo nmap -Pn -n -T4 --open -p "$PORT" -sV --script=rsa-vuln-roca,ssl*,tls-alpn,tls-ticketbleed --script-timeout 20s "$TARGET" > tmp
    echo

    grep -Eiv '(does not|incorrect results|service unrecognized)' tmp | grep -v '^SF' |
    # Find FOO, if the next line is blank, delete both lines
    awk '/latency/ { latency = 1; next }  latency == 1 && /^$/ { latency = 0; next }  { latency = 0 }  { print }' |
    sed 's/Nmap scan report for //g; s/( https:\/\/nmap.org ) //g' >> tmp2
    echo "$MEDIUM" >> tmp2
    echo >> tmp2
done < "$LOCATION"

mv tmp2 "$HOME"/data/nmap-ssl.txt
rm tmp

echo
echo "$MEDIUM"
echo
echo "[*] Scan complete."
echo
echo
echo -e "The new reports are located at ${YELLOW}$HOME/data/sslscan.txt ${NC}and ${YELLOW}nmap-ssl.txt ${NC}"
