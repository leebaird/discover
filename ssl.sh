#!/usr/bin/bash

clear
f_banner

echo -e "${BLUE}Check for SSL certificate issues.${NC}"
echo
echo "List of IP:port."
echo

f_location

echo
echo $medium
echo

echo "Running sslyze."
sslyze --targets_in=$location --resum --reneg --heartbleed --certinfo --sslv2 --sslv3 --openssl_ccs > tmp
# Remove the first 20 lines and cleanup
sed '1,20d' tmp | egrep -v '(=>|error:|ERROR|is trusted|NOT SUPPORTED|OK - Supported|OpenSSLError|Server rejected|timeout|unexpected error)' |
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
cat -s > $home/data/sslyze.txt

###############################################################################################################################

echo "Running sslscan."
echo

START=$(date +%r\ %Z)

echo $medium >> tmp
echo >> tmp

number=$(wc -l $location | cut -d ' ' -f1)
N=0

while read -r line; do
     N=$((N+1))
     echo $line > ssl_$line

     echo -n "[$N/$number]  $line"
     sslscan --ipv4 --ssl2 --ssl3 --tlsall --no-colour --connect-timeout=30 $line > tmp_$line
     echo
     echo >> ssl_$line

     if [ -f tmp_$line ]; then
          error=$(grep 'ERROR:' tmp_$line)

          if [ ! $error ]; then
               cat tmp_$line >> ssl_$line
               echo $medium >> ssl_$line
               echo >> ssl_$line
               cat ssl_$line >> tmp
          else
               echo -e "${RED}Could not open a connection.${NC}"
               echo "[*] Could not open a connection." >> ssl_$line
               echo >> ssl_$line
               echo $medium >> ssl_$line
               echo >> ssl_$line
               cat ssl_$line >> tmp
          fi
     else
          echo -e "${RED}No response.${NC}"
          echo "[*] No response." >> ssl_$line
          echo >> ssl_$line
          echo $medium >> ssl_$line
          echo >> ssl_$line
          cat ssl_$line >> tmp
     fi
done < "$location"

END=$(date +%r\ %Z)

echo "sslscan Report" > tmp2
date +%A" - "%B" "%d", "%Y >> tmp2
echo >> tmp2
echo "Start time   $START" >> tmp2
echo "Finish time  $END" >> tmp2
echo "Scanner IP   $ip" >> tmp2

mv tmp2 $home/data/sslscan.txt

grep -v 'info not available.' tmp >> $home/data/sslscan.txt
rm tmp* ssl_* 2>/dev/null

###############################################################################################################################

echo
echo "Running nmap."
echo

number=$(wc -l $location | cut -d ' ' -f1)
N=0

while read -r line; do
     N=$((N+1))
     port=$(echo $line | cut -d ':' -f2)
     target=$(echo $line | cut -d ':' -f1)

     echo -n "[$N/$number]  $line"
     sudo nmap -Pn -n -T4 --open -p $port -sV --script=rsa-vuln-roca,ssl*,tls-alpn,tls-ticketbleed --script-timeout 20s $target > tmp
     echo

     egrep -v '(does not|incorrect results|service unrecognized)' tmp | grep -v '^SF' |
     # Find FOO, if the next line is blank, delete both lines
     awk '/latency/ { latency = 1; next }  latency == 1 && /^$/ { latency = 0; next }  { latency = 0 }  { print }' |
     sed 's/Nmap scan report for //g; s/( https:\/\/nmap.org ) //g' >> tmp2
     echo $medium >> tmp2
     echo >> tmp2
done < $location

mv tmp2 $home/data/nmap-ssl.txt
rm tmp

echo
echo $medium
echo
echo "***Scan complete.***"
echo
echo
echo -e "The new reports are located at ${YELLOW}$home/data/sslscan.txt ${NC}and ${YELLOW}nmap-ssl.txt ${NC}"
