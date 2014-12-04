#!/bin/bash
clear

# License: GPLv3

# Variables
let I=0          # Used in the while loop's Google queries
METHOD="host"    # Default mode is set to host
let PAGES=5      # Default pages to download from Google
let VERBOSITY=0  # Verbosity is set to off as default
TMPRND=$RANDOM   # Random number used for temporany files
REGEXPRESULT='Results <b>[0-9,]*</b> - <b>[0-9,]*</b> of[" about "]+<b>[0-9,]*</b>' # Extraxct the number of results from a query
METHOD=host      # Default method set to host

usage (){
echo
echo
echo "goohost v.0.0.1 Beta"
echo
echo "Extracts hosts/subdomains, IP or emails for a specific domain with Google search."
echo "Author: watakushi"
echo "Thanks to: Johnny Long and GHDB for inspiration stuff"
echo "Special thanks to: Danya & Roberto"
echo
echo "Usage: $0 -t domain [-m <host|ip|mail> -p <1-20> -v]"
echo "-t: domain"
echo "-m: method: <ip|host|mail>. Default value is set to host"
echo "      host: raw google hosts and subdomains search"
echo "        ip: raw google hosts and subdomains search and performs a reverse DNS resolution"
echo "      mail: raw google email search"
echo "-p: pages [1-20]. Max number of pages to download. Default is 5."
echo "-v: verbosity. Default is off"
echo
echo "Example: $0 -t target.com -m ip -p 10 -v"
echo
echo
exit 1
}

# Extract the number of results Google gives from the query
getresult (){
RESULT=$(grep -Eio "$REGEXPRESULT" /tmp/goohost$I-$TMPRND.log | cut -d "<" -f6 | cut -d ">" -f2 | tr -d ",")
return $RESULT
}

while getopts "t:m:p:v" optname; do
     case "$optname" in
          "t")
          DOMAIN=$OPTARG
          ;;

          "m")
          METHOD=$OPTARG
          ;;

          "p")
          let PAGES=$OPTARG
          ;;

          "v")
          let VERBOSITY=1
          ;;

          "?")
          echo "[*] Error: Unknown option."
          usage
          ;;

          ":")
          echo "[*] Error: Argument needed."
          usage
          ;;

          *)
          echo "[*] Error: Unknown error."
          usage
          ;;
     esac
done

# Check for write permissions and several tools used in the script
if [ ! -x /usr/bin/wget ]; then
     echo "[*] Error: /usr/bin/wget not found."
     exit 1
fi

if [ ! -x /usr/bin/awk ]; then
     echo "[*] Error: /usr/bin/awk not found."
     exit 1
fi

if [ ! -x /bin/sed ]; then
     echo "[*] Error: /bin/sed not found."
     exit 1
fi

if [ ! -w /tmp ]; then
     echo "[*] Error: Can't write to /tmp - Permission denied."
     exit 1
fi

if [ ! -w ./ ]; then
     echo "[*] Error: Can't write in ./ - Permission denied."
     exit 1
fi

# Print usage if parameters are not passed to the script
if [[ -z $DOMAIN ]] || [[ $METHOD != host && $METHOD != ip && $METHOD != mail ]]; then
     usage
fi

# Use a regex based on the method option
case "$METHOD" in
     host)
     REGEXPQUERY='[a-zA-Z0-9\._-]+\.'$DOMAIN
     ;;

     ip)
     REGEXPQUERY='[a-zA-Z0-9\._-]+\.'$DOMAIN
     ;;

     mail)
     REGEXPQUERY="[a-zA-Z0-9._-]+@<em>$DOMAIN</em>"
     QEMAIL="+$DOMAIN"
     ;;
esac

# Set the number of queries to do. Default value 5.
if [[ $PAGES -lt 1 || $PAGES -gt 20 ]]; then
     echo "[-] Warning: Pages value not in the range 1-20. Default value used."
     let PAGES=5
     echo
fi

# Check for DNS wildcards
if [[ $(host idontexist.xxxxx$TMPRND.com | grep address) ]]; then
     echo
     echo "[-] Warning: DNS wildcard detected! With IP method you should have some false positive results."
     echo
fi

###########################################################################
# QUERY:0  Download the first google page with the site: parameter

# Google query
case "$METHOD" in
     host)
     GOOGLEQUERY0="http://www.google.com/search?num=100&q=site%3A$DOMAIN" #site:example.tld
     ;;

     ip)
     GOOGLEQUERY0="http://www.google.com/search?num=100&q=site%3A$DOMAIN" #site:example.tld
     ;;

     mail)
     GOOGLEQUERY0="http://www.google.com/search?num=100&q=site%3A$DOMAIN$QEMAIL" #example.tld site:example.tld
     ;;
esac

# Download with wget the page
wget -q -U "" "$GOOGLEQUERY0" -O /tmp/goohost$I-$TMPRND.log

# Extract the hosts/emails and save in the result file
grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log > result-$TMPRND.log

# Extract the number of results Google gives from the query
getresult

# Verbosity
if [ "$VERBOSITY" = "1" ]; then
     echo
     echo "Google Query n.$I \n"
     echo $GOOGLEQUERY0
     echo
     echo "Results for query: $RESULT \n"
     echo
fi

###########################################################################
# Start the loop, download the pages generated with different types of query

while [[ "$RESULT" -ge "100"  &&  "$I" -lt $PAGES-1 ]]; do
    let I=I+1

    case "$I" in
         1)
         # Google query
         case "$METHOD" in
              host)
              GOOGLEQUERY1="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3Awww.$DOMAIN" #site:example.tld -inurl:www.example.tld
              ;;

              ip)
              GOOGLEQUERY1="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3Awww.$DOMAIN" #site:example.tld -inurl:www.example.tld
              ;;

              mail)
              GOOGLEQUERY1="http://www.google.com/search?num=100&q=site%3A$DOMAIN$QEMAIL+mail" #site:example.tld example.tld mail
              ;;
         esac

         # Download with wget the page
         wget -q -U "" "$GOOGLEQUERY1" -O /tmp/goohost$I-$TMPRND.log

         # Extract the hosts/emails and save in the result file
         grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log >> result-$TMPRND.log

         # Extract the number of results Google gives from the query
         getresult

         #Verbosity
         if [ "$VERBOSITY" = "1" ]; then
              echo
              echo "Google Query n.$I \n"
              echo $GOOGLEQUERY1
              echo "\n"
              echo "Results for query: $RESULT \n"
              echo
         fi
         ;;

         2)
         # Google query
         case "$METHOD" in
              host)
              GOOGLEQUERY2="http://www.google.com/search?num=100&q=*.site%3A$DOMAIN+-inurl%3Awww.$DOMAIN" #site:example.tld -inurl:www.example.tld
              ;;

              ip)
              GOOGLEQUERY2="http://www.google.com/search?num=100&q=*.site%3A$DOMAIN+-inurl%3Awww.$DOMAIN" #site:example.tld -inurl:www.example.tld
              ;;

              mail)
              GOOGLEQUERY2="http://www.google.com/search?num=100&q=$site%3A$DOMAIN$QEMAIL+mail&start=200" #site:example.tld example.tld mail
              ;;
         esac

         # Download with wget the page
         wget -q -U "" "$GOOGLEQUERY2" -O /tmp/goohost$I-$TMPRND.log

         # Extract the hosts/emails and save in the result file
         grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log >> result-$TMPRND.log

         # Extract the number of results Google gives from the query
         getresult

         # Verbosity
         if [ "$VERBOSITY" = "1" ]; then
              echo
              echo "Google Query n.$I \n"
              echo $GOOGLEQUERY2
              echo
              echo "Results for query: $RESULT \n"
              echo
         fi

         # Generate top 6 file and pass the values to the next queries
         case "$METHOD" in
              host)
              grep -Eio $REGEXPQUERY result-$TMPRND.log | sort | uniq -i -c | sort -n -r |  grep -Eio $REGEXPQUERY | sed -e "s/.$DOMAIN//g" > /tmp/top6-$TMPRND.log
              ;;

              ip)
              grep -Eio $REGEXPQUERY result-$TMPRND.log | sort | uniq -i -c | sort -n -r |  grep -Eio $REGEXPQUERY | sed -e "s/.$DOMAIN//g" > /tmp/top6-$TMPRND.log
              ;;

              mail)
              grep -Eio $REGEXPQUERY result-$TMPRND.log | sort | uniq -i -c | sort -n -r |  grep -Eio $REGEXPQUERY | cut -d "@" -f1 > /tmp/top6-$TMPRND.log
              ;;
         esac
         ;;

         3)
         CURL1=$(awk NR==1 /tmp/top6-$TMPRND.log)
         CURL2=$(awk NR==2 /tmp/top6-$TMPRND.log)
         CURL3=$(awk NR==3 /tmp/top6-$TMPRND.log)
         CURL4=$(awk NR==4 /tmp/top6-$TMPRND.log)
         CURL5=$(awk NR==5 /tmp/top6-$TMPRND.log)
         CURL6=$(awk NR==6 /tmp/top6-$TMPRND.log)

         # Google query
         case "$METHOD" in
              host)
              GOOGLEQUERY3="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3A$CURL1+-inurl%3A$CURL2+-inurl%3A$CURL3+-inurl%3A$CURL4+-inurl%3A$CURL5+-inurl%3A$CURL6" #site:example.tlf -inurl:top1 -inurl:top2 -inurl:top3 -inurl:top4 -inurl:top5 -inurl:top6
              ;;

              ip)
              GOOGLEQUERY3="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3A$CURL1+-inurl%3A$CURL2+-inurl%3A$CURL3+-inurl%3A$CURL4+-inurl%3A$CURL5+-inurl%3A$CURL6" #site:example.tlf -inurl:top1 -inurl:top2 -inurl:top3 -inurl:top4 -inurl:top5 -inurl:top6
              ;;

              mail)
              GOOGLEQUERY3="http://www.google.com/search?num=100&q=$QEMAILsite%3A$DOMAIN+-intext%3A$CURL1+-intext%3A$CURL2+-intext%3A$CURL3+-intext%3A$CURL4+-intext%3A$CURL5+-intext%3A$CURL6" #site:example.tlf -intext:info
              ;;
         esac

         # Download with wget the page
         wget -q -U  "" "$GOOGLEQUERY3" -O /tmp/goohost$I-$TMPRND.log

         # Extract the hosts/emails and save in the result file
         grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log >> result-$TMPRND.log

         # Extract the number of results google gives from the query
         getresult

         # Verbosity
         if [ "$VERBOSITY" = "1" ]; then
              echo
              echo "Google Query n.$I \n"
              echo $GOOGLEQUERY3
              echo
              echo "Result for query: $RESULT \n"
              # Print the top 6 host from result-$TMPRND.log
              echo "The TOP6 are: \n"
              echo "$CURL1 $CURL2 $CURL3 $CURL4 $CURL5 $CURL6"
              echo
         fi
         ;;

         4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 )

         let START=($I-3)*100 # Google query top 6 changed the start parameter

         # Google query
         case "$METHOD" in
             host)
              GOOGLEQUERY3="http://www.google.com/search?num=100&start=$START&q=site%3A$DOMAIN+-inurl%3A$CURL1+-inurl%3A$CURL2+-inurl%3A$CURL3+-inurl%3A$CURL4+-inurl%3A$CURL5+-inurl%3A$CURL6" #site:example.tlf -inurl:top1 -inurl:top2 -inurl:top3 -inurl:top4 -inurl:top5 -inurl:top6
             ;;

             ip)
              GOOGLEQUERY3="http://www.google.com/search?num=100&start=$START&q=site%3A$DOMAIN+-inurl%3A$CURL1+-inurl%3A$CURL2+-inurl%3A$CURL3+-inurl%3A$CURL4+-inurl%3A$CURL5+-inurl%3A$CURL6" #site:example.tlf -inurl:top1 -inurl:top2 -inurl:top3 -inurl:top4 -inurl:top5 -inurl:top6
             ;;

             mail)
             GOOGLEQUERY3="http://www.google.com/search?num=100&start=$START&q=$QEMAILsite%3A$DOMAIN+-intext%3A$CURL1+-intext%3A$CURL2+-intext%3A$CURL3+-intext%3A$CURL4+-intext%3A$CURL5+-intext%3A$CURL6" #site:example.tlf -intext:info
             ;;
         esac

         # Download with wget the page
         wget -q -U  "" "$GOOGLEQUERY3" -O /tmp/goohost$I-$TMPRND.log

         # Extract the hosts/emails and save in the result file
         grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log >> result-$TMPRND.log

         # Extract the number of results Google gives from the query
         getresult

         # Check how many pages to download with this query
         let END=($RESULT/100) # Number of pages to download

         if [[ $I -ge $END+3 ]]; then
             let I=12
         fi

         # Verbosity
         if [ "$VERBOSITY" = "1" ]; then
              echo
              echo "Google Query n.$I \n"
              echo $GOOGLEQUERY3
              echo
              echo "Result for query: $RESULT \n"
              # Print the top 6 host from result-$TMPRND.log
              echo "The TOP6 are: \n"
              echo "$CURL1 $CURL2 $CURL3 $CURL4 $CURL5 $CURL6"
              echo
         fi
         ;;

         13)

         #Generate temporary file for the random query
         case "$METHOD" in
              host)
              sort -u result-$TMPRND.log | sed -e "s/.$DOMAIN//g" > /tmp/random-$TMPRND.log
              ;;

              ip)
              sort -u result-$TMPRND.log | sed -e "s/.$DOMAIN//g" > /tmp/random-$TMPRND.log
              ;;

              mail)
              sort -u result-$TMPRND.log | cut -d "@" -f1 > /tmp/random-$TMPRND.log
              ;;
         esac

         highest=$(wc -l /tmp/random-$TMPRND.log | cut -d " " -f1 ) # Number of hosts present in the result file

         #################################################
         #TODO: Exit from the case loop if highest is <= 0
         #################################################
         if [[ $highest -ge "1" ]]; then
              R1=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
              R2=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
              R3=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
              R4=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
              R5=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
              R6=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]

              RURL1="$(awk "NR==$R1" /tmp/random-$TMPRND.log)"
              RURL2="$(awk "NR==$R2" /tmp/random-$TMPRND.log)"
              RURL3="$(awk "NR==$R3" /tmp/random-$TMPRND.log)"
              RURL4="$(awk "NR==$R4" /tmp/random-$TMPRND.log)"
              RURL5="$(awk "NR==$R5" /tmp/random-$TMPRND.log)"
              RURL6="$(aewk "NR==$R6" /tmp/random-$TMPRND.log)"

              # Google query
              case "$METHOD" in
                   host)
                   GOOGLEQUERY4="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3A$RURL1+-inurl%3A$RURL2+-inurl%3A$RURL3+-inurl%3A$RURL4+-inurl%3A$RURL5+-inurl%3A$RURL6" #site:example.tlf -inurl:random1 -inurl:random2 -inurl:random3 -inurl:random4 -inurl:random5 -inurl:random6
                   ;;

                   ip)
                   GOOGLEQUERY4="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3A$RURL1+-inurl%3A$RURL2+-inurl%3A$RURL3+-inurl%3A$RURL4+-inurl%3A$RURL5+-inurl%3A$RURL6" #site:example.tlf -inurl:random1 -inurl:random2 -inurl:random3 -inurl:random4 -inurl:random5 -inurl:random6
                   ;;

                   mail)
                   GOOGLEQUERY4="http://www.google.com/search?num=100&q=$QEMAILsite%3A$DOMAIN+-intext%3A$RURL1+-intext%3A$RURL2+-intext%3A$RURL3+-intext%3A$RURL4+-intext%3A$RURL5+-intext%3A$RURL6" #site:example.tlf example.tld -itext:random1 -intext:random2 -intext:random3 -intext:random4 -intext:random5 -intext:random6
                   ;;
              esac

              # Download with wget the page
              wget -q -U "" "$GOOGLEQUERY4" -O /tmp/goohost$I-$TMPRND.log

              # Extract the hosts/emails and save in the result file
              grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log >> result-$TMPRND.log

              # Extract the number of results Google gives from the query
              getresult

              # Verbosity
              if [ "$VERBOSITY" = "1" ]; then
                  echo
                  echo "Google Query n.$I \n"
                  echo $GOOGLEQUERY4
                  echo
                  echo "Result for query: $RESULT \n"
                  echo "Random hosts: $RURL1 $RURL2 $RURL3 $RURL4 $RURL5 $RURL6 \n"
                  echo
              fi

         else
              let I=20
         fi
         ;;

         14 | 15 | 16 | 17 | 18 | 19)

         R1=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
         R2=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
         R3=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
         R4=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
         R5=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]
         R6=$[ ( $RANDOM % ( $[ $highest - 1 ] + 1 ) ) + 1 ]

         RURL1="$(awk "NR==$R1" /tmp/random-$TMPRND.log)"
         RURL2="$(awk "NR==$R2" /tmp/random-$TMPRND.log)"
         RURL3="$(awk "NR==$R3" /tmp/random-$TMPRND.log)"
         RURL4="$(awk "NR==$R4" /tmp/random-$TMPRND.log)"
         RURL5="$(awk "NR==$R5" /tmp/random-$TMPRND.log)"
         RURL6="$(awk "NR==$R6" /tmp/random-$TMPRND.log)"

         # Google query
         case "$METHOD" in
              host)
              GOOGLEQUERY4="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3A$RURL1+-inurl%3A$RURL2+-inurl%3A$RURL3+-inurl%3A$RURL4+-inurl%3A$RURL5+-inurl%3A$RURL6" #site:example.tlf -inurl:random1 -inurl:random2 -inurl:random3 -inurl:random4 -inurl:random5 -inurl:random6
              ;;

              ip)
              GOOGLEQUERY4="http://www.google.com/search?num=100&q=site%3A$DOMAIN+-inurl%3A$RURL1+-inurl%3A$RURL2+-inurl%3A$RURL3+-inurl%3A$RURL4+-inurl%3A$RURL5+-inurl%3A$RURL6" #site:example.tlf -inurl:random1 -inurl:random2 -inurl:random3 -inurl:random4 -inurl:random5 -inurl:random6
              ;;

              mail)
              GOOGLEQUERY4="http://www.google.com/search?num=100&q=$QEMAILsite%3A$DOMAIN+-intext%3A$RURL1+-intext%3A$RURL2+-intext%3A$RURL3+-intext%3A$RURL4+-intext%3A$RURL5+-intext%3A$RURL6" #site:example.tlf example.tld -itext:random1 -intext:random2 -intext:random3 -intext:random4 -intext:random5 -intext:random6
              ;;
         esac

         # Download with wget the page
         wget -q -U "" "$GOOGLEQUERY4" -O /tmp/goohost$I-$TMPRND.log

         # Extract the hosts/emails and save in the result file
         grep -Eio $REGEXPQUERY /tmp/goohost$I-$TMPRND.log >> result-$TMPRND.log

         # Extract the number of results Google gives from the query
         getresult

         # Verbosity
         if [ "$VERBOSITY" = "1" ]; then
             echo
             echo "Google Query n.$I \n"
             echo $GOOGLEQUERY4
             echo
             echo "Result for query: $RESULT \n"
             # Print the top 6 host from result-$TMPRND.log
             echo "Random hosts: $RURL1 $RURL2 $RURL3 $RURL4 $RURL5 $RURL6 \n"
             echo
         fi

         ;;
    esac
done

###########################################################################
# Generate output and report file

# Generate different report for different methods
case "$METHOD" in
     host)
     echo
     cat result-$TMPRND.log | sort -u > report-$TMPRND-$DOMAIN.txt
     echo "Results saved in file report-$TMPRND-$DOMAIN.txt \n"
     echo "$(wc -l report-$TMPRND-$DOMAIN.txt | cut -d" " -f1) results found! \n"
     ;;

     ip)
     echo

     for line in $(cat result-$TMPRND.log | sort -u); do
         host $line | grep "has address" | cut -d " " -f1,4 >> report-$TMPRND-$DOMAIN.txt &
     done

     echo "Results saved in file report-$TMPRND-$DOMAIN.txt \n"
     ;;

     mail)
     echo
     cat result-$TMPRND.log | sort -u | sed -e "s/<[^>]*>//g" > report-$TMPRND-$DOMAIN.txt
     echo "Results saved in file report-$TMPRND-$DOMAIN.txt \n"
     echo "$(wc -l report-$TMPRND-$DOMAIN.txt | cut -d" " -f1) results found! \n"
     ;;
esac

rm -f result-$TMPRND.log 2> /dev/null
rm -f /tmp/goohost*-$TMPRND.log 2> /dev/null
rm -f /tmp/random-$TMPRND.log 2> /dev/null
rm -f /tmp/top6-$TMPRND.log 2> /dev/null
