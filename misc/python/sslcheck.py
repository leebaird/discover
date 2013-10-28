# sslcheck.py
#
# By Lee Baird & Jason Arnold
# Feel free to contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
##############################################################################################################

os.system('clear')
banner()

print colorblue.format('SSL Check')
print
location = raw_input('Enter the location of your list: ')

if os.path.isfile(location):
     print location
     goodbye()
else:
     error()

#date2stamp()
     #date --utc --date "$1" +%s

#stamp2date()
     #date --utc --date "1970-01-01 $1 sec" "+%Y-%m-%d %T"


#datediff()
     #case $1 in
     #     -s) sec=1; shift;;
     #     -m) sec=60; shift;;
     #     -h) sec=3600; shift;;
     #     -d) sec=86400; shift;;
     #     *)  sec=86400;;
     #esac

#dte1=$(date2stamp $1)
#dte2=$(date2stamp $2)
#diffSec=$((dte2-dte1))

#if ((diffSec < 0)):
#     abs=-1
#else:
#     abs=1

#print $((diffSec/sec*abs))

#monthconv()
     #if [ "$1" == "Jan" ]; then monthnum="01"
     #if [ "$1" == "Feb" ]; then monthnum="02"
     #if [ "$1" == "Mar" ]; then monthnum="03"
     #if [ "$1" == "Apr" ]; then monthnum="04"
     #if [ "$1" == "May" ]; then monthnum="05"
     #if [ "$1" == "Jun" ]; then monthnum="06"
     #if [ "$1" == "Jul" ]; then monthnum="07"
     #if [ "$1" == "Aug" ]; then monthnum="08"
     #if [ "$1" == "Sep" ]; then monthnum="09"
     #if [ "$1" == "Oct" ]; then monthnum="10"
     #if [ "$1" == "Nov" ]; then monthnum="11"
     #if [ "$1" == "Dec" ]; then monthnum="12"

## Number of hosts
#number=$(wc -l $location | cut -d ' ' -f1)
#N=0

#print
#print 'Scanning $number IP addresses.'
#print

#print > tmp-report
#print >> tmp-report
#print 'SSL Report' >> tmp-report
#reportdate=$(date +%A" - "%B" "%d", "%Y)
#print $reportdate >> tmp-report
#print sslscan $(sslscan | grep 'Version' | awk '{print $2}') >> tmp-report
#print >> tmp-report
#print $line >> tmp-report
#print >> tmp-report

#while read -r line; do

#     # Initialize ssl_$line.txt file
#     print "$line" > ssl_$line.txt
#     N=$((N+1))
#     sslscan --no-failed $line > ssltmp_$line & pid=$!

#     # print "pid = $pid"  # debug statement
#     print -n "$line  [$N/$number]  "; sleep 40
#     print >> ssl_$line.txt

#     if [ -s ssltmp_$line ]:
#          ERRORCHECK=$(cat ssltmp_$line | grep 'ERROR:')
#          if [[ ! $ERRORCHECK ]]:

#               ISSUER=$(cat ssltmp_$line | grep 'Issuer:')
#               if [[ $ISSUER ]]:
#                    cat ssltmp_$line | grep 'Issuer:' >> ssl_$line.txt
#                    print >> ssl_$line.txt
#               else:
#                    print 'Issuer information not available for this certificate. Look into this!' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               SUBJECT=$(cat ssltmp_$line | grep 'Subject:')
#               if [[ $SUBJECT ]]:
#                    cat ssltmp_$line | grep 'Subject:' >> ssl_$line.txt
#                    print >> ssl_$line.txt
#               else:
#                    print 'Certificate subject information not available. Look into this!' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               DNS=$(cat ssltmp_$line | grep 'DNS:')
#               if [[ $DNS ]]:
#                    cat ssltmp_$line | grep 'DNS:' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               A=$(cat ssltmp_$line | grep -i 'MD5WithRSAEncryption')
#               if [[ $A ]]:
#                    print '[*] MD5-based Signature in TLS/SSL Server X.509 Certificate' >> ssl_$line.txt
#                    cat ssltmp_$line | grep -i 'MD5WithRSAEncryption' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               B=$(cat ssltmp_$line | grep 'NULL')
#               if [[ $B ]]:
#                    print '[*] NULL Ciphers' >> ssl_$line.txt
#                    cat ssltmp_$line | grep 'NULL' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               C=$(cat ssltmp_$line | grep 'SSLv2')
#               if [[ $C ]]"
#                    print '[*] TLS/SSL Server Supports SSLv2' >> ssl_$line.txt
#                    cat ssltmp_$line | grep 'SSLv2' > ssltmp2_$line
#                    sed '/^    SSL/d' ssltmp2_$line >> ssl_$line.txt
#                    print >> ssl_$line.txt
#                    rm ssltmp2_$line

#               D=$(cat ssltmp_$line | grep ' 40 bits')
#               D2=$(cat ssltmp_$line | grep ' 56 bits')

#               if [[ $D || $D2 ]]:
#                    print '[*] TLS/SSL Server Supports Weak Cipher Algorithms' >> ssl_$line.txt
#                    cat ssltmp_$line | grep ' 40 bits' >> ssl_$line.txt
#                    cat ssltmp_$line | grep ' 56 bits' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               datenow=$(date +%F)
#               # print datenow=$datenow
#               datenowstamp=$(date2stamp "$datenow")
#               # print datenowstamp=$datenowstamp
#               monthconv $(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $4'})
#               # print monthnum=$monthnum
#               expyear=$(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $7'})
#               # print expyear=$expyear
#               expday=$(grep "Not valid after:" ssltmp_$line | awk -F" " {'print $5'})
#               # print expday=$expday
#               expdate=$(print "$expyear-$monthnum-$expday")
#               # print expdate=$expdate
#               expdatestamp=$(date2stamp "$expdate")
#               # print expdatestamp=$expdatestamp
#               numdaysdiff=$(datediff $datenow $expdate)
#               # print numdaysdiff=$numdaysdiff

#               if (($expdatestamp < $datenowstamp)):
#                    print [*] X.509 Server Certificate is Invalid/Expired >> ssl_$line.txt
#                    print "    Cert Expire Date: $expdate" >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               E=$(cat ssltmp_$line | grep 'Authority Information Access:')
#               if [[ ! $E ]]:
#                    print '[*] Self-signed TLS/SSL Certificate' >> ssl_$line.txt
#                    print >> ssl_$line.txt

#               print $line >> ssl_$line.txt
#               print >> ssl_$line.txt
#               print
#               # print "kill $pid process test"
#               (sleep 5 && kill -9 $pid 2>/dev/null) &

#               # Add current data to tmp-report
#               cat ssl_$line.txt >> tmp-report
#          else:
#               print -e "\e[1;31mCould not open a connection.\e[0m"
#               print $ERRORCHECK >> ssl_$line.txt
#               print >> ssl_$line.txt
#               print $line >> ssl_$line.txt
#               cat ssl_$line.txt >> tmp-report
#     else:
#          print -e "\e[1;31mNo response.\e[0m"
#          print '[*] No response.' >> ssl_$line.txt
#          print >> ssl_$line.txt
#          print $line >> ssl_$line.txt

#          # Add current data to tmp-report
#          cat ssl_$line.txt >> tmp-report

#done < "$location"

#mv tmp-report /$user/ssl-report.txt
#rm ssltmp_* ssl_*.txt 2>/dev/null

#print
#print line
#print
#print "***Scan complete.***"
#print
#printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/ssl-report.txt
#print
#print
