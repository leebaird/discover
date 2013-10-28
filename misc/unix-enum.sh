#!/bin/bash

# by Jason Arnold

hname=`/bin/hostname`
fndate=`/bin/date +%F_%H.%M.%S.%Z`
outfile="/root/$hname-$fndate.txt"

break="###############################################################################"
echo
echo "New file located at $outfile"

# clear out prior file and recreate if exists
echo "" > $outfile

echo "`/bin/date`" >> $outfile
echo "" >> $outfile

echo "Hostname: $hname" >> $outfile
echo "" >> $outfile

echo "Kernel version:" >> $outfile
echo "`uname -a`" >> $outfile
echo "" >> $outfile

echo "System uptime:" >> $outfile
echo "`/usr/bin/uptime`" >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "Network information:" >> $outfile
echo "`/sbin/ifconfig -a`" >> $outfile
echo "" >> $outfile

echo "resolv.conf contents:" >> $outfile
echo "" >> $outfile
echo "`cat /etc/resolv.conf`" >> $outfile
echo "" >> $outfile

echo "Route:" >> $outfile
echo "" >> $outfile
echo "`route`" >> $outfile
echo "" >> $outfile

echo "Open ports and services:" >> $outfile
echo "" >> $outfile
echo "`netstat -lpn`" >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "Defined user accounts:" >> $outfile
echo "`cat /etc/passwd | /usr/bin/wc -l`" >> $outfile
echo "" >> $outfile

echo "passwd file contents:" >> $outfile
echo "`cat /etc/passwd`" >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "group file contents:" >> $outfile
echo "`cat /etc/group`" >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "Filesystem stats:" >> $outfile
echo "" >> $outfile
mount >> $outfile
echo "" >> $outfile
df -h >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "Listening ports:" >> $outfile
echo "" >> $outfile
netstat -n --listen >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "Process listing:" >> $outfile
echo "" >> $outfile
ps axuw >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "/var/log contents:" >> $outfile
echo "" >> $outfile
ls -lRa /var/log >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "/etc contents:" >> $outfile
echo "" >> $outfile
ls -lRa /etc >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "mail file sizes:" >> $outfile
echo "" >> $outfile
ls -l /var/spool/mail | awk -F" " {'print $5"\t"$6" "$7"\t"$9"\t\t"$3'} | sort -nr >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "Last 100 logins:" >> $outfile
echo "" >> $outfile
last -100 >> $outfile
echo "" >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "/tmp dir contents:" >> $outfile
echo "" >> $outfile
ls -lRa /tmp >> $outfile

echo $break >> $outfile
echo "" >> $outfile
echo "/var/log/messages contents:" >> $outfile
echo "" >> $outfile
cat /var/log/messages >> $outfile

echo "" >> $outfile
echo "" >> $outfile
echo "--- END OF REPORT for $hname ---" >> $outfile
echo
echo
