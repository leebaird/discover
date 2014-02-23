#!/bin/bash

clear

# Based on Metasploit post Linux modules

# Variables
hname=`/bin/hostname`
fndate=`/bin/date +%F_%H.%M.%S.%Z`
line="======================================================================"
user=$(whoami)

echo > tmp
/bin/date >> tmp
echo >> tmp

echo 'Whoami' >> tmp
/usr/bin/whoami >> tmp
echo >> tmp

echo 'Hostname' >> tmp
/bin/hostname >> tmp
echo >> tmp

echo 'Kernel' >> tmp
/bin/uname -a >> tmp
echo >> tmp

echo 'System uptime' >> tmp
/usr/bin/uptime >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Users' >> tmp
echo >> tmp
cat /etc/passwd >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Passwords' >> tmp
echo >> tmp
cat /etc/shadow >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'User groups' >> tmp
echo >> tmp
cat /etc/group >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Last 25 logins' >> tmp
echo >> tmp
/usr/bin/last -25 >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Listening ports' >> tmp
echo >> tmp
/bin/netstat -ant >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Filesystem stats' >> tmp
echo >> tmp
/bin/mount >> tmp
echo >> tmp
/bin/df -h >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Processes' >> tmp
echo >> tmp
ps aux >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Networking' >> tmp
echo >> tmp
/sbin/ifconfig -a >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
/sbin/route -e >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
/sbin/iptables -L >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
/sbin/iptables -L -t nat >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
/sbin/iptables -L -t mangle >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
echo '/etc/resolv.con' >> tmp
echo >> tmp
cat /etc/resolv.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'SSH config' >> tmp
echo >> tmp
cat /etc/ssh/sshd_config >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo '/etc/hosts' >> tmp
echo >> tmp
cat /etc/hosts >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
/usr/bin/lsof -nPi >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
/sbin/iwconfig >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
/bin/netstat -tulpn >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
ls -R /etc/network >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Apache config' >> tmp
echo >> tmp
cat /etc/apache2/apache2.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'Apache ports' >> tmp
echo >> tmp
cat /etc/apache2/ports.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/nginx/nginx.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'Snort config' >> tmp
echo >> tmp
cat /etc/snort/snort.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'MySQL config' >> tmp
echo >> tmp
cat /etc/mysql/my.cnf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/ufw/ufw.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/ufw/sysctl.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/security.access.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/shells >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/security/sepermit.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/ca-certificates.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/security/access.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/gated.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/rpc >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/psad/psad.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/mysql/debian.cnf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/chkrootkit.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/logrotate.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/rkhunter.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'Samba config' >> tmp
echo >> tmp
cat /etc/samba/smb.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'LDAP config' >> tmp
echo >> tmp
cat /etc/ldap/ldap.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'Open LDAP config' >> tmp
echo >> tmp
cat /etc/openldap/openldap.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
echo 'CUPS config' >> tmp
echo >> tmp
cat /etc/cups/cups.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/opt/lampp/etc/httpd.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/sysctl.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/proxychains.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/cups/snmp.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/mail/sendmail.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/snmp/snmp.conf >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp

echo 'Misc' >> tmp
echo >> tmp
/usr/bin/dpkg -l >> tmp
echo >> tmp
echo $line >> tmp
echo >> tmp
/usr/sbin/service --status-all >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/sudoers >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /root/.bash_history >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /root/.mysql_history >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /root/.viminfo >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/fstab >> tmp 2>/dev/null
echo >> tmp
echo $line >> tmp
echo >> tmp
cat /etc/ppp/chap-secrets >> tmp 2>/dev/null

##############################################################################################################

mv tmp /$user/$hname-$fndate.txt

echo
echo $line
echo
echo "***Scan complete.***"
echo
printf 'The new report is located at \e[1;33m%s\e[0m\n' /$user/$hname-$fndate.txt
echo
echo

