#!/bin/bash

# Idea from post exploitation modules by Carlos Perez
# by Lee Baird

break="=================================================="

cat /etc/apache2/apache2.conf
cat /etc/apache2/ports.conf
cat /etc/ca-certificates.conf
cat /etc/fstab
cat /etc/hosts
cat /etc/ldap/ldap.conf
cat /etc/logrotate.conf
cat /etc/mysql/debian.cnf
cat /etc/mysql/my.cnf
cat /etc/passwd
cat /etc/proxychains.conf
cat /etc/rkhunter.conf
cat /etc/resolv.conf
cat /etc/rpc
cat /etc/samba/smb.conf
cat /etc/security/access.conf
cat /etc/security/sepermit.conf
cat /etc/shadow
cat /etc/shells
cat /etc/snort/snort.conf
cat /etc/ssh/sshd_config
cat /etc/sudoers
cat /etc/sysctl.conf
cat /etc/ufw/sysctl.conf
cat /etc/ufw/ufw.conf
cat /root/.bash_history

/usr/bin/whoami
/sbin/ifconfig -a
/sbin/iwconfig
/sbin/route -e
/sbin/iptables -L
/sbin/iptables -L -t mangle
/sbin/iptables -L -t nat
/usr/bin/lsof -nPi
/bin/netstat -antpul
ls -R /etc/network

/bin/mount -l
/bin/df -ahT
dpkg -l

/usr/bin/service --status-all
crontab -l

/bin/mount -l
/usr/bin/last && /usr/bin/lastlog
