#!/bin/bash

name='/root/rescan/'
sourceport='88'
delay='0'
medium='====================================================================================='

f_cleanup(){
sed 's/Nmap scan report for //' tmp > tmp2

# Remove lines that start with |, and have various numbers of trailing spaces.
sed -i '/^| *$/d' tmp2

egrep -v '(0 of 100|afp-serverinfo:|ACCESS_DENIED|appears to be clean|cannot|closed|close|Compressors|Could not|Couldn|Denied|denied|Did not|DISABLED|dns-nsid:|dns-service-discovery:|Document Moved|doesn|eppc-enum-processes|error|Error|ERROR|Failed to get|failed|filtered|GET|hbase-region-info:|HEAD|Host is up|Host script results|impervious|incorrect|latency|ldap-rootdse:|LDAP Results|Likely CLEAN|MAC Address|Mac OS X security type|nbstat:|No accounts left|No Allow|no banner|none|Nope.|not allowed|Not Found|Not Shown|not supported|NOT VULNERABLE|nrpe-enum:|ntp-info:|rdp-enum-encryption:|remaining|rpcinfo:|seconds|Security types|See http|Server not returning|Service Info|Skipping|smb-check-vulns|smb-mbenum:|sorry|Starting|telnet-encryption:|Telnet server does not|TIMEOUT|Unauthorized|uncompressed|unhandled|Unknown|viewed over a secure|vnc-info:|wdb-version:)' tmp2 | grep -v "Can't" > tmp3

mv tmp3 tmp4
}

##############################################################################################################


echo
echo $medium
echo
echo -e "\e[1;34mRunning nmap scripts.\e[0m"

# If the file for the corresponding port doesn't exist, skip
if [ -e $name/13.txt ]; then
	echo "     Daytime"
	nmap -iL $name/13.txt -Pn -n --open -p13 --script=daytime --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-13.txt
fi

if [ -e $name/21.txt ]; then
	echo "     FTP"
	nmap -iL $name/21.txt -Pn -n --open -p21 --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-vsftpd-backdoor --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-21.txt
fi

if [ -e $name/22.txt ]; then
	echo "     SSH"
	nmap -iL $name/22.txt -Pn -n --open -p22 --script=sshv1,ssh2-enum-algos --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-22.txt
fi

if [ -e $name/23.txt ]; then
	echo "     Telnet"
	nmap -iL $name/23.txt -Pn -n --open -p23 --script=banner,telnet-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-23.txt
fi

if [ -e $name/smtp.txt ]; then
	echo "     SMTP"
	nmap -iL $name/smtp.txt -Pn -n --open -p25,465,587 --script=banner,smtp-commands,smtp-open-relay,smtp-strangeport,smtp-enum-users --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	printf '%s\n' 'g/NOT VULNERABLE/d\' '-d' w | ed -s tmp4
	mv tmp4 $name/script-25.txt
fi

if [ -e $name/37.txt ]; then
	echo "     Time"
	nmap -iL $name/37.txt -Pn -n --open -p37 --script=rfc868-time --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-37.txt
fi

if [ -e $name/53.txt ]; then
	echo "     DNS"
	nmap -iL $name/53.txt -Pn -n -sU --open -p53 --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-53.txt
fi

if [ -e $name/67.txt ]; then
	echo "     DHCP"
	nmap -iL $name/67.txt -Pn -n -sU --open -p67 --script=dhcp-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-67.txt
fi

if [ -e $name/70.txt ]; then
	echo "     Gopher"
	nmap -iL $name/70.txt -Pn -n --open -p70 --script=gopher-ls --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-70.txt
fi

if [ -e $name/79.txt ]; then
	echo "     Finger"
	nmap -iL $name/79.txt -Pn -n --open -p79 --script=finger --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-79.txt
fi

if [ -e $name/110.txt ]; then
	echo "     POP3"
	nmap -iL $name/110.txt -Pn -n --open -p110 --script=banner,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-110.txt
fi

if [ -e $name/111.txt ]; then
	echo "     NFS"
	nmap -iL $name/111.txt -Pn -n --open -p111 --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-111.txt
fi

if [ -e $name/123.txt ]; then
	echo "     NTP"
	nmap -iL $name/123.txt -Pn -n -sU --open -p123 --script=ntp-monlist --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-123.txt
fi

if [ -e $name/137.txt ]; then
	echo "     NetBIOS"
	nmap -iL $name/137.txt -Pn -n -sU --open -p137 --script=nbstat --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	sed -i '/^MAC/{n; /.*/d}' tmp4		# Find lines that start with MAC, and delete the following line
	sed -i '/^137\/udp/{n; /.*/d}' tmp4	# Find lines that start with 137/udp, and delete the following line
	mv tmp4 $name/script-137.txt
fi

if [ -e $name/139.txt ]; then
     echo "     MS08-067"
     nmap -iL $name/139.txt -Pn -n --open -p139 --script=smb-check-vulns --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
     f_cleanup
     egrep -v '(SERVICE|netbios)' tmp4 > tmp5
     sed '1N;N;/\(.*\n\)\{2\}.*VULNERABLE/P;$d;D' tmp5
     sed '/^$/d' tmp5 > tmp6
     grep -v '|' tmp6 > $name/script-ms08-067.txt
fi

if [ -e $name/143.txt ]; then
	echo "     IMAP"
	nmap -iL $name/143.txt -Pn -n --open -p143 --script=imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-143.txt
fi

if [ -e $name/161.txt ]; then
	echo "     SNMP"
	nmap -iL $name/161.txt -Pn -n -sU --open -p161 --script=snmp-hh3c-logins,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-161.txt
fi

if [ -e $name/389.txt ]; then
	echo "     LDAP"
	nmap -iL $name/389.txt -Pn -n --open -p389 --script=ldap-rootdse --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-389.txt
fi

if [ -e $name/445.txt ]; then
	echo "     SMB"
	nmap -iL $name/445.txt -Pn -n --open -p445 --script=msrpc-enum,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-security-mode,smb-server-stats,smb-system-info,smbv2-enabled,stuxnet-detect --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	sed -i '/^445/{n; /.*/d}' tmp4		# Find lines that start with 445, and delete the following line
	mv tmp4 $name/script-445.txt
fi

if [ -e $name/500.txt ]; then
	echo "     Ike"
	nmap -iL $name/500.txt -Pn -n -sS -sU --open -p500 --script=ike-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-500.txt
fi

if [ -e $name/db2.txt ]; then
	echo "     DB2"
	nmap -iL $name/db2.txt -Pn -n -sS -sU --open -p523 --script=db2-das-info,db2-discover --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-523.txt
fi

if [ -e $name/524.txt ]; then
	echo "     Novell NetWare Core Protocol"
	nmap -iL $name/524.txt -Pn -n --open -p524 --script=ncp-enum-users,ncp-serverinfo --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-524.txt
fi

if [ -e $name/548.txt ]; then
	echo "     AFP"
	nmap -iL $name/548.txt -Pn -n --open -p548 --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-548.txt
fi

if [ -e $name/554.txt ]; then
	echo "     RTSP"
	nmap -iL $name/554.txt -Pn -n --open -p554 --script=rtsp-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-554.txt
fi

if [ -e $name/631.txt ]; then
	echo "     CUPS"
	nmap -iL $name/631.txt -Pn -n --open -p631 --script=cups-info,cups-queue-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-631.txt
fi

if [ -e $name/873.txt ]; then
	echo "     rsync"
	nmap -iL $name/873.txt -Pn -n --open -p873 --script=rsync-list-modules --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-873.txt
fi

if [ -e $name/993.txt ]; then
	echo "     IMAP/S"
	nmap -iL $name/993.txt -Pn -n --open -p993 --script=banner,sslv2,imap-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-993.txt
fi

if [ -e $name/995.txt ]; then
	echo "     POP3/S"
	nmap -iL $name/995.txt -Pn -n --open -p995 --script=banner,sslv2,pop3-capabilities --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-995.txt
fi

if [ -e $name/1050.txt ]; then
	echo "     COBRA"
	nmap -iL $name/1050.txt -Pn -n --open -p1050 --script=giop-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1050.txt
fi

if [ -e $name/1080.txt ]; then
	echo "     SOCKS"
	nmap -iL $name/1080.txt -Pn -n --open -p1080 --script=socks-auth-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1080.txt
fi

if [ -e $name/1099.txt ]; then
	echo "     RMI Registry"
	nmap -iL $name/1099.txt -Pn -n --open -p1099 --script=rmi-dumpregistry --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1099.txt
fi

if [ -e $name/1344.txt ]; then
	echo "     ICAP"
	nmap -iL $name/1344.txt -Pn -n --open -p1344 --script=icap-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1344.txt
fi

if [ -e $name/1352.txt ]; then
	echo "     Lotus Domino"
	nmap -iL $name/1352.txt -Pn -n --open -p1352 --script=domino-enum-users --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1352.txt
fi

if [ -e $name/1433.txt ]; then
	echo "     MS-SQL"
	nmap -iL $name/1433.txt -Pn -n --open -p1433 --script=ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1433.txt
fi

if [ -e $name/1434.txt ]; then
	echo "     MS-SQL UDP"
	nmap -iL $name/1434.txt -Pn -n -sU --open -p1434 --script=ms-sql-dac --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1434.txt
fi

if [ -e $name/1521.txt ]; then
	echo "     Oracle"
	nmap -iL $name/1521.txt -Pn -n --open -p1521 --script=oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1521.txt
fi

if [ -e $name/1604.txt ]; then
	echo "     Citrix"
	nmap -iL $name/1604.txt -Pn -n -sU --open -p1604 --script=citrix-enum-apps,citrix-enum-servers --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1604.txt
fi

if [ -e $name/1723.txt ]; then
	echo "     PPTP"
	nmap -iL $name/1723.txt -Pn -n --open -p1723 --script=pptp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-1723.txt
fi

if [ -e $name/2202.txt ]; then
	echo "     ACARS"
	nmap -iL $name/2202.txt -Pn -n --open -p2202 --script=acarsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2202.txt
fi

if [ -e $name/2302.txt ]; then
	echo "     Freelancer"
	nmap -iL $name/2302.txt -Pn -n -sU --open -p2302 --script=freelancer-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2302.txt
fi

if [ -e $name/2628.txt ]; then
	echo "     DICT"
	nmap -iL $name/2628.txt -Pn -n --open -p2628 --script=dict-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2628.txt
fi

if [ -e $name/2947.txt ]; then
	echo "     GPS"
	nmap -iL $name/2947.txt -Pn -n --open -p2947 --script=gpsd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-2947.txt
fi

if [ -e $name/3031.txt ]; then
	echo "     Apple Remote Event"
	nmap -iL $name/3031.txt -Pn -n --open -p3031 --script=eppc-enum-processes --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3031.txt
fi

if [ -e $name/3260.txt ]; then
	echo "     iSCSI"
	nmap -iL $name/3260.txt -Pn -n --open -p3260 --script=iscsi-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3260.txt
fi

if [ -e $name/3306.txt ]; then
	echo "     MySQL"
	nmap -iL $name/3306.txt -Pn -n --open -p3306 --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3306.txt
fi

if [ -e $name/3389.txt ]; then
	echo "     Remote Desktop"
	nmap -iL $name/3389.txt -Pn -n --open -p3389 --script=rdp-vuln-ms12-020,rdp-enum-encryption --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	egrep -v '(attackers|Description|Disclosure|http|References|Risk factor)' tmp4 > $name/script-3389.txt
fi

if [ -e $name/3478.txt ]; then
	echo "     STUN"
	nmap -iL $name/3478.txt -Pn -n -sU --open -p3478 --script=stun-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-3478.txt
fi

if [ -e $name/3632.txt ]; then
	echo "     Distributed Compiler Daemon"
	nmap -iL $name/3632.txt -Pn -n --open -p3632 --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
     egrep -v '(IDs|Risk factor|Description|Allows|earlier|Disclosure|Extra|References|http)' tmp4 > $name/script-3632.txt
fi

if [ -e $name/4369.txt ]; then
	echo "     Erlang Port Mapper"
	nmap -iL $name/4369.txt -Pn -n --open -p4369 --script=epmd-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-4369.txt
fi

if [ -e $name/5019.txt ]; then
	echo "     Versant"
	nmap -iL $name/5019.txt -Pn -n --open -p5019 --script=versant-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5019.txt
fi

if [ -e $name/5060.txt ]; then
	echo "     SIP"
	nmap -iL $name/5060.txt -Pn -n --open -p5060 --script=sip-enum-users,sip-methods --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5060.txt
fi

if [ -e $name/5353.txt ]; then
	echo "     DNS Service Discovery"
	nmap -iL $name/5353.txt -Pn -n -sU --open -p5353 --script=dns-service-discovery --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5353.txt
fi

if [ -e $name/5666.txt ]; then
	echo "     Nagios"
	nmap -iL $name/5666.txt -Pn -n --open -p5666 --script=nrpe-enum --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5666.txt
fi

if [ -e $name/5672.txt ]; then
	echo "     AMQP"
	nmap -iL $name/5672.txt -Pn -n --open -p5672 --script=amqp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5672.txt
fi

if [ -e $name/5850.txt ]; then
	echo "     OpenLookup"
	nmap -iL $name/5850.txt -Pn -n --open -p5850 --script=openlookup-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5850.txt
fi

if [ -e $name/5900.txt ]; then
	echo "     VNC"
	nmap -iL $name/5900.txt -Pn -n --open -p5900 --script=realvnc-auth-bypass,vnc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5900.txt
fi

if [ -e $name/5984.txt ]; then
	echo "     CouchDB"
	nmap -iL $name/5984.txt -Pn -n --open -p5984 --script=couchdb-databases,couchdb-stats --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-5984.txt
fi

if [ -e $name/x11.txt ]; then
	echo "     X11"
	nmap -iL $name/x11.txt -Pn -n --open -p6000-6005 --script=x11-access --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-x11.txt
fi

if [ -e $name/6379.txt ]; then
	echo "     Redis"
	nmap -iL $name/6379.txt -Pn -n --open -p6379 --script=redis-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-6379.txt
fi

if [ -e $name/6481.txt ]; then
	echo "     Sun Service Tags"
	nmap -iL $name/6481.txt -Pn -n -sU --open -p6481 --script=servicetags --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-6481.txt
fi

if [ -e $name/6666.txt ]; then
	echo "     Voldemort"
	nmap -iL $name/6666.txt -Pn -n --open -p6666 --script=voldemort-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-6666.txt
fi

if [ -e $name/7210.txt ]; then
	echo "     Max DB"
	nmap -iL $name/7210.txt -Pn -n --open -p7210 --script=maxdb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-7210.txt
fi

if [ -e $name/7634.txt ]; then
	echo "     Hard Disk Info"
	nmap -iL $name/7634.txt -Pn -n --open -p7634 --script=hddtemp-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-7634.txt
fi

if [ -e $name/8000.txt ]; then
        echo "     QNX QCONN"
        nmap -iL $name/8000.txt -Pn -n --open -p8000 --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
        f_cleanup
        mv tmp4 $name/script-8000.txt
fi

if [ -e $name/8009.txt ]; then
        echo "     AJP"
        nmap -iL $name/8009.txt -Pn -n --open -p8009 --script=ajp-methods,ajp-request --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
        f_cleanup
        mv tmp4 $name/script-8009.txt
fi

if [ -e $name/8081.txt ]; then
	echo "     McAfee ePO"
	nmap -iL $name/8081.txt -Pn -n --open -p8081 --script=mcafee-epo-agent --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-8081.txt
fi

if [ -e $name/8091.txt ]; then
	echo "     CouchBase Web Administration"
	nmap -iL $name/8091.txt -Pn -n --open -p8091 --script=membase-http-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-8091.txt
fi

if [ -e $name/bitcoin.txt ]; then
	echo "     Bitcoin"
	nmap -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-bitcoin.txt
fi

if [ -e $name/9100.txt ]; then
	echo "     Lexmark"
	nmap -iL $name/9100.txt -Pn -n --open -p9100 --script=lexmark-config --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-9100.txt
fi

if [ -e $name/9160.txt ]; then
	echo "     Cassandra"
	nmap -iL $name/9160.txt -Pn -n --open -p9160 --script=cassandra-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-9160.txt
fi

if [ -e $name/9999.txt ]; then
	echo "     Java Debug Wire Protocol"
	nmap -iL $name/9999.txt -Pn -n --open -p9999 --script=jdwp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-9999.txt
fi

if [ -e $name/10000.txt ]; then
	echo "     Network Data Management"
	nmap -iL $name/10000.txt -Pn -n --open -p10000 --script=ndmp-fs-info,ndmp-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-10000.txt
fi

if [ -e $name/11211.txt ]; then
	echo "     Memory Object Caching"
	nmap -iL $name/11211.txt -Pn -n --open -p11211 --script=memcached-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-11211.txt
fi

if [ -e $name/12000.txt ]; then
	echo "     CCcam"
	nmap -iL $name/12000.txt -Pn -n --open -p12000 --script=cccam-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-12000.txt
fi

if [ -e $name/12345.txt ]; then
	echo "     NetBus"
	nmap -iL $name/12345.txt -Pn -n --open -p12345 --script=netbus-auth-bypass,netbus-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-12345.txt
fi

if [ -e $name/17185.txt ]; then
	echo "     VxWorks"
	nmap -iL $name/17185.txt -Pn -n -sU --open -p17185 --script=wdb-version --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-17185.txt
fi

if [ -e $name/19150.txt ]; then
	echo "     GKRellM"
	nmap -iL $name/19150.txt -Pn -n --open -p19150 --script=gkrellm-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-19150.txt
fi

if [ -e $name/27017.txt ]; then
	echo "     MongoDB"
	nmap -iL $name/27017.txt -Pn -n --open -p27017 --script=mongodb-databases,mongodb-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-27017.txt
fi

if [ -e $name/31337.txt ]; then
	echo "     BackOrifice"
	nmap -iL $name/31337.txt -Pn -n -sU --open -p31337 --script=backorifice-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-31337.txt
fi

if [ -e $name/35871.txt ]; then
	echo "     Flume"
	nmap -iL $name/35871.txt -Pn -n --open -p35871 --script=flume-master-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-35871.txt
fi

if [ -e $name/50000.txt ]; then
	echo "     DRDA"
	nmap -iL $name/50000.txt -Pn -n --open -p50000 --script=drda-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-50000.txt
fi

if [ -e $name/hadoop.txt ]; then
	echo "     Hadoop"
	nmap -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-hadoop.txt
fi

if [ -e $name/apache-hbase.txt ]; then
	echo "     Apache HBase"
	nmap -iL $name/apache-hbase.txt -Pn -n --open -p60010,60030 --script=hbase-master-info,hbase-region-info --host-timeout 5m --min-hostgroup 100 -g $sourceport --scan-delay $delay > tmp
	f_cleanup
	mv tmp4 $name/script-apache-hbase.txt
fi

rm tmp*

for x in $name/./script*; do
     if grep '|' $x > /dev/null 2>&1; then
          echo > /dev/null 2>&1
     else
          rm $x > /dev/null 2>&1
     fi
done

