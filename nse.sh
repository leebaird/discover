#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

echo
echo "$MEDIUM"
echo
echo -e "${BLUE}Running Nmap scripts.${NC}"

# If the file for the corresponding port doesn't exist, skip
if [ -f "$NAME"/13.txt ]; then
    echo "    Daytime"
    nmap --randomize-hosts --randomize-hosts -iL "$NAME"/13.txt -Pn -n --open -p13 -sT --script-timeout 20s --script=daytime --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-13.txt
fi

if [ -f "$NAME"/21.txt ]; then
    echo "    FTP"
    nmap --randomize-hosts -iL "$NAME"/21.txt -Pn -n --open -p21 -sT --script-timeout 20s --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-21.txt
fi

if [ -f "$NAME"/22.txt ]; then
    echo "    SSH"
    nmap --randomize-hosts -iL "$NAME"/22.txt -Pn -n --open -p22 -sT -script-timeout 20s --script=rsa-vuln-roca,sshv1,ssh2-enum-algos --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-22.txt
fi

if [ -f "$NAME"/23.txt ]; then
    echo "    Telnet"
    nmap --randomize-hosts -iL "$NAME"/23.txt -Pn -n --open -p23 -sT --script-timeout 20s --script=banner,cics-info,cics-enum,cics-user-enum,telnet-encryption,telnet-ntlm-info,tn3270-screen,tso-enum --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-23.txt
fi

if [ -f "$NAME"/smtp.txt ]; then
    echo "    SMTP"
    nmap --randomize-hosts -iL "$NAME"/smtp.txt -Pn -n --open -p25,465,587 -sT --script-timeout 20s --script=banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-enum-users,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-smtp.txt
fi

if [ -f "$NAME"/37.txt ]; then
    echo "    Time"
    nmap --randomize-hosts -iL "$NAME"/37.txt -Pn -n --open -p37 -sT --script-timeout 20s --script=rfc868-time --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-37.txt
fi

if [ -f "$NAME"/53.txt ]; then
    echo "    DNS"
    nmap --randomize-hosts -iL "$NAME"/53.txt -Pn -n --open -p53 -sU --script-timeout 20s --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-53.txt
fi

if [ -f "$NAME"/67.txt ]; then
    echo "    DHCP"
    nmap --randomize-hosts -iL "$NAME"/67.txt -Pn -n --open -p67 -sU --script-timeout 20s --script=dhcp-discover --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-67.txt
fi

if [ -f "$NAME"/70.txt ]; then
    echo "    Gopher"
    nmap --randomize-hosts -iL "$NAME"/70.txt -Pn -n --open -p70 -sT --script-timeout 20s --script=gopher-ls --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-70.txt
fi

if [ -f "$NAME"/79.txt ]; then
    echo "    Finger"
    nmap --randomize-hosts -iL "$NAME"/79.txt -Pn -n --open -p79 -sT --script-timeout 20s --script=finger --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-79.txt
fi

if [ -f "$NAME"/102.txt ]; then
    echo "    S7"
    nmap --randomize-hosts -iL "$NAME"/102.txt -Pn -n --open -p102 -sT --script-timeout 20s --script=s7-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-102.txt
fi

if [ -f "$NAME"/110.txt ]; then
    echo "    POP3"
    nmap --randomize-hosts -iL "$NAME"/110.txt -Pn -n --open -p110 -sT --script-timeout 20s --script=banner,pop3-capabilities,pop3-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-110.txt
fi

if [ -f "$NAME"/111.txt ]; then
    echo "    RPC"
    nmap --randomize-hosts -iL "$NAME"/111.txt -Pn -n --open -p111 -sT --script-timeout 20s --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-111.txt
fi

if [ -f "$NAME"/nntp.txt ]; then
    echo "    NNTP"
    nmap --randomize-hosts -iL "$NAME"/nntp.txt -Pn -n --open -p119,433,563 -sT --script-timeout 20s --script=nntp-ntlm-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-nntp.txt
fi

if [ -f "$NAME"/123.txt ]; then
    echo "    NTP"
    nmap --randomize-hosts -iL "$NAME"/123.txt -Pn -n --open -p123 -sU --script-timeout 20s --script=ntp-info,ntp-monlist --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-123.txt
fi

if [ -f "$NAME"/137.txt ]; then
    echo "    NetBIOS"
    nmap --randomize-hosts -iL "$NAME"/137.txt -Pn -n --open -p137 -sU --script-timeout 20s --script=nbstat --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    sed -i '/^MAC/{n; /.*/d}' tmp4        # Find lines that start with MAC, and delete the following line
    sed -i '/^137\/udp/{n; /.*/d}' tmp4    # Find lines that start with 137/udp, and delete the following line
    mv tmp4 "$NAME"/script-137.txt
fi

if [ -f "$NAME"/139.txt ]; then
    echo "    SMB Vulns"
    nmap --randomize-hosts -iL "$NAME"/139.txt -Pn -n --open -p139 -sT --script-timeout 20s --script=smb-vuln-cve-2017-7494,smb-vuln-ms10-061,smb-vuln-ms17-010 --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-smbvulns.txt
fi

if [ -f "$NAME"/143.txt ]; then
    echo "    IMAP"
    nmap --randomize-hosts -iL "$NAME"/143.txt -Pn -n --open -p143 -sT --script-timeout 20s --script=imap-capabilities,imap-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-143.txt
fi

if [ -f "$NAME"/161.txt ]; then
    echo "    SNMP"
    nmap --randomize-hosts -iL "$NAME"/161.txt -Pn -n --open -p161 -sU --script-timeout 20s --script=snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-161.txt
fi

if [ -f "$NAME"/389.txt ]; then
    echo "    LDAP"
    nmap --randomize-hosts -iL "$NAME"/389.txt -Pn -n --open -p389 -sT --script-timeout 20s --script=ldap-rootdse,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-389.txt
fi

if [ -f "$NAME"/443.txt ]; then
    echo "    VMware"
    nmap --randomize-hosts -iL "$NAME"/443.txt -Pn -n --open -p443 -sT --script-timeout 20s --script=vmware-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-443.txt
fi

if [ -f "$NAME"/445.txt ]; then
    echo "    SMB"
    nmap --randomize-hosts -iL "$NAME"/445.txt -Pn -n --open -p445 -sT --script-timeout 20s --script=smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-protocols,smb-security-mode,smb-server-stats,smb-system-info,smb2-capabilities,smb2-security-mode,smb2-time,msrpc-enum,stuxnet-detect --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    sed -i '/^445/{n; /.*/d}' tmp4    # Find lines that start with 445, and delete the following line
    mv tmp4 "$NAME"/script-445.txt
fi

if [ -f "$NAME"/500.txt ]; then
    echo "    Ike"
    nmap --randomize-hosts -iL "$NAME"/500.txt -Pn -n --open -p500 -sT -sU --script-timeout 20s --script=ike-version -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-500.txt
fi

if [ -f "$NAME"/db2.txt ]; then
    echo "    DB2"
    nmap --randomize-hosts -iL "$NAME"/db2.txt -Pn -n --open -p523 -sT -sU --script-timeout 20s --script=db2-das-info,db2-discover --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-523.txt
fi

if [ -f "$NAME"/524.txt ]; then
    echo "    Novell NetWare Core Protocol"
    nmap --randomize-hosts -iL "$NAME"/524.txt -Pn -n --open -p524 -sT --script-timeout 20s --script=ncp-enum-users,ncp-serverinfo --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-524.txt
fi

if [ -f "$NAME"/548.txt ]; then
    echo "    AFP"
    nmap --randomize-hosts -iL "$NAME"/548.txt -Pn -n --open -p548 -sT --script-timeout 20s --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-548.txt
fi

if [ -f "$NAME"/554.txt ]; then
    echo "    RTSP"
    nmap --randomize-hosts -iL "$NAME"/554.txt -Pn -n --open -p554 -sT --script-timeout 20s --script=rtsp-methods --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-554.txt
fi

if [ -f "$NAME"/623.txt ]; then
    echo "    IPMI"
    nmap --randomize-hosts -iL "$NAME"/623.txt -Pn -n --open -p623 -sU --script-timeout 20s --script=ipmi-version,ipmi-cipher-zero --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-623.txt
fi

if [ -f "$NAME"/631.txt ]; then
    echo "    CUPS"
    nmap --randomize-hosts -iL "$NAME"/631.txt -Pn -n --open -p631 -sT --script-timeout 20s --script=cups-info,cups-queue-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-631.txt
fi

if [ -f "$NAME"/636.txt ]; then
    echo "    LDAP/S"
    nmap --randomize-hosts -iL "$NAME"/636.txt -Pn -n --open -p636 -sT --script-timeout 20s --script=ldap-rootdse,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-636.txt
fi

if [ -f "$NAME"/873.txt ]; then
    echo "    rsync"
    nmap --randomize-hosts -iL "$NAME"/873.txt -Pn -n --open -p873 -sT --script-timeout 20s --script=rsync-list-modules --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-873.txt
fi

if [ -f "$NAME"/993.txt ]; then
    echo "    IMAP/S"
    nmap --randomize-hosts -iL "$NAME"/993.txt -Pn -n --open -p993 -sT --script-timeout 20s --script=banner,imap-capabilities,imap-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-993.txt
fi

if [ -f "$NAME"/995.txt ]; then
    echo "    POP3/S"
    nmap --randomize-hosts -iL "$NAME"/995.txt -Pn -n --open -p995 -sT --script-timeout 20s --script=banner,pop3-capabilities,pop3-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-995.txt
fi

if [ -f "$NAME"/1050.txt ]; then
    echo "    COBRA"
    nmap --randomize-hosts -iL "$NAME"/1050.txt -Pn -n --open -p1050 -sT --script-timeout 20s --script=giop-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1050.txt
fi

if [ -f "$NAME"/1080.txt ]; then
    echo "    SOCKS"
    nmap --randomize-hosts -iL "$NAME"/1080.txt -Pn -n --open -p1080 -sT --script-timeout 20s --script=socks-auth-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1080.txt
fi

if [ -f "$NAME"/1099.txt ]; then
    echo "    RMI Registry"
    nmap --randomize-hosts -iL "$NAME"/1099.txt -Pn -n --open -p1099 -sT --script-timeout 20s --script=rmi-dumpregistry,rmi-vuln-classloader --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1099.txt
fi

if [ -f "$NAME"/1344.txt ]; then
    echo "    ICAP"
    nmap --randomize-hosts -iL "$NAME"/1344.txt -Pn -n --open -p1344 -sT --script-timeout 20s --script=icap-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1344.txt
fi

if [ -f "$NAME"/1352.txt ]; then
    echo "    Lotus Domino"
    nmap --randomize-hosts -iL "$NAME"/1352.txt -Pn -n --open -p1352 -sT --script-timeout 20s --script=domino-enum-users --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1352.txt
fi

if [ -f "$NAME"/1433.txt ]; then
    echo "    MS-SQL"
    nmap --randomize-hosts -iL "$NAME"/1433.txt -Pn -n --open -p1433 -sT --script-timeout 20s --script=ms-sql-config,ms-sql-dac,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1433.txt
fi

if [ -f "$NAME"/1434.txt ]; then
    echo "    MS-SQL UDP"
    nmap --randomize-hosts -iL "$NAME"/1434.txt -Pn -n --open -p1434 -sU --script-timeout 20s --script=ms-sql-dac --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1434.txt
fi

if [ -f "$NAME"/1521.txt ]; then
    echo "    Oracle"
    nmap --randomize-hosts -iL "$NAME"/1521.txt -Pn -n --open -p1521 -sT --script-timeout 20s --script=oracle-tns-version,oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1521.txt
fi

if [ -f "$NAME"/1604.txt ]; then
    echo "    Citrix"
    nmap --randomize-hosts -iL "$NAME"/1604.txt -Pn -n --open -p1604 -sU --script-timeout 20s --script=citrix-enum-apps,citrix-enum-servers --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1604.txt
fi

if [ -f "$NAME"/1723.txt ]; then
    echo "    PPTP"
    nmap --randomize-hosts -iL "$NAME"/1723.txt -Pn -n --open -p1723 -sT --script-timeout 20s --script=pptp-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1723.txt
fi

if [ -f "$NAME"/1883.txt ]; then
    echo "    MQTT"
    nmap --randomize-hosts -iL "$NAME"/1883.txt -Pn -n --open -p1883 -sT --script-timeout 20s --script=mqtt-subscribe --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1883.txt
fi

if [ -f "$NAME"/1911.txt ]; then
    echo "    Tridium Niagara Fox"
    nmap --randomize-hosts -iL "$NAME"/1911.txt -Pn -n --open -p1911 -sT --script-timeout 20s --script=fox-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1911.txt
fi

if [ -f "$NAME"/1962.txt ]; then
    echo "    PCWorx"
    nmap --randomize-hosts -iL "$NAME"/1962.txt -Pn -n --open -p1962 -sT --script-timeout 20s --script=pcworx-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-1962.txt
fi

if [ -f "$NAME"/2049.txt ]; then
    echo "    NFS"
    nmap --randomize-hosts -iL "$NAME"/2049.txt -Pn -n --open -p2049 -sT --script-timeout 20s --script=nfs-ls,nfs-showmount,nfs-statfs --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-2049.txt
fi

if [ -f "$NAME"/2202.txt ]; then
    echo "    ACARS"
    nmap --randomize-hosts -iL "$NAME"/2202.txt -Pn -n --open -p2202 -sT --script-timeout 20s --script=acarsd-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-2202.txt
fi

if [ -f "$NAME"/2302.txt ]; then
    echo "    Freelancer"
    nmap --randomize-hosts -iL "$NAME"/2302.txt -Pn -n --open -p2302 -sU --script-timeout 20s --script=freelancer-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-2302.txt
fi

if [ -f "$NAME"/2375.txt ]; then
    echo "    Docker"
    nmap --randomize-hosts -iL "$NAME"/2375.txt -Pn -n --open -p2375 -sT --script-timeout 20s --script=docker-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-2375.txt
fi

if [ -f "$NAME"/2628.txt ]; then
    echo "    DICT"
    nmap --randomize-hosts -iL "$NAME"/2628.txt -Pn -n --open -p2628 -sT --script-timeout 20s --script=dict-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-2628.txt
fi

if [ -f "$NAME"/2947.txt ]; then
    echo "    GPS"
    nmap --randomize-hosts -iL "$NAME"/2947.txt -Pn -n --open -p2947 -sT --script-timeout 20s --script=gpsd-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-2947.txt
fi

if [ -f "$NAME"/3031.txt ]; then
    echo "    Apple Remote Event"
    nmap --randomize-hosts -iL "$NAME"/3031.txt -Pn -n --open -p3031 -sT --script-timeout 20s --script=eppc-enum-processes --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-3031.txt
fi

if [ -f "$NAME"/3260.txt ]; then
    echo "    iSCSI"
    nmap --randomize-hosts -iL "$NAME"/3260.txt -Pn -n --open -p3260 -sT --script-timeout 20s --script=iscsi-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-3260.txt
fi

if [ -f "$NAME"/3306.txt ]; then
    echo "    MySQL"
    nmap --randomize-hosts -iL "$NAME"/3306.txt -Pn -n --open -p3306 -sT --script-timeout 20s --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-3306.txt
fi

if [ -f "$NAME"/3310.txt ]; then
    echo "    ClamAV"
    nmap --randomize-hosts -iL "$NAME"/3310.txt -Pn -n --open -p3310 -sT --script-timeout 20s --script=clamav-exec --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-3310.txt
fi

if [ -f "$NAME"/3389.txt ]; then
    echo "    Remote Desktop"
    nmap --randomize-hosts -iL "$NAME"/3389.txt -Pn -n --open -p3389 -sT --script-timeout 20s --script=rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    grep -Eiv '(attackers|description|disclosure|http|references|risk factor)' tmp4 > "$NAME"/script-3389.txt
fi

if [ -f "$NAME"/3478.txt ]; then
    echo "    STUN"
    nmap --randomize-hosts -iL "$NAME"/3478.txt -Pn -n --open -p3478 -sU --script-timeout 20s --script=stun-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-3478.txt
fi

if [ -f "$NAME"/3632.txt ]; then
    echo "    Distributed Compiler Daemon"
    nmap --randomize-hosts -iL "$NAME"/3632.txt -Pn -n --open -p3632 -sT --script-timeout 20s --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    grep -Eiv '(allows|description|disclosure|earlier|extra|http|ids|references|risk factor)' tmp4 > "$NAME"/script-3632.txt
fi

if [ -f "$NAME"/3671.txt ]; then
    echo "    KNX gateway"
    nmap --randomize-hosts -iL "$NAME"/3671.txt -Pn -n --open -p3671 -sU --script-timeout 20s --script=knx-gateway-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-3671.txt
fi

if [ -f "$NAME"/4369.txt ]; then
    echo "    Erlang Port Mapper"
    nmap --randomize-hosts -iL "$NAME"/4369.txt -Pn -n --open -p4369 -sT --script-timeout 20s --script=epmd-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-4369.txt
fi

if [ -f "$NAME"/5019.txt ]; then
    echo "    Versant"
    nmap --randomize-hosts -iL "$NAME"/5019.txt -Pn -n --open -p5019 -sT --script-timeout 20s --script=versant-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5019.txt
fi

if [ -f "$NAME"/5060.txt ]; then
    echo "    SIP"
    nmap --randomize-hosts -iL "$NAME"/5060.txt -Pn -n --open -p5060 -sT --script-timeout 20s --script=sip-enum-users,sip-methods --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5060.txt
fi

if [ -f "$NAME"/5353.txt ]; then
    echo "    DNS Service Discovery"
    nmap --randomize-hosts -iL "$NAME"/5353.txt -Pn -n --open -p5353 -sU --script-timeout 20s --script=dns-service-discovery --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5353.txt
fi

if [ -f "$NAME"/5666.txt ]; then
    echo "    Nagios"
    nmap --randomize-hosts -iL "$NAME"/5666.txt -Pn -n --open -p5666 -sT --script-timeout 20s --script=nrpe-enum --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5666.txt
fi

if [ -f "$NAME"/5672.txt ]; then
    echo "    AMQP"
    nmap --randomize-hosts -iL "$NAME"/5672.txt -Pn -n --open -p5672 -sT --script-timeout 20s --script=amqp-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5672.txt
fi

if [ -f "$NAME"/5683.txt ]; then
    echo "    CoAP"
    nmap --randomize-hosts -iL "$NAME"/5683.txt -Pn -n --open -p5683 -sU --script-timeout 20s --script=coap-resources --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5683.txt
fi

if [ -f "$NAME"/5850.txt ]; then
    echo "    OpenLookup"
    nmap --randomize-hosts -iL "$NAME"/5850.txt -Pn -n --open -p5850 -sT --script-timeout 20s --script=openlookup-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5850.txt
fi

if [ -f "$NAME"/5900.txt ]; then
    echo "    VNC"
    nmap --randomize-hosts -iL "$NAME"/5900.txt -Pn -n --open -p5900 -sT --script-timeout 20s --script=realvnc-auth-bypass,vnc-info,vnc-title --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5900.txt
fi

if [ -f "$NAME"/5984.txt ]; then
    echo "    CouchDB"
    nmap --randomize-hosts -iL "$NAME"/5984.txt -Pn -n --open -p5984 -sT --script-timeout 20s --script=couchdb-databases,couchdb-stats --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-5984.txt
fi

if [ -f "$NAME"/x11.txt ]; then
    echo "    X11"
    nmap --randomize-hosts -iL "$NAME"/x11.txt -Pn -n --open -p6000-6005 -sT --script-timeout 20s --script=x11-access --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-x11.txt
fi

if [ -f "$NAME"/6379.txt ]; then
    echo "    Redis"
    nmap --randomize-hosts -iL "$NAME"/6379.txt -Pn -n --open -p6379 -sT --script-timeout 20s --script=redis-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-6379.txt
fi

if [ -f "$NAME"/6481.txt ]; then
    echo "    Sun Service Tags"
    nmap --randomize-hosts -iL "$NAME"/6481.txt -Pn -n --open -p6481 -sU --script-timeout 20s --script=servicetags --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-6481.txt
fi

if [ -f "$NAME"/6666.txt ]; then
    echo "    Voldemort"
    nmap --randomize-hosts -iL "$NAME"/6666.txt -Pn -n --open -p6666 -sT --script-timeout 20s --script=voldemort-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-6666.txt
fi

if [ -f "$NAME"/7210.txt ]; then
    echo "    Max DB"
    nmap --randomize-hosts -iL "$NAME"/7210.txt -Pn -n --open -p7210 -sT --script-timeout 20s --script=maxdb-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-7210.txt
fi

if [ -f "$NAME"/7634.txt ]; then
    echo "    Hard Disk Info"
    nmap --randomize-hosts -iL "$NAME"/7634.txt -Pn -n --open -p7634 -sT --script-timeout 20s --script=hddtemp-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-7634.txt
fi

if [ -f "$NAME"/8000.txt ]; then
    echo "    QNX QCONN"
    nmap --randomize-hosts -iL "$NAME"/8000.txt -Pn -n --open -p8000 -sT --script-timeout 20s --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-8000.txt
fi

if [ -f "$NAME"/8009.txt ]; then
    echo "    AJP"
    nmap --randomize-hosts -iL "$NAME"/8009.txt -Pn -n --open -p8009 -sT --script-timeout 20s --script=ajp-methods,ajp-request --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-8009.txt
fi

if [ -f "$NAME"/8081.txt ]; then
    echo "    McAfee ePO"
    nmap --randomize-hosts -iL "$NAME"/8081.txt -Pn -n --open -p8081 -sT --script-timeout 20s --script=mcafee-epo-agent --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-8081.txt
fi

if [ -f "$NAME"/8091.txt ]; then
    echo "    CouchBase Web Administration"
    nmap --randomize-hosts -iL "$NAME"/8091.txt -Pn -n --open -p8091 -sT --script-timeout 20s --script=membase-http-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-8091.txt
fi

if [ -f "$NAME"/8140.txt ]; then
    echo "    Puppet"
    nmap --randomize-hosts -iL "$NAME"/8140.txt -Pn -n --open -p8140 -sT --script-timeout 20s --script=puppet-naivesigning --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-8140.txt
fi

if [ -f "$NAME"/bitcoin.txt ]; then
    echo "    Bitcoin"
    nmap --randomize-hosts -iL "$NAME"/bitcoin.txt -Pn -n --open -p8332,8333 -sT --script-timeout 20s --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-bitcoin.txt
fi

if [ -f "$NAME"/9100.txt ]; then
    echo "    Lexmark"
    nmap --randomize-hosts -iL "$NAME"/9100.txt -Pn -n --open -p9100 -sT --script-timeout 20s --script=lexmark-config --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-9100.txt
fi

if [ -f "$NAME"/9160.txt ]; then
    echo "    Cassandra"
    nmap --randomize-hosts -iL "$NAME"/9160.txt -Pn -n --open -p9160 -sT --script-timeout 20s --script=cassandra-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-9160.txt
fi

if [ -f "$NAME"/9600.txt ]; then
    echo "    FINS"
    nmap --randomize-hosts -iL "$NAME"/9600.txt -Pn -n --open -p9600 -sT --script-timeout 20s --script=omron-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-9600.txt
fi

if [ -f "$NAME"/9999.txt ]; then
    echo "    Java Debug Wire Protocol"
    nmap --randomize-hosts -iL "$NAME"/9999.txt -Pn -n --open -p9999 -sT --script-timeout 20s --script=jdwp-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-9999.txt
fi

if [ -f "$NAME"/10000.txt ]; then
    echo "    Network Data Management"
    nmap --randomize-hosts -iL "$NAME"/10000.txt -Pn -n --open -p10000 -sT --script-timeout 20s --script=ndmp-fs-info,ndmp-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-10000.txt
fi


if [ -f "$NAME"/10809.txt ]; then
    echo "    Memory Object Caching"
    nmap --randomize-hosts -iL "$NAME"/10809.txt -Pn -n --open -p10809 -sT --script-timeout 20s --script=nbd-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-10809.txt
fi


if [ -f "$NAME"/11211.txt ]; then
    echo "    Memory Object Caching"
    nmap --randomize-hosts -iL "$NAME"/11211.txt -Pn -n --open -p11211 -sT --script-timeout 20s --script=memcached-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-11211.txt
fi

if [ -f "$NAME"/12000.txt ]; then
    echo "    CCcam"
    nmap --randomize-hosts -iL "$NAME"/12000.txt -Pn -n --open -p12000 -sT --script-timeout 20s --script=cccam-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-12000.txt
fi

if [ -f "$NAME"/12345.txt ]; then
    echo "    NetBus"
    nmap --randomize-hosts -iL "$NAME"/12345.txt -Pn -n --open -p12345 -sT --script-timeout 20s --script=netbus-auth-bypass,netbus-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-12345.txt
fi

if [ -f "$NAME"/17185.txt ]; then
    echo "    VxWorks"
    nmap --randomize-hosts -iL "$NAME"/17185.txt -Pn -n --open -p17185 -sU --script-timeout 20s --script=wdb-version --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-17185.txt
fi

if [ -f "$NAME"/19150.txt ]; then
    echo "    GKRellM"
    nmap --randomize-hosts -iL "$NAME"/19150.txt -Pn -n --open -p19150 -sT --script-timeout 20s --script=gkrellm-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-19150.txt
fi

if [ -f "$NAME"/27017.txt ]; then
    echo "    MongoDB"
    nmap --randomize-hosts -iL "$NAME"/27017.txt -Pn -n --open -p27017 -sT --script-timeout 20s --script=mongodb-databases,mongodb-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-27017.txt
fi

if [ -f "$NAME"/31337.txt ]; then
    echo "    BackOrifice"
    nmap --randomize-hosts -iL "$NAME"/31337.txt -Pn -n --open -p31337 -sU --script-timeout 20s --script=backorifice-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-31337.txt
fi

if [ -f "$NAME"/35871.txt ]; then
    echo "    Flume"
    nmap --randomize-hosts -iL "$NAME"/35871.txt -Pn -n --open -p35871 -sT --script-timeout 20s --script=flume-master-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-35871.txt
fi

if [ -f "$NAME"/44818.txt ]; then
    echo "    EtherNet/IP"
    nmap --randomize-hosts -iL "$NAME"/44818.txt -Pn -n --open -p44818 -sU --script-timeout 20s --script=enip-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-44818.txt
fi

if [ -f "$NAME"/47808.txt ]; then
    echo "    BACNet"
    nmap --randomize-hosts -iL "$NAME"/47808.txt -Pn -n --open -p47808 -sU --script-timeout 20s --script=bacnet-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-47808.txt
fi

if [ -f "$NAME"/49152.txt ]; then
    echo "    Supermicro"
    nmap --randomize-hosts -iL "$NAME"/49152.txt -Pn -n --open -p49152 -sT --script-timeout 20s --script=supermicro-ipmi-conf --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-49152.txt
fi

if [ -f "$NAME"/50000.txt ]; then
    echo "    DRDA"
    nmap --randomize-hosts -iL "$NAME"/50000.txt -Pn -n --open -p50000 -sT --script-timeout 20s --script=drda-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-50000.txt
fi

if [ -f "$NAME"/hadoop.txt ]; then
    echo "    Hadoop"
    nmap --randomize-hosts -iL "$NAME"/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 -sT --script-timeout 20s --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-hadoop.txt
fi

if [ -f "$NAME"/apache-hbase.txt ]; then
    echo "    Apache HBase"
    nmap --randomize-hosts -iL "$NAME"/apache-hbase.txt -Pn -n --open -p60010,60030 -sT --script-timeout 20s --script=hbase-master-info,hbase-region-info --min-hostgroup 100 --scan-delay "$DELAY" > tmp
    f_cleanup
    mv tmp4 "$NAME"/script-apache-hbase.txt
fi

rm tmp* 2>/dev/null

for x in "$NAME"/./script*; do
    if grep '|' "$x" > /dev/null 2>&1; then
        echo > /dev/null 2>&1
    else
        rm "$x" > /dev/null 2>&1
    fi
done

###############################################################################################################################

# Additional tools

if [ -f "$NAME"/161.txt ] || [ -f "$NAME"/445.txt ] || [ -f "$NAME"/500.txt ]; then
    echo
    echo "$MEDIUM"
    echo
    echo -e "${BLUE}Running additional tools.${NC}"

    if [ -f "$NAME"/161.txt ]; then
        echo "    onesixtyone"
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt -i "$NAME"/161.txt | grep -v 'Scanning' > "$NAME"/script-onesixtyone.txt
    fi

    if [ -f "$NAME"/445.txt ]; then
        echo "    enum4linux"
        while read -r LINE; do
            echo "$LINE" >> "$NAME"/script-enum4linux.txt
            enum4linux -a "$LINE" >> "$NAME"/script-enum4linux.txt 2>/dev/null
            echo >> "$NAME"/script-enum4linux.txt
        done < "$NAME"/445.txt

        echo "    smbclient"
        while read -r LINE; do
            echo "$LINE" >> "$NAME"/script-smbclient.txt
            smbclient -L "$LINE" -N | grep -Eiv '(disabled|failed)' >> "$NAME"/script-smbclient.txt 2>/dev/null
            echo >> "$NAME"/script-smbclient.txt
        done < "$NAME"/445.txt
    fi

    if [ -f "$NAME"/500.txt ]; then
        echo "    ike-scan"
        while read -r LINE; do
                ike-scan -f "$LINE" >> "$NAME"/script-ike-scan.txt
        done < "$NAME"/445.txt
    fi

    rm tmp 2>/dev/null
fi
