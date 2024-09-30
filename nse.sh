#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

echo
echo $medium
echo
echo -e "${BLUE}Running Nmap scripts.${NC}"

# If the file for the corresponding port doesn't exist, skip
if [ -f $name/13.txt ]; then
    echo "    Daytime"
    sudo nmap --randomize-hosts --randomize-hosts -iL $name/13.txt -Pn -n --open -p13 -sT --script-timeout 20s --script=daytime --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-13.txt
fi

if [ -f $name/21.txt ]; then
    echo "    FTP"
    sudo nmap --randomize-hosts -iL $name/21.txt -Pn -n --open -p21 -sT --script-timeout 20s --script=banner,ftp-anon,ftp-bounce,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-21.txt
fi

if [ -f $name/22.txt ]; then
    echo "    SSH"
    sudo nmap --randomize-hosts -iL $name/22.txt -Pn -n --open -p22 -sT -script-timeout 20s --script=rsa-vuln-roca,sshv1,ssh2-enum-algos --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-22.txt
fi

if [ -f $name/23.txt ]; then
    echo "    Telnet"
    sudo nmap --randomize-hosts -iL $name/23.txt -Pn -n --open -p23 -sT --script-timeout 20s --script=banner,cics-info,cics-enum,cics-user-enum,telnet-encryption,telnet-ntlm-info,tn3270-screen,tso-enum --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-23.txt
fi

if [ -f $name/smtp.txt ]; then
    echo "    SMTP"
    sudo nmap --randomize-hosts -iL $name/smtp.txt -Pn -n --open -p25,465,587 -sT --script-timeout 20s --script=banner,smtp-commands,smtp-ntlm-info,smtp-open-relay,smtp-strangeport,smtp-enum-users,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --script-args smtp-enum-users.methods={EXPN,RCPT,VRFY} --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-smtp.txt
fi

if [ -f $name/37.txt ]; then
    echo "    Time"
    sudo nmap --randomize-hosts -iL $name/37.txt -Pn -n --open -p37 -sT --script-timeout 20s --script=rfc868-time --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-37.txt
fi

if [ -f $name/53.txt ]; then
    echo "    DNS"
    sudo nmap --randomize-hosts -iL $name/53.txt -Pn -n --open -p53 -sU --script-timeout 20s --script=dns-blacklist,dns-cache-snoop,dns-nsec-enum,dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-service-discovery,dns-update,dns-zeustracker,dns-zone-transfer --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-53.txt
fi

if [ -f $name/67.txt ]; then
    echo "    DHCP"
    sudo nmap --randomize-hosts -iL $name/67.txt -Pn -n --open -p67 -sU --script-timeout 20s --script=dhcp-discover --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-67.txt
fi

if [ -f $name/70.txt ]; then
    echo "    Gopher"
    sudo nmap --randomize-hosts -iL $name/70.txt -Pn -n --open -p70 -sT --script-timeout 20s --script=gopher-ls --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-70.txt
fi

if [ -f $name/79.txt ]; then
    echo "    Finger"
    sudo nmap --randomize-hosts -iL $name/79.txt -Pn -n --open -p79 -sT --script-timeout 20s --script=finger --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-79.txt
fi

if [ -f $name/102.txt ]; then
    echo "    S7"
    sudo nmap --randomize-hosts -iL $name/102.txt -Pn -n --open -p102 -sT --script-timeout 20s --script=s7-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-102.txt
fi

if [ -f $name/110.txt ]; then
    echo "    POP3"
    sudo nmap --randomize-hosts -iL $name/110.txt -Pn -n --open -p110 -sT --script-timeout 20s --script=banner,pop3-capabilities,pop3-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-110.txt
fi

if [ -f $name/111.txt ]; then
    echo "    RPC"
    sudo nmap --randomize-hosts -iL $name/111.txt -Pn -n --open -p111 -sT --script-timeout 20s --script=nfs-ls,nfs-showmount,nfs-statfs,rpcinfo --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-111.txt
fi

if [ -f $name/nntp.txt ]; then
    echo "    NNTP"
    sudo nmap --randomize-hosts -iL $name/nntp.txt -Pn -n --open -p119,433,563 -sT --script-timeout 20s --script=nntp-ntlm-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-nntp.txt
fi

if [ -f $name/123.txt ]; then
    echo "    NTP"
    sudo nmap --randomize-hosts -iL $name/123.txt -Pn -n --open -p123 -sU --script-timeout 20s --script=ntp-info,ntp-monlist --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-123.txt
fi

if [ -f $name/137.txt ]; then
    echo "    NetBIOS"
    sudo nmap --randomize-hosts -iL $name/137.txt -Pn -n --open -p137 -sU --script-timeout 20s --script=nbstat --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    sed -i '/^MAC/{n; /.*/d}' tmp4        # Find lines that start with MAC, and delete the following line
    sed -i '/^137\/udp/{n; /.*/d}' tmp4    # Find lines that start with 137/udp, and delete the following line
    mv tmp4 $name/script-137.txt
fi

if [ -f $name/139.txt ]; then
    echo "    SMB Vulns"
    sudo nmap --randomize-hosts -iL $name/139.txt -Pn -n --open -p139 -sT --script-timeout 20s --script=smb-vuln-cve-2017-7494,smb-vuln-ms10-061,smb-vuln-ms17-010 --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-smbvulns.txt
fi

if [ -f $name/143.txt ]; then
    echo "    IMAP"
    sudo nmap --randomize-hosts -iL $name/143.txt -Pn -n --open -p143 -sT --script-timeout 20s --script=imap-capabilities,imap-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-143.txt
fi

if [ -f $name/161.txt ]; then
    echo "    SNMP"
    sudo nmap --randomize-hosts -iL $name/161.txt -Pn -n --open -p161 -sU --script-timeout 20s --script=snmp-hh3c-logins,snmp-info,snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-161.txt
fi

if [ -f $name/389.txt ]; then
    echo "    LDAP"
    sudo nmap --randomize-hosts -iL $name/389.txt -Pn -n --open -p389 -sT --script-timeout 20s --script=ldap-rootdse,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-389.txt
fi

if [ -f $name/443.txt ]; then
    echo "    VMware"
    sudo nmap --randomize-hosts -iL $name/443.txt -Pn -n --open -p443 -sT --script-timeout 20s --script=vmware-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-443.txt
fi

if [ -f $name/445.txt ]; then
    echo "    SMB"
    sudo nmap --randomize-hosts -iL $name/445.txt -Pn -n --open -p445 -sT --script-timeout 20s --script=smb-double-pulsar-backdoor,smb-enum-domains,smb-enum-groups,smb-enum-processes,smb-enum-services,smb-enum-sessions,smb-enum-shares,smb-enum-users,smb-mbenum,smb-os-discovery,smb-protocols,smb-security-mode,smb-server-stats,smb-system-info,smb2-capabilities,smb2-security-mode,smb2-time,msrpc-enum,stuxnet-detect --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    sed -i '/^445/{n; /.*/d}' tmp4    # Find lines that start with 445, and delete the following line
    mv tmp4 $name/script-445.txt
fi

if [ -f $name/500.txt ]; then
    echo "    Ike"
    sudo nmap --randomize-hosts -iL $name/500.txt -Pn -n --open -p500 -sT -sU --script-timeout 20s --script=ike-version -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-500.txt
fi

if [ -f $name/db2.txt ]; then
    echo "    DB2"
    sudo nmap --randomize-hosts -iL $name/db2.txt -Pn -n --open -p523 -sT -sU --script-timeout 20s --script=db2-das-info,db2-discover --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-523.txt
fi

if [ -f $name/524.txt ]; then
    echo "    Novell NetWare Core Protocol"
    sudo nmap --randomize-hosts -iL $name/524.txt -Pn -n --open -p524 -sT --script-timeout 20s --script=ncp-enum-users,ncp-serverinfo --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-524.txt
fi

if [ -f $name/548.txt ]; then
    echo "    AFP"
    sudo nmap --randomize-hosts -iL $name/548.txt -Pn -n --open -p548 -sT --script-timeout 20s --script=afp-ls,afp-path-vuln,afp-serverinfo,afp-showmount --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-548.txt
fi

if [ -f $name/554.txt ]; then
    echo "    RTSP"
    sudo nmap --randomize-hosts -iL $name/554.txt -Pn -n --open -p554 -sT --script-timeout 20s --script=rtsp-methods --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-554.txt
fi

if [ -f $name/623.txt ]; then
    echo "    IPMI"
    sudo nmap --randomize-hosts -iL $name/623.txt -Pn -n --open -p623 -sU --script-timeout 20s --script=ipmi-version,ipmi-cipher-zero --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-623.txt
fi

if [ -f $name/631.txt ]; then
    echo "    CUPS"
    sudo nmap --randomize-hosts -iL $name/631.txt -Pn -n --open -p631 -sT --script-timeout 20s --script=cups-info,cups-queue-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-631.txt
fi

if [ -f $name/636.txt ]; then
    echo "    LDAP/S"
    sudo nmap --randomize-hosts -iL $name/636.txt -Pn -n --open -p636 -sT --script-timeout 20s --script=ldap-rootdse,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-636.txt
fi

if [ -f $name/873.txt ]; then
    echo "    rsync"
    sudo nmap --randomize-hosts -iL $name/873.txt -Pn -n --open -p873 -sT --script-timeout 20s --script=rsync-list-modules --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-873.txt
fi

if [ -f $name/993.txt ]; then
    echo "    IMAP/S"
    sudo nmap --randomize-hosts -iL $name/993.txt -Pn -n --open -p993 -sT --script-timeout 20s --script=banner,imap-capabilities,imap-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-993.txt
fi

if [ -f $name/995.txt ]; then
    echo "    POP3/S"
    sudo nmap --randomize-hosts -iL $name/995.txt -Pn -n --open -p995 -sT --script-timeout 20s --script=banner,pop3-capabilities,pop3-ntlm-info,ssl-cert,ssl-cert-intaddr,ssl-ccs-injection,ssl-date,ssl-dh-params,ssl-enum-ciphers,ssl-heartbleed,ssl-known-key,ssl-poodle,sslv2,sslv2-drown,tls-nextprotoneg -sV --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-995.txt
fi

if [ -f $name/1050.txt ]; then
    echo "    COBRA"
    sudo nmap --randomize-hosts -iL $name/1050.txt -Pn -n --open -p1050 -sT --script-timeout 20s --script=giop-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1050.txt
fi

if [ -f $name/1080.txt ]; then
    echo "    SOCKS"
    sudo nmap --randomize-hosts -iL $name/1080.txt -Pn -n --open -p1080 -sT --script-timeout 20s --script=socks-auth-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1080.txt
fi

if [ -f $name/1099.txt ]; then
    echo "    RMI Registry"
    sudo nmap --randomize-hosts -iL $name/1099.txt -Pn -n --open -p1099 -sT --script-timeout 20s --script=rmi-dumpregistry,rmi-vuln-classloader --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1099.txt
fi

if [ -f $name/1344.txt ]; then
    echo "    ICAP"
    sudo nmap --randomize-hosts -iL $name/1344.txt -Pn -n --open -p1344 -sT --script-timeout 20s --script=icap-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1344.txt
fi

if [ -f $name/1352.txt ]; then
    echo "    Lotus Domino"
    sudo nmap --randomize-hosts -iL $name/1352.txt -Pn -n --open -p1352 -sT --script-timeout 20s --script=domino-enum-users --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1352.txt
fi

if [ -f $name/1433.txt ]; then
    echo "    MS-SQL"
    sudo nmap --randomize-hosts -iL $name/1433.txt -Pn -n --open -p1433 -sT --script-timeout 20s --script=ms-sql-config,ms-sql-dac,ms-sql-dump-hashes,ms-sql-empty-password,ms-sql-info,ms-sql-ntlm-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1433.txt
fi

if [ -f $name/1434.txt ]; then
    echo "    MS-SQL UDP"
    sudo nmap --randomize-hosts -iL $name/1434.txt -Pn -n --open -p1434 -sU --script-timeout 20s --script=ms-sql-dac --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1434.txt
fi

if [ -f $name/1521.txt ]; then
    echo "    Oracle"
    sudo nmap --randomize-hosts -iL $name/1521.txt -Pn -n --open -p1521 -sT --script-timeout 20s --script=oracle-tns-version,oracle-sid-brute --script oracle-enum-users --script-args oracle-enum-users.sid=ORCL,userdb=orausers.txt --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1521.txt
fi

if [ -f $name/1604.txt ]; then
    echo "    Citrix"
    sudo nmap --randomize-hosts -iL $name/1604.txt -Pn -n --open -p1604 -sU --script-timeout 20s --script=citrix-enum-apps,citrix-enum-servers --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1604.txt
fi

if [ -f $name/1723.txt ]; then
    echo "    PPTP"
    sudo nmap --randomize-hosts -iL $name/1723.txt -Pn -n --open -p1723 -sT --script-timeout 20s --script=pptp-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1723.txt
fi

if [ -f $name/1883.txt ]; then
    echo "    MQTT"
    sudo nmap --randomize-hosts -iL $name/1883.txt -Pn -n --open -p1883 -sT --script-timeout 20s --script=mqtt-subscribe --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1883.txt
fi

if [ -f $name/1911.txt ]; then
    echo "    Tridium Niagara Fox"
    sudo nmap --randomize-hosts -iL $name/1911.txt -Pn -n --open -p1911 -sT --script-timeout 20s --script=fox-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1911.txt
fi

if [ -f $name/1962.txt ]; then
    echo "    PCWorx"
    sudo nmap --randomize-hosts -iL $name/1962.txt -Pn -n --open -p1962 -sT --script-timeout 20s --script=pcworx-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-1962.txt
fi

if [ -f $name/2049.txt ]; then
    echo "    NFS"
    sudo nmap --randomize-hosts -iL $name/2049.txt -Pn -n --open -p2049 -sT --script-timeout 20s --script=nfs-ls,nfs-showmount,nfs-statfs --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-2049.txt
fi

if [ -f $name/2202.txt ]; then
    echo "    ACARS"
    sudo nmap --randomize-hosts -iL $name/2202.txt -Pn -n --open -p2202 -sT --script-timeout 20s --script=acarsd-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-2202.txt
fi

if [ -f $name/2302.txt ]; then
    echo "    Freelancer"
    sudo nmap --randomize-hosts -iL $name/2302.txt -Pn -n --open -p2302 -sU --script-timeout 20s --script=freelancer-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-2302.txt
fi

if [ -f $name/2375.txt ]; then
    echo "    Docker"
    sudo nmap --randomize-hosts -iL $name/2375.txt -Pn -n --open -p2375 -sT --script-timeout 20s --script=docker-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-2375.txt
fi

if [ -f $name/2628.txt ]; then
    echo "    DICT"
    sudo nmap --randomize-hosts -iL $name/2628.txt -Pn -n --open -p2628 -sT --script-timeout 20s --script=dict-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-2628.txt
fi

if [ -f $name/2947.txt ]; then
    echo "    GPS"
    sudo nmap --randomize-hosts -iL $name/2947.txt -Pn -n --open -p2947 -sT --script-timeout 20s --script=gpsd-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-2947.txt
fi

if [ -f $name/3031.txt ]; then
    echo "    Apple Remote Event"
    sudo nmap --randomize-hosts -iL $name/3031.txt -Pn -n --open -p3031 -sT --script-timeout 20s --script=eppc-enum-processes --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-3031.txt
fi

if [ -f $name/3260.txt ]; then
    echo "    iSCSI"
    sudo nmap --randomize-hosts -iL $name/3260.txt -Pn -n --open -p3260 -sT --script-timeout 20s --script=iscsi-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-3260.txt
fi

if [ -f $name/3306.txt ]; then
    echo "    MySQL"
    sudo nmap --randomize-hosts -iL $name/3306.txt -Pn -n --open -p3306 -sT --script-timeout 20s --script=mysql-databases,mysql-empty-password,mysql-info,mysql-users,mysql-variables --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-3306.txt
fi

if [ -f $name/3310.txt ]; then
    echo "    ClamAV"
    sudo nmap --randomize-hosts -iL $name/3310.txt -Pn -n --open -p3310 -sT --script-timeout 20s --script=clamav-exec --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 > $name/script-3310.txt
fi

if [ -f $name/3389.txt ]; then
    echo "    Remote Desktop"
    sudo nmap --randomize-hosts -iL $name/3389.txt -Pn -n --open -p3389 -sT --script-timeout 20s --script=rdp-vuln-ms12-020,rdp-enum-encryption,rdp-ntlm-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    grep -Eiv '(attackers|description|disclosure|http|references|risk factor)' tmp4 > $name/script-3389.txt
fi

if [ -f $name/3478.txt ]; then
    echo "    STUN"
    sudo nmap --randomize-hosts -iL $name/3478.txt -Pn -n --open -p3478 -sU --script-timeout 20s --script=stun-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-3478.txt
fi

if [ -f $name/3632.txt ]; then
    echo "    Distributed Compiler Daemon"
    sudo nmap --randomize-hosts -iL $name/3632.txt -Pn -n --open -p3632 -sT --script-timeout 20s --script=distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    grep -Eiv '(allows|description|disclosure|earlier|extra|http|ids|references|risk factor)' tmp4 > $name/script-3632.txt
fi

if [ -f $name/3671.txt ]; then
    echo "    KNX gateway"
    sudo nmap --randomize-hosts -iL $name/3671.txt -Pn -n --open -p3671 -sU --script-timeout 20s --script=knx-gateway-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-3671.txt
fi

if [ -f $name/4369.txt ]; then
    echo "    Erlang Port Mapper"
    sudo nmap --randomize-hosts -iL $name/4369.txt -Pn -n --open -p4369 -sT --script-timeout 20s --script=epmd-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-4369.txt
fi

if [ -f $name/5019.txt ]; then
    echo "    Versant"
    sudo nmap --randomize-hosts -iL $name/5019.txt -Pn -n --open -p5019 -sT --script-timeout 20s --script=versant-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5019.txt
fi

if [ -f $name/5060.txt ]; then
    echo "    SIP"
    sudo nmap --randomize-hosts -iL $name/5060.txt -Pn -n --open -p5060 -sT --script-timeout 20s --script=sip-enum-users,sip-methods --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5060.txt
fi

if [ -f $name/5353.txt ]; then
    echo "    DNS Service Discovery"
    sudo nmap --randomize-hosts -iL $name/5353.txt -Pn -n --open -p5353 -sU --script-timeout 20s --script=dns-service-discovery --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5353.txt
fi

if [ -f $name/5666.txt ]; then
    echo "    Nagios"
    sudo nmap --randomize-hosts -iL $name/5666.txt -Pn -n --open -p5666 -sT --script-timeout 20s --script=nrpe-enum --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5666.txt
fi

if [ -f $name/5672.txt ]; then
    echo "    AMQP"
    sudo nmap --randomize-hosts -iL $name/5672.txt -Pn -n --open -p5672 -sT --script-timeout 20s --script=amqp-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5672.txt
fi

if [ -f $name/5683.txt ]; then
    echo "    CoAP"
    sudo nmap --randomize-hosts -iL $name/5683.txt -Pn -n --open -p5683 -sU --script-timeout 20s --script=coap-resources --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5683.txt
fi

if [ -f $name/5850.txt ]; then
    echo "    OpenLookup"
    sudo nmap --randomize-hosts -iL $name/5850.txt -Pn -n --open -p5850 -sT --script-timeout 20s --script=openlookup-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5850.txt
fi

if [ -f $name/5900.txt ]; then
    echo "    VNC"
    sudo nmap --randomize-hosts -iL $name/5900.txt -Pn -n --open -p5900 -sT --script-timeout 20s --script=realvnc-auth-bypass,vnc-info,vnc-title --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5900.txt
fi

if [ -f $name/5984.txt ]; then
    echo "    CouchDB"
    sudo nmap --randomize-hosts -iL $name/5984.txt -Pn -n --open -p5984 -sT --script-timeout 20s --script=couchdb-databases,couchdb-stats --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-5984.txt
fi

if [ -f $name/x11.txt ]; then
    echo "    X11"
    sudo nmap --randomize-hosts -iL $name/x11.txt -Pn -n --open -p6000-6005 -sT --script-timeout 20s --script=x11-access --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-x11.txt
fi

if [ -f $name/6379.txt ]; then
    echo "    Redis"
    sudo nmap --randomize-hosts -iL $name/6379.txt -Pn -n --open -p6379 -sT --script-timeout 20s --script=redis-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-6379.txt
fi

if [ -f $name/6481.txt ]; then
    echo "    Sun Service Tags"
    sudo nmap --randomize-hosts -iL $name/6481.txt -Pn -n --open -p6481 -sU --script-timeout 20s --script=servicetags --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-6481.txt
fi

if [ -f $name/6666.txt ]; then
    echo "    Voldemort"
    sudo nmap --randomize-hosts -iL $name/6666.txt -Pn -n --open -p6666 -sT --script-timeout 20s --script=voldemort-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-6666.txt
fi

if [ -f $name/7210.txt ]; then
    echo "    Max DB"
    sudo nmap --randomize-hosts -iL $name/7210.txt -Pn -n --open -p7210 -sT --script-timeout 20s --script=maxdb-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-7210.txt
fi

if [ -f $name/7634.txt ]; then
    echo "    Hard Disk Info"
    sudo nmap --randomize-hosts -iL $name/7634.txt -Pn -n --open -p7634 -sT --script-timeout 20s --script=hddtemp-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-7634.txt
fi

if [ -f $name/8000.txt ]; then
    echo "    QNX QCONN"
    sudo nmap --randomize-hosts -iL $name/8000.txt -Pn -n --open -p8000 -sT --script-timeout 20s --script=qconn-exec --script-args=qconn-exec.timeout=60,qconn-exec.bytes=1024,qconn-exec.cmd="uname -a" --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-8000.txt
fi

if [ -f $name/8009.txt ]; then
    echo "    AJP"
    sudo nmap --randomize-hosts -iL $name/8009.txt -Pn -n --open -p8009 -sT --script-timeout 20s --script=ajp-methods,ajp-request --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-8009.txt
fi

if [ -f $name/8081.txt ]; then
    echo "    McAfee ePO"
    sudo nmap --randomize-hosts -iL $name/8081.txt -Pn -n --open -p8081 -sT --script-timeout 20s --script=mcafee-epo-agent --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-8081.txt
fi

if [ -f $name/8091.txt ]; then
    echo "    CouchBase Web Administration"
    sudo nmap --randomize-hosts -iL $name/8091.txt -Pn -n --open -p8091 -sT --script-timeout 20s --script=membase-http-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-8091.txt
fi

if [ -f $name/8140.txt ]; then
    echo "    Puppet"
    sudo nmap --randomize-hosts -iL $name/8140.txt -Pn -n --open -p8140 -sT --script-timeout 20s --script=puppet-naivesigning --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-8140.txt
fi

if [ -f $name/bitcoin.txt ]; then
    echo "    Bitcoin"
    sudo nmap --randomize-hosts -iL $name/bitcoin.txt -Pn -n --open -p8332,8333 -sT --script-timeout 20s --script=bitcoin-getaddr,bitcoin-info,bitcoinrpc-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-bitcoin.txt
fi

if [ -f $name/9100.txt ]; then
    echo "    Lexmark"
    sudo nmap --randomize-hosts -iL $name/9100.txt -Pn -n --open -p9100 -sT --script-timeout 20s --script=lexmark-config --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-9100.txt
fi

if [ -f $name/9160.txt ]; then
    echo "    Cassandra"
    sudo nmap --randomize-hosts -iL $name/9160.txt -Pn -n --open -p9160 -sT --script-timeout 20s --script=cassandra-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-9160.txt
fi

if [ -f $name/9600.txt ]; then
    echo "    FINS"
    sudo nmap --randomize-hosts -iL $name/9600.txt -Pn -n --open -p9600 -sT --script-timeout 20s --script=omron-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-9600.txt
fi

if [ -f $name/9999.txt ]; then
    echo "    Java Debug Wire Protocol"
    sudo nmap --randomize-hosts -iL $name/9999.txt -Pn -n --open -p9999 -sT --script-timeout 20s --script=jdwp-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-9999.txt
fi

if [ -f $name/10000.txt ]; then
    echo "    Network Data Management"
    sudo nmap --randomize-hosts -iL $name/10000.txt -Pn -n --open -p10000 -sT --script-timeout 20s --script=ndmp-fs-info,ndmp-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-10000.txt
fi


if [ -f $name/10809.txt ]; then
    echo "    Memory Object Caching"
    sudo nmap --randomize-hosts -iL $name/10809.txt -Pn -n --open -p10809 -sT --script-timeout 20s --script=nbd-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-10809.txt
fi


if [ -f $name/11211.txt ]; then
    echo "    Memory Object Caching"
    sudo nmap --randomize-hosts -iL $name/11211.txt -Pn -n --open -p11211 -sT --script-timeout 20s --script=memcached-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-11211.txt
fi

if [ -f $name/12000.txt ]; then
    echo "    CCcam"
    sudo nmap --randomize-hosts -iL $name/12000.txt -Pn -n --open -p12000 -sT --script-timeout 20s --script=cccam-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-12000.txt
fi

if [ -f $name/12345.txt ]; then
    echo "    NetBus"
    sudo nmap --randomize-hosts -iL $name/12345.txt -Pn -n --open -p12345 -sT --script-timeout 20s --script=netbus-auth-bypass,netbus-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-12345.txt
fi

if [ -f $name/17185.txt ]; then
    echo "    VxWorks"
    sudo nmap --randomize-hosts -iL $name/17185.txt -Pn -n --open -p17185 -sU --script-timeout 20s --script=wdb-version --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-17185.txt
fi

if [ -f $name/19150.txt ]; then
    echo "    GKRellM"
    sudo nmap --randomize-hosts -iL $name/19150.txt -Pn -n --open -p19150 -sT --script-timeout 20s --script=gkrellm-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-19150.txt
fi

if [ -f $name/27017.txt ]; then
    echo "    MongoDB"
    sudo nmap --randomize-hosts -iL $name/27017.txt -Pn -n --open -p27017 -sT --script-timeout 20s --script=mongodb-databases,mongodb-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-27017.txt
fi

if [ -f $name/31337.txt ]; then
    echo "    BackOrifice"
    sudo nmap --randomize-hosts -iL $name/31337.txt -Pn -n --open -p31337 -sU --script-timeout 20s --script=backorifice-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-31337.txt
fi

if [ -f $name/35871.txt ]; then
    echo "    Flume"
    sudo nmap --randomize-hosts -iL $name/35871.txt -Pn -n --open -p35871 -sT --script-timeout 20s --script=flume-master-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-35871.txt
fi

if [ -f $name/44818.txt ]; then
    echo "    EtherNet/IP"
    sudo nmap --randomize-hosts -iL $name/44818.txt -Pn -n --open -p44818 -sU --script-timeout 20s --script=enip-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-44818.txt
fi

if [ -f $name/47808.txt ]; then
    echo "    BACNet"
    sudo nmap --randomize-hosts -iL $name/47808.txt -Pn -n --open -p47808 -sU --script-timeout 20s --script=bacnet-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-47808.txt
fi

if [ -f $name/49152.txt ]; then
    echo "    Supermicro"
    sudo nmap --randomize-hosts -iL $name/49152.txt -Pn -n --open -p49152 -sT --script-timeout 20s --script=supermicro-ipmi-conf --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-49152.txt
fi

if [ -f $name/50000.txt ]; then
    echo "    DRDA"
    sudo nmap --randomize-hosts -iL $name/50000.txt -Pn -n --open -p50000 -sT --script-timeout 20s --script=drda-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-50000.txt
fi

if [ -f $name/hadoop.txt ]; then
    echo "    Hadoop"
    sudo nmap --randomize-hosts -iL $name/hadoop.txt -Pn -n --open -p50030,50060,50070,50075,50090 -sT --script-timeout 20s --script=hadoop-datanode-info,hadoop-jobtracker-info,hadoop-namenode-info,hadoop-secondary-namenode-info,hadoop-tasktracker-info --min-hostgroup 100 --scan-delay $delay > tmp
    f_cleanup
    mv tmp4 $name/script-hadoop.txt
fi

if [ -f $name/apache-hbase.txt ]; then
    echo "    Apache HBase"
    sudo nmap --randomize-hosts -iL $name/apache-hbase.txt -Pn -n --open -p60010,60030 -sT --script-timeout 20s --script=hbase-master-info,hbase-region-info --min-hostgroup 100 --scan-delay $delay > tmp
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

###############################################################################################################################

# Additional tools

if [ -f $name/161.txt ] || [ -f $name/445.txt ] || [ -f $name/500.txt ]; then
    echo
    echo $medium
    echo
    echo -e "${BLUE}Running additional tools.${NC}"

    if [ -f $name/161.txt ]; then
        echo "    onesixtyone"
        onesixtyone -c /usr/share/doc/onesixtyone/dict.txt -i $name/161.txt | grep -v 'Scanning' > $name/script-onesixtyone.txt
    fi

    if [ -f $name/445.txt ]; then
        echo "    enum4linux"
        for i in $(cat $name/445.txt); do
            echo $i >> $name/script-enum4linux.txt
            enum4linux -a $i >> $name/script-enum4linux.txt 2>/dev/null
            echo >> $name/script-enum4linux.txt
        done

        echo "    smbclient"
        for i in $(cat $name/445.txt); do
            echo $i >> $name/script-smbclient.txt
            smbclient -L $i -N | grep -Eiv '(disabled|failed)' >> $name/script-smbclient.txt 2>/dev/null
            echo >> $name/script-smbclient.txt
        done
    fi

    if [ -f $name/500.txt ]; then
        echo "    ike-scan"
        for i in $(cat $name/445.txt); do
            ike-scan -f $i >> $name/script-ike-scan.txt
        done
    fi

    rm tmp 2>/dev/null
fi
