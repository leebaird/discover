#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

trap 'rm -rf /tmp/resource/ /tmp/master tmpmsf; sudo systemctl stop postgresql.service' EXIT

echo
echo "$MEDIUM"
echo
echo -e "${BLUE}Starting Postgres.${NC}"
sudo systemctl start postgresql.service

echo
echo -e "${BLUE}Starting Metasploit.${NC}"
echo
echo -e "${BLUE}Using the following resource files.${NC}"
cp -R "$DISCOVER"/resource/ /tmp/

echo workspace -a "$NAME" > /tmp/master
echo spool tmpmsf > /tmp/master

###############################################################################################################################

if [ -f "$NAME"/19.txt ]; then
    echo "    Chargen Probe Utility"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/19.txt|g" /tmp/resource/19-chargen.rc
    cat /tmp/resource/19-chargen.rc >> /tmp/master
fi

if [ -f "$NAME"/21.txt ]; then
    echo "    FTP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/21.txt|g" /tmp/resource/21-ftp.rc
    cat /tmp/resource/21-ftp.rc >> /tmp/master
fi

if [ -f "$NAME"/22.txt ]; then
    echo "    SSH"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/22.txt|g" /tmp/resource/22-ssh.rc
    cat /tmp/resource/22-ssh.rc >> /tmp/master
fi

if [ -f "$NAME"/23.txt ]; then
    echo "    Telnet"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/23.txt|g" /tmp/resource/23-telnet.rc
    cat /tmp/resource/23-telnet.rc >> /tmp/master
fi

if [ -f "$NAME"/25.txt ]; then
    echo "    SMTP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/25.txt|g" /tmp/resource/25-smtp.rc
    cat /tmp/resource/25-smtp.rc >> /tmp/master
fi

if [ -f "$NAME"/69.txt ]; then
    echo "    TFTP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/69.txt|g" /tmp/resource/69-tftp.rc
    cat /tmp/resource/69-tftp.rc >> /tmp/master
fi

if [ -f "$NAME"/79.txt ]; then
    echo "    Finger"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/79.txt|g" /tmp/resource/79-finger.rc
    cat /tmp/resource/79-finger.rc >> /tmp/master
fi

if [ -f "$NAME"/110.txt ]; then
    echo "    POP3"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/110.txt|g" /tmp/resource/110-pop3.rc
    cat /tmp/resource/110-pop3.rc >> /tmp/master
fi

#if [ -f "$NAME"/111.txt ]; then
#    echo "    RPC"
#    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/111.txt|g" /tmp/resource/111-rpc.rc
#    cat /tmp/resource/111-rpc.rc >> /tmp/master
#fi

if [ -f "$NAME"/123.txt ]; then
    echo "    NTP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/123.txt|g" /tmp/resource/123-udp-ntp.rc
    cat /tmp/resource/123-udp-ntp.rc >> /tmp/master
fi

if [ -f "$NAME"/135.txt ]; then
    echo "    DCE/RPC"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/135.txt|g" /tmp/resource/135-dcerpc.rc
    cat /tmp/resource/135-dcerpc.rc >> /tmp/master
fi

if [ -f "$NAME"/137.txt ]; then
    echo "    NetBIOS"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/137.txt|g" /tmp/resource/137-udp-netbios.rc
    cat /tmp/resource/137-udp-netbios.rc >> /tmp/master
fi

if [ -f "$NAME"/143.txt ]; then
    echo "    IMAP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/143.txt|g" /tmp/resource/143-imap.rc
    cat /tmp/resource/143-imap.rc >> /tmp/master
fi

if [ -f "$NAME"/161.txt ]; then
    echo "    SNMP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/161.txt|g" /tmp/resource/161-udp-snmp.rc
    cat /tmp/resource/161-udp-snmp.rc >> /tmp/master
fi

if [ -f "$NAME"/407.txt ]; then
    echo "    Motorola"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/407.txt|g" /tmp/resource/407-udp-motorola.rc
    cat /tmp/resource/407-udp-motorola.rc >> /tmp/master
fi

if [ -f "$NAME"/443.txt ]; then
    echo "    VMware"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/443.txt|g" /tmp/resource/443-vmware.rc
    cat /tmp/resource/443-vmware.rc >> /tmp/master
fi

if [ -f "$NAME"/445.txt ]; then
    echo "    SMB"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/445.txt|g" /tmp/resource/445-smb.rc
    cat /tmp/resource/445-smb.rc >> /tmp/master
fi

if [ -f "$NAME"/465.txt ]; then
    echo "    SMTP/S"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/465.txt|g" /tmp/resource/465-smtp.rc
    cat /tmp/resource/465-smtp.rc >> /tmp/master
fi

if [ -f "$NAME"/502.txt ]; then
    echo "    SCADA Modbus Client Utility"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/502.txt|g" /tmp/resource/502-scada.rc
    cat /tmp/resource/502-scada.rc >> /tmp/master
fi

if [ -f "$NAME"/512.txt ]; then
    echo "    Rexec"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/512.txt|g" /tmp/resource/512-rexec.rc
    cat /tmp/resource/512-rexec.rc >> /tmp/master
fi

if [ -f "$NAME"/513.txt ]; then
    echo "    rlogin"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/513.txt|g" /tmp/resource/513-rlogin.rc
    cat /tmp/resource/513-rlogin.rc >> /tmp/master
fi

if [ -f "$NAME"/514.txt ]; then
    echo "    rshell"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/514.txt|g" /tmp/resource/514-rshell.rc
    cat /tmp/resource/514-rshell.rc >> /tmp/master
fi

if [ -f "$NAME"/523.txt ]; then
    echo "    db2"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/523.txt|g" /tmp/resource/523-udp-db2.rc
    cat /tmp/resource/523-udp-db2.rc >> /tmp/master
fi

if [ -f "$NAME"/548.txt ]; then
    echo "    AFP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/548.txt|g" /tmp/resource/548-afp.rc
    cat /tmp/resource/548-afp.rc >> /tmp/master
fi

if [ -f "$NAME"/623.txt ]; then
    echo "    IPMI"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/623.txt|g" /tmp/resource/623-udp-ipmi.rc
    cat /tmp/resource/623-udp-ipmi.rc >> /tmp/master
fi

if [ -f "$NAME"/771.txt ]; then
    echo "    SCADA Digi"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/771.txt|g" /tmp/resource/771-scada.rc
    cat /tmp/resource/771-scada.rc >> /tmp/master
fi

if [ -f "$NAME"/831.txt ]; then
    echo "    EasyCafe Server Remote File Access"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/831.txt|g" /tmp/resource/831-easycafe.rc
    cat /tmp/resource/831-easycafe.rc >> /tmp/master
fi

if [ -f "$NAME"/902.txt ]; then
    echo "    VMware"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/902.txt|g" /tmp/resource/902-vmware.rc
    cat /tmp/resource/902-vmware.rc >> /tmp/master
fi

if [ -f "$NAME"/998.txt ]; then
    echo "    Novell ZENworks Configuration Management Preboot Service Remote File Access"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/998.txt|g" /tmp/resource/998-zenworks.rc
    cat /tmp/resource/998-zenworks.rc >> /tmp/master
fi

if [ -f "$NAME"/1099.txt ]; then
    echo "    RMI Registery"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1099.txt|g" /tmp/resource/1099-rmi.rc
    cat /tmp/resource/1099-rmi.rc >> /tmp/master
fi

if [ -f "$NAME"/1158.txt ]; then
    echo "    Oracle"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1158.txt|g" /tmp/resource/1158-oracle.rc
    cat /tmp/resource/1158-oracle.rc >> /tmp/master
fi

if [ -f "$NAME"/1414.txt ]; then
    echo "    IBM MQ"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1414.txt|g" /tmp/resource/1414-ibm-mq.rc
    cat /tmp/resource/1414-ibm-mq.rc >> /tmp/master
fi

if [ -f "$NAME"/1433.txt ]; then
    echo "    MS-SQL"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1433.txt|g" /tmp/resource/1433-mssql.rc
    cat /tmp/resource/1433-mssql.rc >> /tmp/master
fi

if [ -f "$NAME"/1521.txt ]; then
    echo "    Oracle"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1521.txt|g" /tmp/resource/1521-oracle.rc
    cat /tmp/resource/1521-oracle.rc >> /tmp/master
fi

if [ -f "$NAME"/1604.txt ]; then
    echo "    Citrix"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1604.txt|g" /tmp/resource/1604-udp-citrix.rc
    cat /tmp/resource/1604-udp-citrix.rc >> /tmp/master
fi

if [ -f "$NAME"/1720.txt ]; then
    echo "    H323"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1720.txt|g" /tmp/resource/1720-h323.rc
    cat /tmp/resource/1720-h323.rc >> /tmp/master
fi

if [ -f "$NAME"/1900.txt ]; then
    echo "    UPnP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/1900.txt|g" /tmp/resource/1900-udp-upnp.rc
    cat /tmp/resource/1900-udp-upnp.rc >> /tmp/master
fi

if [ -f "$NAME"/2049.txt ]; then
    echo "    NFS"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/2049.txt|g" /tmp/resource/2049-nfs.rc
    cat /tmp/resource/2049-nfs.rc >> /tmp/master
fi

if [ -f "$NAME"/2362.txt ]; then
    echo "    SCADA Digi"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/2362.txt|g" /tmp/resource/2362-udp-scada.rc
    cat /tmp/resource/2362-udp-scada.rc >> /tmp/master
fi

if [ -f "$NAME"/3000.txt ]; then
    echo "    EMC"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/3000.txt|g" /tmp/resource/3000-emc.rc
    cat /tmp/resource/3000-emc.rc >> /tmp/master
fi

if [ -f "$NAME"/3050.txt ]; then
    echo "    Borland InterBase Services Manager Information"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/3050.txt|g" /tmp/resource/3050-borland.rc
    cat /tmp/resource/3050-borland.rc >> /tmp/master
fi

if [ -f "$NAME"/3306.txt ]; then
    echo "    MySQL"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/3306.txt|g" /tmp/resource/3306-mysql.rc
    cat /tmp/resource/3306-mysql.rc >> /tmp/master
fi

if [ -f "$NAME"/3310.txt ]; then
    echo "    ClamAV"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/3310.txt|g" /tmp/resource/3310-clamav.rc
    cat /tmp/resource/3310-clamav.rc >> /tmp/master
fi

if [ -f "$NAME"/3389.txt ]; then
    echo "    RDP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/3389.txt|g" /tmp/resource/3389-rdp.rc
    cat /tmp/resource/3389-rdp.rc >> /tmp/master
fi

if [ -f "$NAME"/3500.txt ]; then
    echo "    EMC"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/3500.txt|g" /tmp/resource/3500-emc.rc
    cat /tmp/resource/3500-emc.rc >> /tmp/master
fi

if [ -f "$NAME"/4786.txt ]; then
    echo "    Cisco Smart Install"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/4786.txt|g" /tmp/resource/4786-cisco-smart-install.rc
    cat /tmp/resource/4786-cisco-smart-install.rc >> /tmp/master
fi

if [ -f "$NAME"/4800.txt ]; then
    echo "    Moxa"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/4800.txt|g" /tmp/resource/4800-udp-moxa.rc
    cat /tmp/resource/4800-udp-moxa.rc >> /tmp/master
fi

if [ -f "$NAME"/5000.txt ]; then
    echo "    Satel"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5000.txt|g" /tmp/resource/5000-satel.rc
    cat /tmp/resource/5000-satel.rc >> /tmp/master
fi

if [ -f "$NAME"/5040.txt ]; then
    echo "    DCE/RPC"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5040.txt|g" /tmp/resource/5040-dcerpc.rc
    cat /tmp/resource/5040-dcerpc.rc >> /tmp/master
fi

if [ -f "$NAME"/5060.txt ]; then
    echo "    SIP UDP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5060.txt|g" /tmp/resource/5060-udp-sip.rc
    cat /tmp/resource/5060-udp-sip.rc >> /tmp/master
fi

if [ -f "$NAME"/5060-tcp.txt ]; then
    echo "    SIP"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5060-tcp.txt|g" /tmp/resource/5060-sip.rc
    cat /tmp/resource/5060-sip.rc >> /tmp/master
fi

if [ -f "$NAME"/5432.txt ]; then
    echo "    Postgres"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5432.txt|g" /tmp/resource/5432-postgres.rc
    cat /tmp/resource/5432-postgres.rc >> /tmp/master
fi

if [ -f "$NAME"/5560.txt ]; then
    echo "    Oracle iSQL"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5560.txt|g" /tmp/resource/5560-oracle.rc
    cat /tmp/resource/5560-oracle.rc >> /tmp/master
fi

if [ -f "$NAME"/5631.txt ]; then
    echo "    pcAnywhere"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5631.txt|g" /tmp/resource/5631-pcanywhere.rc
    cat /tmp/resource/5631-pcanywhere.rc >> /tmp/master
fi

if [ -f "$NAME"/5632.txt ]; then
    echo "    pcAnywhere"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5632.txt|g" /tmp/resource/5632-pcanywhere.rc
    cat /tmp/resource/5632-pcanywhere.rc >> /tmp/master
fi

if [ -f "$NAME"/5900.txt ]; then
    echo "    VNC"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5900.txt|g" /tmp/resource/5900-vnc.rc
    cat /tmp/resource/5900-vnc.rc >> /tmp/master
fi

if [ -f "$NAME"/5920.txt ]; then
    echo "    CCTV DVR"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5920.txt|g" /tmp/resource/5920-cctv.rc
    cat /tmp/resource/5920-cctv.rc >> /tmp/master
fi

if [ -f "$NAME"/5984.txt ]; then
    echo "    CouchDB"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5984.txt|g" /tmp/resource/5984-couchdb.rc
    cat /tmp/resource/5984-couchdb.rc >> /tmp/master
fi

if [ -f "$NAME"/5985.txt ]; then
    echo "    winrm"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/5985.txt|g" /tmp/resource/5985-winrm.rc
    cat /tmp/resource/5985-winrm.rc >> /tmp/master
fi

if [ -f "$NAME"/x11.txt ]; then
    echo "    x11"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/x11.txt|g" /tmp/resource/6000-5-x11.rc
    cat /tmp/resource/6000-5-x11.rc >> /tmp/master
fi

if [ -f "$NAME"/6379.txt ]; then
    echo "    Redis"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/6379.txt|g" /tmp/resource/6379-redis.rc
    cat /tmp/resource/6379-redis.rc >> /tmp/master
fi

if [ -f "$NAME"/7777.txt ]; then
    echo "    Backdoor"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/7777.txt|g" /tmp/resource/7777-backdoor.rc
    cat /tmp/resource/7777-backdoor.rc >> /tmp/master
fi

if [ -f "$NAME"/8000.txt ]; then
    echo "    Canon"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/8000.txt|g" /tmp/resource/8000-canon.rc
    cat /tmp/resource/8000-canon.rc >> /tmp/master
fi

if [ -f "$NAME"/8080.txt ]; then
    echo "    Tomcat"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/8080.txt|g" /tmp/resource/8080-tomcat.rc
    cat /tmp/resource/8080-tomcat.rc >> /tmp/master
fi

if [ -f "$NAME"/8080.txt ]; then
    echo "    Oracle"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/8080.txt|g" /tmp/resource/8080-oracle.rc
    cat /tmp/resource/8080-oracle.rc >> /tmp/master
fi

if [ -f "$NAME"/8222.txt ]; then
    echo "    VMware"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/8222.txt|g" /tmp/resource/8222-vmware.rc
    cat /tmp/resource/8222-vmware.rc >> /tmp/master
fi

if [ -f "$NAME"/8400.txt ]; then
    echo "    Adobe"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/8400.txt|g" /tmp/resource/8400-adobe.rc
    cat /tmp/resource/8400-adobe.rc >> /tmp/master
fi

if [ -f "$NAME"/8834.txt ]; then
    echo "    Nessus"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/8834.txt|g" /tmp/resource/8834-nessus.rc
    cat /tmp/resource/8834-nessus.rc >> /tmp/master
fi

if [ -f "$NAME"/9000.txt ]; then
    echo "    Sharp DVR Password Retriever"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/9000.txt|g" /tmp/resource/9000-sharp.rc
    cat /tmp/resource/9000-sharp.rc >> /tmp/master
fi

if [ -f "$NAME"/9084.txt ]; then
    echo "    VMware"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/9084.txt|g" /tmp/resource/9084-vmware.rc
    cat /tmp/resource/9084-vmware.rc >> /tmp/master
fi

if [ -f "$NAME"/9100.txt ]; then
    echo "    Printers"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/9100.txt|g" /tmp/resource/9100-printers.rc
    cat /tmp/resource/9100-printers.rc >> /tmp/master
fi

if [ -f "$NAME"/9999.txt ]; then
    echo "    Telnet"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/9999.txt|g" /tmp/resource/9999-telnet.rc
    cat /tmp/resource/9999-telnet.rc >> /tmp/master
fi

if [ -f "$NAME"/13364.txt ]; then
    echo "    Rosewill RXS-3211 IP Camera Password Retriever"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/13364.txt|g" /tmp/resource/13364-rosewill.rc
    cat /tmp/resource/13364-rosewill.rc >> /tmp/master
fi

if [ -f "$NAME"/17185.txt ]; then
    echo "    VxWorks"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/17185.txt|g" /tmp/resource/17185-udp-vxworks.rc
    cat /tmp/resource/17185-udp-vxworks.rc >> /tmp/master
fi

if [ -f "$NAME"/20256.txt ]; then
    echo "    Unitronics"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/20256.txt|g" /tmp/resource/20256-unitronics.rc
    cat /tmp/resource/20256-unitronics.rc >> /tmp/master
fi

if [ -f "$NAME"/28784.txt ]; then
    echo "    SCADA Koyo DirectLogic PLC"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/28784.txt|g" /tmp/resource/28784-scada.rc
    cat /tmp/resource/28784-scada.rc >> /tmp/master
fi

if [ -f "$NAME"/30718.txt ]; then
    echo "    Telnet"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/30718.txt|g" /tmp/resource/30718-telnet.rc
    cat /tmp/resource/30718-telnet.rc >> /tmp/master
fi

if [ -f "$NAME"/37777.txt ]; then
    echo "    Dahua DVR"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/37777.txt|g" /tmp/resource/37777-dahua-dvr.rc
    cat /tmp/resource/37777-dahua-dvr.rc >> /tmp/master
fi

if [ -f "$NAME"/46824.txt ]; then
    echo "    SCADA Sielco Sistemi"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/46824.txt|g" /tmp/resource/46824-scada.rc
    cat /tmp/resource/46824-scada.rc >> /tmp/master
fi

if [ -f "$NAME"/50000.txt ]; then
    echo "    db2"
    sed -i "s|setg RHOSTS.*|setg RHOSTS file:$NAME\/50000.txt|g" /tmp/resource/50000-db2.rc
    cat /tmp/resource/50000-db2.rc >> /tmp/master
fi

###############################################################################################################################

echo db_export -f xml -a "$NAME"/metasploit.xml >> /tmp/master
echo exit >> /tmp/master

X=$(wc -l /tmp/master | cut -d ' ' -f1)

if [ "$X" -eq 4 ]; then
    echo
    echo -e "${YELLOW}[*] No ports or modules to scan.${NC}"
else
    echo
    sed 's/\/\//\//g' /tmp/master > "$NAME"/master.rc
    sudo msfdb init
    msfconsole -r "$NAME"/master.rc
    cat tmpmsf | sed 's/Host is running Windows //g' | sed 's/\.\.\.//g' | grep -Eiv "(> exit|> run|% complete|1.0 error|appears to be safe|attempting authentication bypass|attempting to extract|authorization not requested|boot.ini not found|checking if file|completed|connecting to the server|connection reset by peer|data_connect failed|database|db_export|did not reply|does not appear|doesn't exist|erb directives|error occurred|failed to login|finished export|handshake failed|ineffective|invalid login|invalid sql|it doesn't seem|login failed|metasploit tip|negotiation failed|nomethoderror|no relay detected|no response|No users found|not allowed to connect|not be identified|not exploitable|not foundnot vulnerable|oracle - checking|oracle - refused|providing some time|request timeout|reset by peer|responded with error|rhosts|rport|scanning for vulnerable|shutting down the tftp|spool|starting export|starting tftp server|starting vnc login|threads|timed out|trying to acquire|unable to login|unknown state)" > "$NAME"/metasploit.txt
fi

echo
echo -e "${BLUE}Stopping Postgres.${NC}"
sudo systemctl stop postgresql.service

# Cleanup temp files
rm -rf /tmp/resource/ /tmp/master tmpmsf
