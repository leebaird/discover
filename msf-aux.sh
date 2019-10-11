#!/bin/bash

if [[ -e $name/19.txt ]]; then
     echo "     Chargen Probe Utility"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/19.txt|g" /tmp/resource/19-chargen.rc
     cat /tmp/resource/19-chargen.rc >> /tmp/master
fi

if [[ -e $name/21.txt ]]; then
     echo "     FTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/21.txt|g" /tmp/resource/21-ftp.rc
     cat /tmp/resource/21-ftp.rc >> /tmp/master
fi

if [[ -e $name/22.txt ]]; then
     echo "     SSH"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/22.txt|g" /tmp/resource/22-ssh.rc
     cat /tmp/resource/22-ssh.rc >> /tmp/master
fi

if [[ -e $name/23.txt ]]; then
     echo "     Telnet"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/23.txt|g" /tmp/resource/23-telnet.rc
     cat /tmp/resource/23-telnet.rc >> /tmp/master
fi

if [[ -e $name/25.txt ]]; then
     echo "     SMTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/25.txt|g" /tmp/resource/25-smtp.rc
     cat /tmp/resource/25-smtp.rc >> /tmp/master
fi

if [[ -e $name/69.txt ]]; then
     echo "     TFTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/69.txt|g" /tmp/resource/69-tftp.rc
     cat /tmp/resource/69-tftp.rc >> /tmp/master
fi

if [[ -e $name/79.txt ]]; then
     echo "     Finger"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/79.txt|g" /tmp/resource/79-finger.rc
     cat /tmp/resource/79-finger.rc >> /tmp/master
fi

if [[ -e $name/110.txt ]]; then
     echo "     POP3"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/110.txt|g" /tmp/resource/110-pop3.rc
     cat /tmp/resource/110-pop3.rc >> /tmp/master
fi

if [[ -e $name/111.txt ]]; then
     echo "     RPC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/111.txt|g" /tmp/resource/111-rpc.rc
     cat /tmp/resource/111-rpc.rc >> /tmp/master
fi

if [[ -e $name/123.txt ]]; then
     echo "     NTP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/123.txt|g" /tmp/resource/123-udp-ntp.rc
     cat /tmp/resource/123-udp-ntp.rc >> /tmp/master
fi

if [[ -e $name/135.txt ]]; then
     echo "     DCE/RPC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/135.txt|g" /tmp/resource/135-dcerpc.rc
     cat /tmp/resource/135-dcerpc.rc >> /tmp/master
fi

if [[ -e $name/137.txt ]]; then
     echo "     NetBIOS"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/137.txt|g" /tmp/resource/137-udp-netbios.rc
     cat /tmp/resource/137-udp-netbios.rc >> /tmp/master
fi

if [[ -e $name/143.txt ]]; then
     echo "     IMAP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/143.txt|g" /tmp/resource/143-imap.rc
     cat /tmp/resource/143-imap.rc >> /tmp/master
fi

if [[ -e $name/161.txt ]]; then
     echo "     SNMP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/161.txt|g" /tmp/resource/161-udp-snmp.rc
     cat /tmp/resource/161-udp-snmp.rc >> /tmp/master
fi

if [[ -e $name/407.txt ]]; then
     echo "     Motorola"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/407.txt|g" /tmp/resource/407-udp-motorola.rc
     cat /tmp/resource/407-udp-motorola.rc >> /tmp/master
fi

if [[ -e $name/443.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/443.txt|g" /tmp/resource/443-vmware.rc
     cat /tmp/resource/443-vmware.rc >> /tmp/master
fi

if [[ -e $name/445.txt ]]; then
     echo "     SMB"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/445.txt|g" /tmp/resource/445-smb.rc
     cat /tmp/resource/445-smb.rc >> /tmp/master
fi

if [[ -e $name/465.txt ]]; then
     echo "     SMTP/S"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/465.txt|g" /tmp/resource/465-smtp.rc
     cat /tmp/resource/465-smtp.rc >> /tmp/master
fi

if [[ -e $name/502.txt ]]; then
     echo "     SCADA Modbus Client Utility"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/502.txt|g" /tmp/resource/502-scada.rc
     cat /tmp/resource/502-scada.rc >> /tmp/master
fi

if [[ -e $name/512.txt ]]; then
     echo "     Rexec"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/512.txt|g" /tmp/resource/512-rexec.rc
     cat /tmp/resource/512-rexec.rc >> /tmp/master
fi

if [[ -e $name/513.txt ]]; then
     echo "     rlogin"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/513.txt|g" /tmp/resource/513-rlogin.rc
     cat /tmp/resource/513-rlogin.rc >> /tmp/master
fi

if [[ -e $name/514.txt ]]; then
     echo "     rshell"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/514.txt|g" /tmp/resource/514-rshell.rc
     cat /tmp/resource/514-rshell.rc >> /tmp/master
fi

if [[ -e $name/523.txt ]]; then
     echo "     db2"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/523.txt|g" /tmp/resource/523-udp-db2.rc
     cat /tmp/resource/523-udp-db2.rc >> /tmp/master
fi

if [[ -e $name/548.txt ]]; then
     echo "     AFP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/548.txt|g" /tmp/resource/548-afp.rc
     cat /tmp/resource/548-afp.rc >> /tmp/master
fi

if [[ -e $name/623.txt ]]; then
     echo "     IPMI"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/623.txt|g" /tmp/resource/623-udp-ipmi.rc
     cat /tmp/resource/623-udp-ipmi.rc >> /tmp/master
fi

if [[ -e $name/771.txt ]]; then
     echo "     SCADA Digi"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/771.txt|g" /tmp/resource/771-scada.rc
     cat /tmp/resource/771-scada.rc >> /tmp/master
fi

if [[ -e $name/831.txt ]]; then
     echo "     EasyCafe Server Remote File Access"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/831.txt|g" /tmp/resource/831-easycafe.rc
     cat /tmp/resource/831-easycafe.rc >> /tmp/master
fi

if [[ -e $name/902.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/902.txt|g" /tmp/resource/902-vmware.rc
     cat /tmp/resource/902-vmware.rc >> /tmp/master
fi

if [[ -e $name/998.txt ]]; then
     echo "     Novell ZENworks Configuration Management Preboot Service Remote File Access"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/998.txt|g" /tmp/resource/998-zenworks.rc
     cat /tmp/resource/998-zenworks.rc >> /tmp/master
fi

if [[ -e $name/1099.txt ]]; then
     echo "     RMI Registery"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1099.txt|g" /tmp/resource/1099-rmi.rc
     cat /tmp/resource/1099-rmi.rc >> /tmp/master
fi

if [[ -e $name/1158.txt ]]; then
     echo "     Oracle"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1158.txt|g" /tmp/resource/1158-oracle.rc
     cat /tmp/resource/1158-oracle.rc >> /tmp/master
fi

if [[ -e $name/1433.txt ]]; then
     echo "     MS-SQL"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1433.txt|g" /tmp/resource/1433-mssql.rc
     cat /tmp/resource/1433-mssql.rc >> /tmp/master
fi

if [[ -e $name/1521.txt ]]; then
     echo "     Oracle"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1521.txt|g" /tmp/resource/1521-oracle.rc
     cat /tmp/resource/1521-oracle.rc >> /tmp/master
fi

if [[ -e $name/1604.txt ]]; then
     echo "     Citrix"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1604.txt|g" /tmp/resource/1604-udp-citrix.rc
     cat /tmp/resource/1604-udp-citrix.rc >> /tmp/master
fi

if [[ -e $name/1720.txt ]]; then
     echo "     H323"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1720.txt|g" /tmp/resource/1720-h323.rc
     cat /tmp/resource/1720-h323.rc >> /tmp/master
fi

if [[ -e $name/1900.txt ]]; then
     echo "     UPnP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/1900.txt|g" /tmp/resource/1900-udp-upnp.rc
     cat /tmp/resource/1900-udp-upnp.rc >> /tmp/master
fi

if [[ -e $name/2049.txt ]]; then
     echo "     NFS"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/2049.txt|g" /tmp/resource/2049-nfs.rc
     cat /tmp/resource/2049-nfs.rc >> /tmp/master
fi

if [[ -e $name/2362.txt ]]; then
     echo "     SCADA Digi"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/2362.txt|g" /tmp/resource/2362-udp-scada.rc
     cat /tmp/resource/2362-udp-scada.rc >> /tmp/master
fi

if [[ -e $name/3000.txt ]]; then
     echo "     EMC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3000.txt|g" /tmp/resource/3000-emc.rc
     cat /tmp/resource/3000-emc.rc >> /tmp/master
fi

if [[ -e $name/3050.txt ]]; then
     echo "     Borland InterBase Services Manager Information"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3050.txt|g" /tmp/resource/3050-borland.rc
     cat /tmp/resource/3050-borland.rc >> /tmp/master
fi

if [[ -e $name/3306.txt ]]; then
     echo "     MySQL"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3306.txt|g" /tmp/resource/3306-mysql.rc
     cat /tmp/resource/3306-mysql.rc >> /tmp/master
fi

if [[ -e $name/3310.txt ]]; then
     echo "     ClamAV"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3310.txt|g" /tmp/resource/3310-clamav.rc
     cat /tmp/resource/3310-clamav.rc >> /tmp/master
fi

if [[ -e $name/3389.txt ]]; then
     echo "     RDP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3389.txt|g" /tmp/resource/3389-rdp.rc
     cat /tmp/resource/3389-rdp.rc >> /tmp/master
fi

if [[ -e $name/3500.txt ]]; then
     echo "     EMC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/3500.txt|g" /tmp/resource/3500-emc.rc
     cat /tmp/resource/3500-emc.rc >> /tmp/master
fi

if [[ -e $name/4800.txt ]]; then
     echo "     Moxa"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/4800.txt|g" /tmp/resource/4800-udp-moxa.rc
     cat /tmp/resource/4800-udp-moxa.rc >> /tmp/master
fi

if [[ -e $name/5000.txt ]]; then
     echo "     Satel"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5000.txt|g" /tmp/resource/5000-satel.rc
     cat /tmp/resource/5000-satel.rc >> /tmp/master
fi

if [[ -e $name/5040.txt ]]; then
     echo "     DCE/RPC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5040.txt|g" /tmp/resource/5040-dcerpc.rc
     cat /tmp/resource/5040-dcerpc.rc >> /tmp/master
fi

if [[ -e $name/5060.txt ]]; then
     echo "     SIP UDP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5060.txt|g" /tmp/resource/5060-udp-sip.rc
     cat /tmp/resource/5060-udp-sip.rc >> /tmp/master
fi

if [[ -e $name/5060-tcp.txt ]]; then
     echo "     SIP"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5060-tcp.txt|g" /tmp/resource/5060-sip.rc
     cat /tmp/resource/5060-sip.rc >> /tmp/master
fi

if [[ -e $name/5432.txt ]]; then
     echo "     Postgres"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5432.txt|g" /tmp/resource/5432-postgres.rc
     cat /tmp/resource/5432-postgres.rc >> /tmp/master
fi

if [[ -e $name/5560.txt ]]; then
     echo "     Oracle iSQL"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5560.txt|g" /tmp/resource/5560-oracle.rc
     cat /tmp/resource/5560-oracle.rc >> /tmp/master
fi

if [[ -e $name/5631.txt ]]; then
     echo "     pcAnywhere"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5631.txt|g" /tmp/resource/5631-pcanywhere.rc
     cat /tmp/resource/5631-pcanywhere.rc >> /tmp/master
fi

if [[ -e $name/5632.txt ]]; then
     echo "     pcAnywhere"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5632.txt|g" /tmp/resource/5632-pcanywhere.rc
     cat /tmp/resource/5632-pcanywhere.rc >> /tmp/master
fi

if [[ -e $name/5900.txt ]]; then
     echo "     VNC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5900.txt|g" /tmp/resource/5900-vnc.rc
     cat /tmp/resource/5900-vnc.rc >> /tmp/master
fi

if [[ -e $name/5920.txt ]]; then
     echo "     CCTV DVR"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5920.txt|g" /tmp/resource/5920-cctv.rc
     cat /tmp/resource/5920-cctv.rc >> /tmp/master
fi

if [[ -e $name/5984.txt ]]; then
     echo "     CouchDB"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5984.txt|g" /tmp/resource/5984-couchdb.rc
     cat /tmp/resource/5984-couchdb.rc >> /tmp/master
fi

if [[ -e $name/5985.txt ]]; then
     echo "     winrm"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/5985.txt|g" /tmp/resource/5985-winrm.rc
     cat /tmp/resource/5985-winrm.rc >> /tmp/master
fi

if [[ -e $name/x11.txt ]]; then
     echo "     x11"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/x11.txt|g" /tmp/resource/6000-5-x11.rc
     cat /tmp/resource/6000-5-x11.rc >> /tmp/master
fi

if [[ -e $name/6379.txt ]]; then
     echo "     Redis"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/6379.txt|g" /tmp/resource/6379-redis.rc
     cat /tmp/resource/6379-redis.rc >> /tmp/master
fi

if [[ -e $name/7777.txt ]]; then
     echo "     Backdoor"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/7777.txt|g" /tmp/resource/7777-backdoor.rc
     cat /tmp/resource/7777-backdoor.rc >> /tmp/master
fi

if [[ -e $name/8000.txt ]]; then
     echo "     Canon"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8000.txt|g" /tmp/resource/8000-canon.rc
     cat /tmp/resource/8000-canon.rc >> /tmp/master
fi

if [[ -e $name/8080.txt ]]; then
     echo "     Tomcat"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8080.txt|g" /tmp/resource/8080-tomcat.rc
     cat /tmp/resource/8080-tomcat.rc >> /tmp/master
fi

if [[ -e $name/8080.txt ]]; then
     echo "     Oracle"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8080.txt|g" /tmp/resource/8080-oracle.rc
     cat /tmp/resource/8080-oracle.rc >> /tmp/master
fi

if [[ -e $name/8222.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8222.txt|g" /tmp/resource/8222-vmware.rc
     cat /tmp/resource/8222-vmware.rc >> /tmp/master
fi

if [[ -e $name/8400.txt ]]; then
     echo "     Adobe"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8400.txt|g" /tmp/resource/8400-adobe.rc
     cat /tmp/resource/8400-adobe.rc >> /tmp/master
fi

if [[ -e $name/8834.txt ]]; then
     echo "     Nessus"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/8834.txt|g" /tmp/resource/8834-nessus.rc
     cat /tmp/resource/8834-nessus.rc >> /tmp/master
fi

if [[ -e $name/9000.txt ]]; then
     echo "     Sharp DVR Password Retriever"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9000.txt|g" /tmp/resource/9000-sharp.rc
     cat /tmp/resource/9000-sharp.rc >> /tmp/master
fi

if [[ -e $name/9084.txt ]]; then
     echo "     VMware"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9084.txt|g" /tmp/resource/9084-vmware.rc
     cat /tmp/resource/9084-vmware.rc >> /tmp/master
fi

if [[ -e $name/9100.txt ]]; then
     echo "     Printers"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9100.txt|g" /tmp/resource/9100-printers.rc
     cat /tmp/resource/9100-printers.rc >> /tmp/master
fi

if [[ -e $name/9999.txt ]]; then
     echo "     Telnet"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/9999.txt|g" /tmp/resource/9999-telnet.rc
     cat /tmp/resource/9999-telnet.rc >> /tmp/master
fi

if [[ -e $name/13364.txt ]]; then
     echo "     Rosewill RXS-3211 IP Camera Password Retriever"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/13364.txt|g" /tmp/resource/13364-rosewill.rc
     cat /tmp/resource/13364-rosewill.rc >> /tmp/master
fi

if [[ -e $name/17185.txt ]]; then
     echo "     VxWorks"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/17185.txt|g" /tmp/resource/17185-udp-vxworks.rc
     cat /tmp/resource/17185-udp-vxworks.rc >> /tmp/master
fi

if [[ -e $name/28784.txt ]]; then
     echo "     SCADA Koyo DirectLogic PLC"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/28784.txt|g" /tmp/resource/28784-scada.rc
     cat /tmp/resource/28784-scada.rc >> /tmp/master
fi

if [[ -e $name/30718.txt ]]; then
     echo "     Telnet"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/30718.txt|g" /tmp/resource/30718-telnet.rc
     cat /tmp/resource/30718-telnet.rc >> /tmp/master
fi

if [[ -e $name/37777.txt ]]; then
     echo "     Dahua DVR"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/37777.txt|g" /tmp/resource/37777-dahua-dvr.rc
     cat /tmp/resource/37777-dahua-dvr.rc >> /tmp/master
fi

if [[ -e $name/46824.txt ]]; then
     echo "     SCADA Sielco Sistemi"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/46824.txt|g" /tmp/resource/46824-scada.rc
     cat /tmp/resource/46824-scada.rc >> /tmp/master
fi

if [[ -e $name/50000.txt ]]; then
     echo "     db2"
     sed -i "s|setg RHOSTS.*|setg RHOSTS file:$name\/50000.txt|g" /tmp/resource/50000-db2.rc
     cat /tmp/resource/50000-db2.rc >> /tmp/master
fi
