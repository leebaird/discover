#!/bin/bash

# Remove nmap scripts not being used
ls -l /usr/share/nmap/scripts/ | awk '{print $9}' | cut -d '.' -f1 | egrep -v '(address-info|ajp-auth|ajp-headers|allseeingeye-info|asn-query|auth-owners|auth-spoof|broadcast|brute|citrix-enum-apps-xml|citrix-enum-servers-xml|clock-skew|creds-summary|daap-get-library|discover|dns-brute|dns-check-zone|dns-client-subnet-scan|dns-fuzz|dns-ip6-arpa-scan|dns-srv-enum|dns-nsec3-enum|domcon-cmd|duplicates|eap-info|fcrdns|fingerprint-strings|firewalk|firewall-bypass|ftp-libopie|ftp-libopie|ganglia-info|hnap-info|hostmap-bfk|hostmap-ip2hosts|hostmap-robtex|http|iax2-version|informix-query|informix-tables|ip-forwarding|ip-geolocation|ipidseq|ipv6|irc-botnet-channels|irc-info|irc-unrealircd-backdoor|isns-info|jdwp-exec|jdwp-info|jdwp-inject|krb5-enum-users|ldap-novell-getpass|ldap-search|llmnr-resolve|metasploit-info|mmouse-exec|ms-sql-config|mrinfo|ms-sql-hasdbaccess|ms-sql-query|ms-sql-tables|ms-sql-xp-cmdshell|mtrace|murmur-version|mysql-audit|mysql-enum|mysql-dump-hashes|mysql-query|nat-pmp-info|nat-pmp-mapport|netbus-info|ntp-info|omp2-enum-targets|oracle-enum-users|ovs-agent-version|p2p-conficker|path-mtu|pjl-y-message|quake1-info|quake3-info|quake3-master-getservers|qscan|resolveall|reverse-index|rpc-grind|rpcap-info|rusers|shodan-api|script|sip-call-spoof|skypev2-version|smb-flood|smb-ls|smb-print-text|smb-psexec|sniffer-detect|snmp-ios-config|socks-open-proxy|sql-injection|ssh-hostkey|ssh2-enum-algos|sshv1|stun-info|teamspeak2-version|targets|tftp-enum|tor-consensus-checker|traceroute-geolocation|unittest|unusual-port|upnp-info|url-snarf|ventrilo-info|vtam-enum|vuln-cve|vuze-dht-info|weblogic-t3-info|whois|xmlrpc-methods|xmpp-info)' > tmp

grep 'script=' discover.sh | egrep -v '(discover.sh|22.txt|smtp.txt)' | cut -d '=' -f2- | cut -d ' ' -f1 | tr ',' '\n' | egrep -v '(db2-discover|dhcp-discover|dns-service-discovery|http-email-harvest|http-grep|membase-http-info|oracle-sid-brute|smb-os-discovery|tn3270-info)' | sort -u > tmp2

echo > tmp-updates
echo "New modules to be added." > tmp-updates
echo >> tmp-updates
echo >> tmp-updates
echo "Nmap scripts" >> tmp-updates
echo "==============================" >> tmp-updates

diff tmp tmp2 | egrep '^[<>]' | awk '{print $2}' | sed '/^$/d' | egrep -v '(clamav-exec|iec-identify|ntp-info|smb*|smtp-commands|smtp-enum-users|smtp-ntlm-info|smtp-open-relay|smtp-strangeport|smtp-vuln*|ssl*|tls-ticketbleed|tls-nextprotoneg|tmp)' >> tmp-updates

rm tmp

echo >> tmp-updates
echo >> tmp-updates
echo "Metasploit auxiliary/scanners" >> tmp-updates
echo "==============================" >> tmp-updates

# Not included: http sap

categories="afp backdoor chargen couchdb db2 dcerpc dect discovery emc finger ftp h323 imap ip ipmi lotus misc mongodb motorola msf mssql mysql natpmp nessus netbios nexpose nfs ntp openvas oracle pcanywhere pop3 portscan postgres printer rdp rogue rservices scada sip smb smtp snmp ssh telephony telnet tftp upnp vmware vnc voice vxworks winrm x11"

for i in $categories; do
     ls -l /usr/share/metasploit-framework/modules/auxiliary/scanner/$i | awk '{print $9}' | cut -d '.' -f1 >> tmp
done

sed '/^$/d' tmp > tmp2

# Remove Metasploit scanners not used
egrep -v '(ack|apache_karaf_command_execution|arp_sweep|call_scanner|cerberus_sftp_enumusers|cisco_smart_install|couchdb_enum|dvr_config_disclosure|empty_udp|endpoint_mapper|ftpbounce|hidden|indusoft_ntwebserver_fileaccess|ipidseq|ipv6|login|lotus_domino_hashes|lotus_domino_version|management|ms08_067_check|mysql_file_enum|mysql_hashdump|mysql_schemadump|mysql_writable_dirs|natpmp_portscan|poisonivy_control_scanner|profinet_siemens|psexec_loggedin_users|recorder|rogue_recv|rogue_send|sipdroid_ext_enum|snmp_set|ssh_enumusers|ssh_identify_pubkeys|station_scanner|syn|tcp|tftpbrute|udp_probe|udp_sweep|vmware_enum_users|vmware_enum_permissions|vmware_enum_sessions|vmware_enum_vms|vmware_host_details|vmware_screenshot_stealer|wardial|winrm_cmd|winrm_wql|xmas)' tmp2 | sort > tmp-msf-all

grep 'use ' $discover/resource/*.rc | grep -v 'recon-ng' > tmp

# Print from the last /, to the end of the line
sed -e 's:.*/\(.*\):\1:g' tmp > tmp-msf-used

grep -v -f tmp-msf-used tmp-msf-all >> tmp-updates

echo >> tmp-updates
echo >> tmp-updates

echo "recon-ng" >> tmp-updates
echo "==============================" >> tmp-updates
recon-cli -M | grep '/'| egrep -v '(exploitation|import|reporting)' | sed 's/^[ \t]*//' > tmp
cat tmp | egrep -iv '(adobe|bozocrack|brute_suffix|cache_snoop|dev_diver|freegeoip|fullcontact|gists_search|github_commits|github_dorks|github_repos|github_users|google_site_web|hashes_org|interesting_files|ipinfodb|ipstack|jigsaw|linkedin_auth|locations|mailtester|mangle|metacrawler|migrate_contacts|migrate_hosts|namechk|pgp|profiler|pwnedlist|virustotal|vulnerabilities)' > tmp2
cat $discover/resource/recon-ng.rc $discover/resource/recon-ng-active.rc | grep '^use' | awk '{print $2}' | sort -u > tmp3
diff tmp2 tmp3 | grep '/' | grep -v 'netblock' | awk '{print $2}' | sort -u >> tmp-updates

echo >> tmp-updates
echo >> tmp-updates

mv tmp-updates $home/data/new-stuff.txt
rm tmp*

echo
echo $medium
echo
echo -e "The new report is located at ${YELLOW}$home/data/new-stuff.txt${NC}\n"
echo
echo

