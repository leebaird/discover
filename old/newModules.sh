#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

echo
echo -e "${YELLOW}Things that need to be added${NC}"
echo

###############################################################################################################################

if [ -d /usr/share/metasploit-framework ]; then
    echo
    echo -e "${BLUE}Metasploit modules available but not used in resource/*.rc files${NC}"
    echo -e "${BLUE}=================================================================${NC}"

    CATEGORIES="afp backdoor chargen couchdb db2 dcerpc dect discovery emc finger ftp h323 imap ip ipmi lotus misc mongodb motorola msf mssql mysql natpmp nessus netbios nexpose nfs ntp openvas oracle pcanywhere pop3 portscan postgres printer rdp rogue rservices scada sip smb smtp snmp ssh telephony telnet tftp upnp vmware vnc voice vxworks winrm x11"

    # Used modules
    grep -h 'use ' "$DISCOVER/resource/"[0-9hj]*.rc 2>/dev/null |
        awk '{print $2}' |
        sed 's/auxiliary\/scanner\///' |
        sort -u > /tmp/used_ms.txt

    # Available modules
    for cat in $CATEGORIES; do
        find "/usr/share/metasploit-framework/modules/auxiliary/scanner/$cat" \
            -maxdepth 1 -type f -name '*.rb' -printf "${cat}/%f\n" 2>/dev/null
    done | sed 's/\.rb$//' |
    grep -Eiv '(ack|apache_karaf_command_execution|arp_sweep|call_scanner|cerberus_sftp_enumusers|cisco_smart_install|couchdb_enum|dvr_config_disclosure|empty_udp|endpoint_mapper|ftpbounce|hidden|ibm_mq_channel_brute|indusoft_ntwebserver_fileaccess|ipidseq|ipv6|login|lotus_domino_hashes|lotus_domino_version|management|ms08_067_check|mysql_file_enum|mssql_hashdump|mysql_schemadump|mysql_writable_dirs|natpmp_portscan|poisonivy_control_scanner|profinet_siemens|psexec_loggedin_users|recorder|rogue_recv|rogue_send|sipdroid_ext_enum|snmp_set|ssh_enum_git_keys|ssh_enumusers|ssh_identify_pubkeys|station_scanner|syn|tcp|tftpbrute|udp_probe|udp_sweep|vmware_enum_users|vmware_enum_permissions|vmware_enum_sessions|vmware_enum_vms|vmware_host_details|vmware_screenshot_stealer|wardial|winrm_cmd|winrm_wql|xmas)' |
    sort -u > /tmp/avail_ms.txt

    # Output: Available but not used
    grep -vxFf /tmp/used_ms.txt /tmp/avail_ms.txt

    rm -f /tmp/used_ms.txt /tmp/avail_ms.txt
fi

###############################################################################################################################

echo
echo -e "${BLUE}theHarvester modules available for passive.sh${NC}"
echo -e "${BLUE}==============================================${NC}"

if [ -f "$HOME/theHarvester/theHarvester/lib/core.py" ]; then
    # Used sources
    grep 'sources_' "$DISCOVER/recon/passive.sh" 2>/dev/null |
        grep -v '\@' |
        cut -d '(' -f2 | cut -d ')' -f1 |
        tr ' ' '\n' | sort -u > /tmp/used_harv.txt

    # Available engines
    sed -n '/def get_supportedengines/,/\]/p' "$HOME/theHarvester/theHarvester/lib/core.py" 2>/dev/null |
        grep -oP "(?<=').*?(?=')" | sort -u > /tmp/avail_harv.txt

    grep -vxFf /tmp/used_harv.txt /tmp/avail_harv.txt

    rm -f /tmp/used_harv.txt /tmp/avail_harv.txt
else
    echo -e "${YELLOW}[!] $HOME/theHarvester/theHarvester/lib/core.py not found.${NC}"
fi

###############################################################################################################################

NMAP_SCRIPT_DIR="/usr/share/nmap/scripts"

if [ -d "$NMAP_SCRIPT_DIR" ]; then
    echo
    echo -e "${BLUE}Nmap scripts available for nse.sh${NC}"
    echo -e "${BLUE}==================================${NC}"

    # Excluded scripts
    cat <<'END_EXCLUDES' > /tmp/excludes_nmap.txt
address-info
ajp-auth
ajp-headers
allseeingeye-info
asn-query
auth-owners
auth-spoof
citrix-enum-apps-xml
citrix-enum-servers-xml
clock-skew
creds-summary
daap-get-library
discover
dns-check-zone
dns-client-subnet-scan
dns-fuzz
dns-ip6-arpa-scan
dns-srv-enum
dns-nsec3-enum
domcon-cmd
duplicates
eap-info
fcrdns
fingerprint-strings
firewalk
firewall-bypass
ftp-libopie
ganglia-info
hnap-info
hostmap-bfk
hostmap-ip2hosts
hostmap-crtsh
hostmap-robtex
iax2-version
iec-identify
informix-query
informix-tables
ip-forwarding
ip-geolocation
ipidseq
ipv6-multicast-mld-query
irc-botnet-channels
irc-info
irc-unrealircd-backdoor
isns-info
jdwp-exec
jdwp-info
jdwp-inject
krb5-enum-users
ldap-novell-getpass
ldap-search
llmnr-resolve
lu-enum
metasploit-info
mmouse-exec
mrinfo
ms-sql-config
ms-sql-hasdbaccess
ms-sql-query
ms-sql-tables
ms-sql-xp-cmdshell
mtrace
murmur-version
mysql-audit
mysql-dump-hashes
mysql-enum
mysql-query
nat-pmp-info
nat-pmp-mapport
netbus-info
ntp-info
omp2-enum-targets
oracle-enum-users
ovs-agent-version
p2p-conficker
path-mtu
pjl-ready-message
port-states
quake1-info
quake3-info
quake3-master-getservers
qscan
resolveall
reverse-index
rpc-grind
rpcap-info
rsa-vuln-roca
rusers
shodan-api
sip-call-spoof
skypev2-version
smb-enum-domains
smb-flood
smb-ls
smb-print-text
smb-psexec
smb-vuln-conficker
smb-vuln-cve2009-3103
smb-vuln-ms06-025
smb-vuln-ms07-029
smb-vuln-ms08-067
smb-vuln-ms10-054
smb-vuln-regsvc-dos
smb-vuln-webexec
smb-webexec-exploit
smb2-vuln-uptime
sniffer-detect
snmp-ios-config
socks-open-proxy
sql-injection
ssh-auth-methods
ssh-hostkey
ssh-publickey-acceptance
ssh-run
stun-info
teamspeak2-version
targets
tftp-enum
tls-alpn
tls-ticketbleed
tn3270-info
tor-consensus-checker
traceroute-geolocation
unittest
unusual-port
upnp-info
url-snarf
ventrilo-info
vtam-enum
weblogic-t3-info
whois
xmlrpc-methods
xmpp-info
END_EXCLUDES

    # Available scripts
    find "$NMAP_SCRIPT_DIR" -maxdepth 1 -name '*.nse' -printf '%f\n' |
        sed 's/\.nse$//' |
        grep -Eiv '(broadcast|brute)' |
        grep -v -F -x -f /tmp/excludes_nmap.txt |
        sort -u > /tmp/avail_nmap.txt

    # Used scripts
    grep -E 'script=' "$DISCOVER/scan/nse.sh" 2>/dev/null |
        sed -E 's/.*script=([^#]*).*/\1/' |
        tr ',' '\n' |
        sed 's/^[[:space:]]*//; s/[[:space:]]*$//' |
        grep -v '^$' |
        sort -u > /tmp/used_nmap.txt

    # Output: Available but not used
    grep -vxFf /tmp/used_nmap.txt /tmp/avail_nmap.txt

    rm -f /tmp/excludes_nmap.txt /tmp/avail_nmap.txt /tmp/used_nmap.txt
    echo
fi

exit 0

