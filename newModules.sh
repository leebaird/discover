#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

BLUE='\033[1;34m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

###############################################################################################################################

echo
echo -e "${YELLOW}Things that need to be added${NC}"
echo

###############################################################################################################################

if [ -d /usr/share/metasploit-framework ]; then
    echo
    echo -e "${BLUE}Metasploit modules available but not used in resource/*.rc files${NC}"
    echo -e "${BLUE}=================================================================${NC}"

    # Categories to scan (excluding http and sap as noted)
    CATEGORIES="afp backdoor chargen couchdb db2 dcerpc dect discovery emc finger ftp h323 imap ip ipmi lotus misc mongodb motorola msf mssql mysql natpmp nessus netbios nexpose nfs ntp openvas oracle pcanywhere pop3 portscan postgres printer rdp rogue rservices scada sip smb smtp snmp ssh telephony telnet tftp upnp vmware vnc voice vxworks winrm x11"

    # List all available Metasploit scanner modules with category prefix
    for i in $CATEGORIES; do
        ls -l /usr/share/metasploit-framework/modules/auxiliary/scanner/$i | awk -v cat="$i" '{print cat "/" $9}' | cut -d '.' -f1 >> tmp-msf-all
    done

    # Remove empty lines and apply exclusions
    sed '/^$/d' tmp-msf-all | grep -Eiv '(ack|apache_karaf_command_execution|arp_sweep|call_scanner|cerberus_sftp_enumusers|cisco_smart_install|couchdb_enum|dvr_config_disclosure|empty_udp|endpoint_mapper|ftpbounce|hidden|ibm_mq_channel_brute|indusoft_ntwebserver_fileaccess|ipidseq|ipv6|login|lotus_domino_hashes|lotus_domino_version|management|ms08_067_check|mysql_file_enum|mssql_hashdump|mysql_schemadump|mysql_writable_dirs|natpmp_portscan|poisonivy_control_scanner|profinet_siemens|psexec_loggedin_users|recorder|rogue_recv|rogue_send|sipdroid_ext_enum|snmp_set|ssh_enum_git_keys|ssh_enumusers|ssh_identify_pubkeys|station_scanner|syn|tcp|tftpbrute|udp_probe|udp_sweep|vmware_enum_users|vmware_enum_permissions|vmware_enum_sessions|vmware_enum_vms|vmware_host_details|vmware_screenshot_stealer|wardial|winrm_cmd|winrm_wql|xmas)' | sort > tmp-msf-all-clean

    # Extract modules used in .rc files starting with a number, http, or java, keeping category/module format
    grep 'use ' "$PWD"/resource/[0-9hj]*.rc | awk '{print $2}' | sed 's/auxiliary\/scanner\///' | sort -u > tmp-msf-used

    # List Metasploit modules available but not used in resource/*.rc files, filtering out empty categories
    grep -vxFf tmp-msf-used tmp-msf-all-clean | grep -v '/$' | sort

    # Clean up temporary files
    rm tmp-msf-all tmp-msf-all-clean tmp-msf-used
fi

###############################################################################################################################

echo
echo -e "${BLUE}theHarvester modules available for passive.sh${NC}"
echo -e "${BLUE}==============================================${NC}"

# List theHarvester modules
grep "            '" $HOME/theHarvester/theHarvester/lib/core.py | grep -Eiv 'mozilla|ssl_arg' | cut -d "'" -f2 > tmp

# Extract modules used in passive.sh
#grep '\-d "' "$HOME"/discover/passive.sh | awk '{print $5}' | sed '1,3d; s/|/shodan/' > tmp2
grep 'sources_' "$HOME"/discover/passive.sh | grep -v '\@' | cut -d '(' -f2 | cut -d ')' -f1 | sed 's/ /\n/g' | sort > tmp2

# List theHarvester modules available but not used in passive.sh
grep -vxFf tmp2 tmp | sort

# Clean up temporary files
rm tmp tmp2

###############################################################################################################################

NMAP_SCRIPT_DIR="/usr/share/nmap/scripts"

# Scripts to exclude
mapfile -t EXCLUDES < <(cat <<'END_EXCLUDES'
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
)

# All scripts less broadcast, brute, and excludes list
find "$NMAP_SCRIPT_DIR" -maxdepth 1 -name '*.nse' -printf '%f\n' | sed 's/\.nse$//' | grep -Eiv 'broadcast|brute' \
  | grep -v -F -x -f <(printf '%s\n' "${EXCLUDES[@]}") | sort > tmp-available.txt

# Scripts used in nse.sh
grep -E 'script=' nse.sh | sed -E 's/.*script=([^#]*).*/\1/' | tr ',' '\n' \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' | sort -u > tmp-used.txt

echo
echo -e "${BLUE}Nmap scripts available for nse.sh${NC}"
echo -e "${BLUE}==================================${NC}"
comm -23 tmp-available.txt tmp-used.txt
echo

# Clean up temporary files
rm tmp-available.txt tmp-used.txt

