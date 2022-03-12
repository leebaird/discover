#!/usr/bin/bash

# Global variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for root
if [ $EUID -ne 0 ]; then
     echo
     echo "[!] This script must be ran as root."
     exit
fi

###############################################################################################################################

# Clean up

if [ -d /opt/BloodHound-v4/.git ]; then
     rm -rf /opt/BloodHound-v4/
fi

if [ -d /opt/droopescan/.git ]; then
     rm -rf /opt/droopescan/
fi

if [ -d /opt/EyeWitness/.git ]; then
     rm -rf /opt/EyeWitness/
fi

if [ -d /opt/spoofcheck/.git ]; then
     rm -rf /opt/spoofcheck/
fi

if [ -d /opt/unicorn/.git ]; then
     rm -rf /opt/unicorn/
fi

if [ -d /opt/Veil/.git ]; then
     rm -rf /opt/Veil/
fi

if [ -d /opt/WitnessMe/.git ]; then
     rm -rf /opt/WitnessMe/
fi

###############################################################################################################################

clear
echo

echo -e "${BLUE}Updating Kali.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean
echo

if [ ! -d /usr/share/doc/golang-go ]; then
     echo -e "${YELLOW}Installing Go.${NC}"
     apt install -y golang-go
     mv /root/go /opt/
     echo
fi

if [ ! -f /usr/bin/pip ]; then
     echo -e "${YELLOW}Installing Python pip.${NC}"
     apt install -y python3-pip
     echo
fi

if [ ! -f /usr/bin/virtualenv ]; then
     echo -e "${YELLOW}Installing Python Virtualenv.${NC}"
     apt install -y python3-virtualenv
     echo
fi

if [ ! -f /usr/bin/amass ]; then
     echo -e "${YELLOW}Installing Amass.${NC}"
     apt install -y amass
     echo
fi

if [ ! -f /usr/bin/bloodhound ]; then
     echo -e "${YELLOW}Installing BloodHound and Neo4j.${NC}"
     apt install -y bloodhound
     echo
fi

if [ -d /opt/cobaltstrike ]; then
     echo -e "${BLUE}Updating Cobalt Strike.${NC}"
     cd /opt/cobaltstrike ; ./update
     echo

     if [ -d /opt/cobaltstrike/third-party/chryzsh-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - chryzsh.${NC}"
          cd /opt/cobaltstrike/third-party/chryzsh-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - chryzsh.${NC}"
          git clone https://github.com/chryzsh/Aggressor-Scripts /opt/cobaltstrike/third-party/chryzsh-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/mgeeky-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - mgeeky.${NC}"
          cd /opt/cobaltstrike/third-party/mgeeky-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - mgeeky.${NC}"
          git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/third-party/mgeeky-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/taowu-scripts/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike aggressor scripts - taowu.${NC}"
          cd /opt/cobaltstrike/third-party/taowu-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike aggressor scripts - taowu.${NC}"
          git clone https://github.com/pandasec888/taowu-cobalt-strike /opt/cobaltstrike/third-party/taowu-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/trustedsec-bof/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike BOF - trustedsec.${NC}"
          cd /opt/cobaltstrike/third-party/trustedsec-bof/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike BOF - trustedsec.${NC}"
          git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/cobaltstrike/third-party/trustedsec-bof
          echo
     fi

     if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike ElevateKit.${NC}"
          cd /opt/cobaltstrike/elevatekit/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike ElevateKit.${NC}"
          git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
          echo
     fi

     if [ -d /opt/cobaltstrike/malleable-c2-profiles/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike Malleable C2 profiles.${NC}"
          cd /opt/cobaltstrike/malleable-c2-profiles/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike Malleable C2 profiles.${NC}"
          git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles /opt/cobaltstrike/malleable-c2-profiles
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - bluescreenofjeff.${NC}"
          cd /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - bluescreenofjeff.${NC}"
          git clone https://github.com/bluscreenofjeff/Malleable-C2-Randomizer /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - DidierStevens.${NC}"
          cd /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/ ; git pull
          mv cs-dns-stager.py cs-dns-stager.tmp
          rm *.def *.md *.py *.txt *.yaml 2>/dev/null
          mv cs-dns-stager.tmp cs-dns-stager.py
          chmod 755 cs-dns-stager.py
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - DidierStevens.${NC}"
          git clone https://github.com/DidierStevens/Beta /opt/cobaltstrike/third-party/DidierStevens-DNS-stager
          cd /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/
          mv cs-dns-stager.py cs-dns-stager.tmp
          rm *.def *.md *.py *.txt *.yaml 2>/dev/null
          mv cs-dns-stager.tmp cs-dns-stager.py
          chmod 755 cs-dns-stager.py
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - FortyNorthSecurity.${NC}"
          cd /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - FortyNorthSecurity.${NC}"
          git clone https://github.com/FortyNorthSecurity/C2concealer /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/outflanknl-helpcolor/.git ]; then
          echo -e "${BLUE}Updating Cobalt Strike misc - outflanknl.${NC}"
          cd /opt/cobaltstrike/third-party/outflanknl-helpcolor/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing Cobalt Strike misc - outflanknl.${NC}"
          git clone https://github.com/outflanknl/HelpColor /opt/cobaltstrike/third-party/outflanknl-helpcolor
          echo
     fi
fi

if [ -d /opt/discover/.git ]; then
     echo -e "${BLUE}Updating Discover.${NC}"
     cd /opt/discover ; git pull
     echo
fi

if [ -d /opt/DNSRecon/.git ]; then
     echo -e "${BLUE}Updating DNSRecon.${NC}"
     cd /opt/DNSRecon/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing DNSRecon.${NC}"
     git clone https://github.com/darkoperator/dnsrecon /opt/DNSRecon
     echo
fi

if [ -d /opt/dnstwist/.git -a -d /opt/dnstwist-venv ]; then
     echo -e "${BLUE}Updating dnstwist.${NC}"
     cd /opt/dnstwist/ ; git pull
     source /opt/dnstwist-venv/bin/activate
     pip3 install .
     deactivate
     echo
else
     echo -e "${YELLOW}Installing dnstwist.${NC}"
     git clone https://github.com/elceef/dnstwist /opt/dnstwist
     echo
     echo -e "${YELLOW}Setting up dnstwist virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/dnstwist-venv
     source /opt/dnstwist-venv/bin/activate
     cd /opt/dnstwist/
     pip3 install .
     deactivate
     echo
fi

if [ -d /opt/Domain-Hunter/.git ]; then
     echo -e "${BLUE}Updating Domain Hunter.${NC}"
     cd /opt/Domain-Hunter/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Domain Hunter.${NC}"
     git clone https://github.com/threatexpress/domainhunter /opt/Domain-Hunter
     cd /opt/Domain-Hunter/
     pip3 install pytesseract
     chmod 755 domainhunter.py
     echo
fi

if [ -d /opt/DomainPasswordSpray/.git ]; then
     echo -e "${BLUE}Updating DomainPasswordSpray.${NC}"
     cd /opt/DomainPasswordSpray/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing DomainPasswordSpray.${NC}"
     git clone https://github.com/dafthack/DomainPasswordSpray /opt/DomainPasswordSpray
     echo
fi

if [ -d /opt/Donut/.git ]; then
     echo -e "${BLUE}Updating Donut.${NC}"
     cd /opt/Donut/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Donut.${NC}"
     git clone https://github.com/TheWover/donut /opt/Donut
     echo
fi

#if [ -d /opt/Egress-Assess/.git ]; then
#     echo -e "${BLUE}Updating Egress-Assess.${NC}"
#     cd /opt/Egress-Assess/ ; git pull
#     echo
#else
#     echo -e "${YELLOW}Installing Egress-Assess.${NC}"
#     git clone https://github.com/ChrisTruncer/Egress-Assess /opt/Egress-Assess
#     cd /opt/Egress-Assess/setup/
#     ./setup.sh
#     mv server.pem ../Egress-Assess/
#     rm impacket*
#     echo
#fi

if [ -d /opt/egressbuster/.git ]; then
     echo -e "${BLUE}Updating egressbuster.${NC}"
     cd /opt/egressbuster/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing egressbuster.${NC}"
     git clone https://github.com/trustedsec/egressbuster /opt/egressbuster
     echo
fi

if [ -d /opt/gobuster/.git ]; then
     echo -e "${BLUE}Updating gobuster.${NC}"
     cd /opt/gobuster/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing gobuster.${NC}"
     git clone https://github.com/OJ/gobuster.git /opt/gobuster
     cd /opt/gobuster/
     go get && go build
     make
     echo
fi

if [ -d /opt/krbrelayx/.git ]; then
     echo -e "${BLUE}Updating krbrelayx.${NC}"
     cd /opt/krbrelayx/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing krbrelayx.${NC}"
     git clone https://github.com/dirkjanm/krbrelayx /opt/krbrelayx
     echo
fi

if [ ! -f /usr/bin/xmllint ]; then
     echo -e "${YELLOW}Installing libxml2-utils.${NC}"
     apt-get install -y libxml2-utils
fi

if [ -d /opt/Nishang/.git ]; then
     echo -e "${BLUE}Updating Nishang.${NC}"
     cd /opt/Nishang/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Nishang.${NC}"
     git clone https://github.com/samratashok/nishang /opt/Nishang
     echo
fi

echo -e "${BLUE}Updating Nmap scripts.${NC}"
nmap --script-updatedb | egrep -v '(Starting|seconds)' | sed 's/NSE: //'
echo

if [ -d /opt/PEASS-ng/.git ]; then
     echo -e "${BLUE}Updating PEASS-ng.${NC}"
     cd /opt/PEASS-ng/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PEASS-ng.${NC}"
     git clone https://github.com/carlospolop/PEASS-ng /opt/PEASS-ng
     echo
fi

if [ -d /opt/PowerUpSQL/.git ]; then
     echo -e "${BLUE}Updating PowerUpSQL.${NC}"
     cd /opt/PowerUpSQL/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerUpSQL.${NC}"
     git clone https://github.com/NetSPI/PowerUpSQL /opt/PowerUpSQL
     echo
fi

if [ -d /opt/PrivescCheck/.git ]; then
     echo -e "${BLUE}Updating PrivescCheck.${NC}"
     cd /opt/PrivescCheck/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PrivescCheck.${NC}"
     git clone https://github.com/itm4n/PrivescCheck /opt/PrivescCheck
     echo
fi

if [ -d /opt/Responder/.git ]; then
     echo -e "${BLUE}Updating Responder.${NC}"
     cd /opt/Responder/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Responder.${NC}"
     git clone https://github.com/lgandx/Responder /opt/Responder
     echo
fi

if [ -d /opt/SecLists/.git ]; then
     echo -e "${BLUE}Updating SecLists.${NC}"
     cd /opt/SecLists/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing SecLists.${NC}"
     git clone https://github.com/danielmiessler/SecLists /opt/SecLists
     echo
fi

if [ -d /opt/SharpCollection/.git ]; then
     echo -e "${BLUE}Updating SharpCollection.${NC}"
     cd /opt/SharpCollection/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing SharpCollection.${NC}"
     git clone https://github.com/Flangvik/SharpCollection /opt/SharpCollection
     echo
fi

if [ -d /opt/SprayingToolkit/.git -a -d /opt/SprayingToolkit-venv ]; then
     echo -e "${BLUE}Updating SprayingToolkit.${NC}"
     cd /opt/SprayingToolkit/ ; git pull
     source /opt/SprayingToolkit-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing SprayingToolkit.${NC}"
     git clone https://github.com/byt3bl33d3r/SprayingToolkit /opt/SprayingToolkit
     echo
     echo -e "${YELLOW}Setting up SprayingToolkit virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/SprayingToolkit-venv
     source /opt/SprayingToolkit-venv/bin/activate
     cd /opt/SprayingToolkit/
     apt install -y libxml2-dev libxslt-dev
     pip3 install -r requirements.txt
     deactivate
     echo
fi

if [ -d /opt/theHarvester/.git -a -d /opt/theHarvester-venv ]; then
     echo -e "${BLUE}Updating theHarvester.${NC}"
     cd /opt/theHarvester/ ; git pull
     source /opt/theHarvester-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing theHarvester.${NC}"
     git clone https://github.com/laramies/theHarvester /opt/theHarvester
     echo
     echo -e "${YELLOW}Setting up theHarvester virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/theHarvester-venv
     source /opt/theHarvester-venv/bin/activate
     cd /opt/theHarvester/
     pip3 install -r requirements.txt
     deactivate
     echo
fi

if [ ! -f /usr/lib/python3/dist-packages/texttable.py ]; then
     echo -e "${YELLOW}Installing Texttable.${NC}"
     apt install -y python3-texttable
     echo
fi

if [ ! -f /usr/bin/veil ]; then
     echo -e "${YELLOW}Installing Veil.${NC}"
     apt install -y veil
     echo
fi

if [ -d /opt/Windows-Exploit-Suggester-NG/.git ]; then
     echo -e "${BLUE}Updating Windows Exploit Suggester NG.${NC}"
     cd /opt/Windows-Exploit-Suggester-NG/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Windows Exploit Suggester NG.${NC}"
     git clone https://github.com/bitsadmin/wesng /opt/Windows-Exploit-Suggester-NG
     echo
fi

if [ ! -f /usr/bin/xdotool ]; then
     echo -e "${YELLOW}Installing xdotool.${NC}"
     apt-get install -y xdotool
     echo
fi

if [ ! -f /usr/bin/xlsx2csv ]; then
     echo -e "${YELLOW}Installing xlsx2csv.${NC}"
     apt-get install -y xlsx2csv
     echo
fi

if [ ! -f /usr/bin/xml_grep ]; then
     echo -e "${YELLOW}Installing xml_grep.${NC}"
     apt-get install -y xml-twig-tools
     echo
fi

if [ -d /opt/xspy/.git ]; then
     echo -e "${BLUE}Updating xspy.${NC}"
     cd /opt/xspy/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing xspy.${NC}"
     git clone https://github.com/mnp/xspy /opt/xspy
     cd /opt/xspy/
     apt install -y build-essential libx11-dev
     apt install -y x11-utils xutils-dev imagemagick libxext-dev
     make
     echo
fi

if [ -d /opt/xwatchwin/.git ]; then
     echo -e "${BLUE}Updating xwatchwin.${NC}"
     cd /opt/xwatchwin/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing xwatchwin.${NC}"
     apt install -y imagemagick libxext-dev xutils-dev
     wget http://www.ibiblio.org/pub/X11/contrib/utilities/xwatchwin.tar.gz
     tar zxvf xwatchwin.tar.gz
     rm xwatchwin.tar.gz
     mv xwatchwin/ /opt/
     cd /opt/xwatchwin/
     xmkmf && make && make install
     echo
fi

cd /root/

echo -e "${BLUE}Updating locate database.${NC}"
updatedb

exit

