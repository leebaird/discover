#!/usr/bin/bash

# Global variables
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m'

# Check for root
if [ $EUID -ne 0 ]; then
     echo
     echo "[!] This script must be ran as root."
     exit
fi

# -----------------------------------------------------------------------------------------------

# Clean up
if [ -d /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/.git ]; then
     rm -rf /opt/cobaltstrike/third-party/bluescreenofjeff-malleable-c2-randomizer/
fi

if [ -d /opt/cobaltstrike/third-party/chryzsh-scripts/.git ]; then
     rm -rf /opt/cobaltstrike/third-party/chryzsh-scripts/
fi

if [ -d /opt/cobaltstrike/third-party/bokuloader/.git ]; then
     rm -rf /opt/cobaltstrike/third-party/bokuloader/
fi

if [ -d /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/.git ]; then
     rm -rf /opt/cobaltstrike/third-party/DidierStevens-DNS-stager/
fi

if [ -d /opt/cobaltstrike/third-party/trustedsec-bof/  ]; then
     rm -rf /opt/cobaltstrike/third-party/trustedsec-bof/
fi

if [ -d /opt/cobaltstrike/third-party/taowu-scripts/.git ]; then
     rm -rf /opt/cobaltstrike/third-party/taowu-scripts/
fi

# -----------------------------------------------------------------------------------------------

clear
echo

echo -e "${BLUE}Updating Kali.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean
echo

if [ ! -f /usr/bin/ansible ]; then
     echo -e "${YELLOW}Installing Ansible.${NC}"
     apt install -y ansible
     echo
fi

if [ ! -f /usr/bin/aws ]; then
     echo -e "${YELLOW}Installing AWS.${NC}"
     apt install -y awscli
     echo
fi

if [ ! -f /usr/bin/bloodhound ]; then
     echo -e "${YELLOW}Installing BloodHound and Neo4j.${NC}"
     apt install -y bloodhound
     echo
fi

if [ ! -f /usr/bin/go ]; then
     echo -e "${YELLOW}Installing Go.${NC}"
     apt install -y golang-go
     echo >> ~/.zshrc
     echo 'export GOPATH=/opt/go/' >> ~/.zshrc
     echo
     mv /root/go/ /opt/
fi

if [ -d /opt/cobaltstrike ]; then
     if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
          echo -e "${BLUE}Updating CS - ElevateKit.${NC}"
          cd /opt/cobaltstrike/elevatekit/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - ElevateKit.${NC}"
          git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/.git ]; then
          echo -e "${BLUE}Updating CS - FortyNorthSecurity C2concealer.${NC}"
          cd /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - FortyNorthSecurity C2concealer.${NC}"
          git clone https://github.com/FortyNorthSecurity/C2concealer /opt/cobaltstrike/third-party/FortyNorthSecurity-C2concealer
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/kyleavery-inject-assembly/.git ]; then
          echo -e "${BLUE}Updating CS - kyleavery Inject Assembly.${NC}"
          cd /opt/cobaltstrike/third-party/kyleavery-inject-assembly/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - kyleavery Inject Assembly.${NC}"
          git clone https://github.com/kyleavery/inject-assembly /opt/cobaltstrike/third-party/kyleavery-inject-assembly
          echo
     fi

     if [ -d /opt/cobaltstrike/malleable-c2-profiles/.git ]; then
          echo -e "${BLUE}Updating CS - Malleable C2 profiles.${NC}"
          cd /opt/cobaltstrike/malleable-c2-profiles/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Malleable C2 profiles.${NC}"
          git clone https://github.com/Cobalt-Strike/Malleable-C2-Profiles /opt/cobaltstrike/malleable-c2-profiles
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/mgeeky-scripts/.git ]; then
          echo -e "${BLUE}Updating CS - mgeeky cobalt arsenal.${NC}"
          cd /opt/cobaltstrike/third-party/mgeeky-scripts/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - mgeeky cobalt arsenal.${NC}"
          git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/third-party/mgeeky-scripts
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/outflanknl-c2-tool-collection/.git ]; then
          echo -e "${BLUE}Updating CS - Outflanknl C2 Tool Collection.${NC}"
          cd /opt/cobaltstrike/third-party/outflanknl-c2-tool-collection/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Outflanknl C2 Tool Collection.${NC}"
          git clone https://github.com/outflanknl/C2-Tool-Collection /opt/cobaltstrike/third-party/outflanknl-c2-tool-collection
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/outflanknl-helpcolor/.git ]; then
          echo -e "${BLUE}Updating CS - Outflanknl HelpColor.${NC}"
          cd /opt/cobaltstrike/third-party/outflanknl-helpcolor/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Outflanknl HelpColor.${NC}"
          git clone https://github.com/outflanknl/HelpColor /opt/cobaltstrike/third-party/outflanknl-helpcolor
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/trustedsec-remote-ops/.git ]; then
          echo -e "${BLUE}Updating CS - TrustedSec CS Remote OPs BOF.${NC}"
          cd /opt/cobaltstrike/third-party/trustedsec-remote-ops/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - TrustedSec CS Remote OPs BOF.${NC}"
          git clone https://github.com/trustedsec/CS-Remote-OPs-BOF /opt/cobaltstrike/third-party/trustedsec-remote-ops
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/trustedsec-sa/.git ]; then
          echo -e "${BLUE}Updating CS - TrustedSec Situational Awareness BOF.${NC}"
          cd /opt/cobaltstrike/third-party/trustedsec-sa/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - TrustedSec Situational Awareness BOF.${NC}"
          git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/cobaltstrike/third-party/trustedsec-sa
          echo
     fi

     if [ -d /opt/cobaltstrike/third-party/tylous-sourcepoint/.git ]; then
          echo -e "${BLUE}Updating CS - Tylous SourcePoint.${NC}"
          cd /opt/cobaltstrike/third-party/tylous-sourcepoint/ ; git pull
          echo
     else
          echo -e "${YELLOW}Installing CS - Tylous SourcePoint.${NC}"
          git clone https://github.com/Tylous/SourcePoint /opt/cobaltstrike/third-party/tylous-sourcepoint
          cd /opt/cobaltstrike/third-party/tylous-sourcepoint/
          go get gopkg.in/yaml.v2
          go build SourcePoint.go
          echo
     fi
fi

if [ -d /opt/discover/.git ]; then
     echo -e "${BLUE}Updating Discover.${NC}"
     cd /opt/discover ; git pull
     echo
fi

if [ -d /opt/DNSRecon/.git -a -d /opt/DNSRecon-venv ]; then
     echo -e "${BLUE}Updating DNSRecon.${NC}"
     cd /opt/DNSRecon/ ; git pull
     source /opt/DNSRecon-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
     # If you are in a corp env that is doing MITM with SSL use the following line instead.
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing DNSRecon.${NC}"
     git clone https://github.com/darkoperator/dnsrecon /opt/DNSRecon
     echo
     echo -e "${YELLOW}Setting up DNSRecon virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/DNSRecon-venv
     source /opt/DNSRecon-venv/bin/activate
     cd /opt/DNSRecon/
     pip3 install -r requirements.txt
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
     deactivate
     echo
fi

if [ ! -f /usr/bin/dnstwist ]; then
     echo -e "${YELLOW}Installing dnstwist.${NC}"
     apt install -y dnstwist
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

if [ -d /opt/Egress-Assess/.git -a -d /opt/Egress-Assess-venv ]; then
     echo -e "${BLUE}Updating Egress-Assess.${NC}"
     cd /opt/Egress-Assess/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Egress-Assess.${NC}"
     git clone https://github.com/ChrisTruncer/Egress-Assess /opt/Egress-Assess
     echo
     echo -e "${YELLOW}Setting up Egress-Assess virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/Egress-Assess-venv
     source /opt/Egress-Assess-venv/bin/activate
     cd /opt/Egress-Assess
     pip3 install -r requirements.txt
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
     deactivate
     echo
fi

if [ -d /opt/egressbuster/.git ]; then
     echo -e "${BLUE}Updating egressbuster.${NC}"
     cd /opt/egressbuster/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing egressbuster.${NC}"
     git clone https://github.com/trustedsec/egressbuster /opt/egressbuster
     echo
fi

if [ ! -f /usr/bin/feroxbuster ]; then
     echo -e "${YELLOW}Installing feroxbuster.${NC}"
     apt install -y feroxbuster
     echo
fi

if [ -d /opt/Freeze/.git ]; then
     echo -e "${BLUE}Updating Freeze.${NC}"
     cd /opt/Freeze/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Freeze.${NC}"
     git clone https://github.com/optiv/Freeze /opt/Freeze
     echo
fi

if [ ! -f /usr/bin/gobuster ]; then
     echo -e "${YELLOW}Installing gobuster.${NC}"
     apt install -y gobuster
     echo
fi

if [ -d /opt/Havoc/.git ]; then
     echo -e "${BLUE}Updating Havoc.${NC}"
     cd /opt/Havoc/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing Havoc.${NC}"
     git clone https://github.com/HavocFramework/Havoc /opt/Havoc
     apt install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm
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

if [ ! -f /usr/bin/nishang ]; then
     echo -e "${YELLOW}Installing nishang.${NC}"
     apt install -y nishang
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

if [ -d /opt/PowerSharpPack/.git ]; then
     echo -e "${BLUE}Updating PowerSharpPack.${NC}"
     cd /opt/PowerSharpPack/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerSharpPack.${NC}"
     git clone https://github.com/S3cur3Th1sSh1t/PowerSharpPack /opt/PowerSharpPack
     echo
fi

if [ -d /opt/PowerSploit/.git ]; then
     echo -e "${BLUE}Updating PowerSploit.${NC}"
     cd /opt/PowerSploit/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing PowerSploit.${NC}"
     git clone https://github.com/0xe7/PowerSploit /opt/PowerSploit
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

if [ ! -f /usr/share/wordlists/rockyou.txt ]; then
     echo -e "${YELLOW}Expanding Rockyou list.${NC}"
     zcat /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
     rm /usr/share/wordlists/rockyou.txt.gz
     echo
fi

if [ ! -f /usr/bin/rustc ]; then
     echo -e "${YELLOW}Installing Rust.${NC}"
     apt install -y rustc
     echo
fi

if [ ! -d /usr/share/seclists ]; then
     echo -e "${YELLOW}Installing SecLists.${NC}"
     apt install -y seclists
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

if [ -d /opt/spoofcheck/.git -a -d /opt/spoofcheck-venv ]; then
     echo -e "${BLUE}Updating spoofcheck.${NC}"
     cd /opt/spoofcheck/ ; git pull
     source /opt/spoofcheck-venv/bin/activate
     pip3 install -r requirements.txt --upgrade
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade
     deactivate
     echo
else
     echo -e "${YELLOW}Installing spoofcheck.${NC}"
     git clone https://github.com/BishopFox/spoofcheck /opt/spoofcheck
     echo
     echo -e "${YELLOW}Setting up spoofcheck virtualenv.${NC}"
     virtualenv -p /usr/bin/python3 /opt/spoofcheck-venv
     source /opt/spoofcheck-venv/bin/activate
     cd /opt/spoofcheck/
     pip3 install -r requirements.txt
#     pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
     deactivate
     echo
fi

if [ -d /opt/subfinder/.git ]; then
     echo -e "${BLUE}Updating subfinder.${NC}"
     cd /opt/subfinder/ ; git pull
     echo
else
     echo -e "${YELLOW}Installing subfinder.${NC}"
     git clone https://github.com/projectdiscovery/subfinder /opt/subfinder
     cd /opt/subfinder/v2/cmd/subfinder
     go build
     echo
fi

if [ -d /opt/theHarvester/.git -a -d /opt/theHarvester-venv ]; then
     echo -e "${BLUE}Updating theHarvester.${NC}"
     cd /opt/theHarvester/ ; git pull
     source /opt/theHarvester-venv/bin/activate
     /opt/theHarvester-venv/bin/pip3 install -r requirements.txt --upgrade
#     /opt/theHarvester-venv/bin/pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade
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
     /opt/theHarvester-venv/bin/pip3 install -r requirements.txt
#     /opt/theHarvester-venv/bin/pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
     deactivate
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

if [ ! -f /usr/bin/xspy ]; then
     echo -e "${YELLOW}Installing xspy.${NC}"
     apt install -y xspy
     echo
fi

if [ ! -f /opt/xwatchwin/xwatchwin ]; then
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

echo -e "${BLUE}Updating locate database.${NC}"
updatedb

exit
