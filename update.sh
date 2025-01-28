#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Global variables
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# -----------------------------------------------------------------------------------------------

# Clean up deprecated repos

# -----------------------------------------------------------------------------------------------

echo
echo -e "${BLUE}Updating operating system.${NC}"
apt update ; apt -y upgrade ; apt -y dist-upgrade ; apt -y autoremove ; apt -y autoclean ; updatedb
echo

if ! command -v ansible &> /dev/null; then
    echo -e "${YELLOW}Installing Ansible.${NC}"
    apt install -y ansible-core
    echo
fi

if ! command -v aws &> /dev/null; then
    echo -e "${YELLOW}Installing AWS.${NC}"
    apt install -y awscli
    echo
fi

if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}Installing Go.${NC}"
    apt install -y golang-go
    echo "" >> ~/.zshrc
    echo "export GOPATH=/opt/go" >> ~/.zshrc
    echo "export GOROOT=/usr/lib/go" >> ~/.zshrc
    echo "export PATH=\$PATH:/usr/lib/go/bin:/opt/go/bin" >> ~/.zshrc
    mkdir -p /opt/go/{bin,src,pkg}
    source ~/.zshrc
    echo
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}Installing jq.${NC}"
    apt install -y jq
    echo
fi

if ! command -v raven &> /dev/null; then
    echo -e "${YELLOW}Installing Raven.${NC}"
    apt install -y raven
    echo
fi

if ! command -v sublist3r &> /dev/null; then
    echo -e "${YELLOW}Installing Sublist3r.${NC}"
    apt install -y sublist3r
    echo
fi

# -----------------------------------------------------------------------------------------------

if [ -d /opt/BOFs/anthemtotheego-inlineExecute-assembly/.git ]; then
    echo -e "${BLUE}Updating anthemtotheego InlineExecute Assembly BOF.${NC}"
    cd /opt/BOFs/anthemtotheego-inlineExecute-assembly/ ; git pull
    echo
else
    echo -e "${YELLOW}Installing anthemtotheego InlineExecute Assembly BOF.${NC}"
    git clone https://github.com/anthemtotheego/InlineExecute-Assembly /opt/BOFs/anthemtotheego-inlineExecute-assembly
    echo
fi

if [ -d /opt/BOFs/outflanknl-c2-tool-collection/.git ]; then
    echo -e "${BLUE}Updating Outflanknl C2 Tool Collection BOF.${NC}"
    cd /opt/BOFs/outflanknl-c2-tool-collection/ ; git pull
    echo
else
    echo -e "${YELLOW}Installing Outflanknl C2 Tool Collection BOF.${NC}"
    git clone https://github.com/outflanknl/C2-Tool-Collection /opt/BOFs/outflanknl-c2-tool-collection
    echo
fi

if [ -d /opt/BOFs/outflanknl-helpcolor/.git ]; then
    echo -e "${BLUE}Updating Outflanknl HelpColor BOF.${NC}"
    cd /opt/BOFs/outflanknl-helpcolor/ ; git pull
    echo
else
    echo -e "${YELLOW}Installing Outflanknl HelpColor BOF.${NC}"
    git clone https://github.com/outflanknl/HelpColor /opt/BOFs/outflanknl-helpcolor
    echo
fi

if [ -d /opt/BOFs/trustedsec-remote-ops/.git ]; then
    echo -e "${BLUE}Updating TrustedSec Remote OPs BOF.${NC}"
    cd /opt/BOFs/trustedsec-remote-ops/ ; git pull
    echo
else
    echo -e "${YELLOW}Installing TrustedSec Remote OPs BOF.${NC}"
    git clone https://github.com/trustedsec/CS-Remote-OPs-BOF /opt/BOFs/trustedsec-remote-ops
    echo
fi

if [ -d /opt/BOFs/trustedsec-sa/.git ]; then
    echo -e "${BLUE}Updating TrustedSec Situational Awareness BOF.${NC}"
    cd /opt/BOFs/trustedsec-sa/ ; git pull
    echo
else
    echo -e "${YELLOW}Installing TrustedSec Situational Awareness BOF.${NC}"
    git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF /opt/BOFs/trustedsec-sa
    echo
fi

# -----------------------------------------------------------------------------------------------

if [ -d /opt/cobaltstrike/ ]; then
    if [ -d /opt/cobaltstrike/elevatekit/.git ]; then
        echo -e "${BLUE}Updating CS - ElevateKit.${NC}"
        cd /opt/cobaltstrike/elevatekit/ ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - ElevateKit.${NC}"
        git clone https://github.com/rsmudge/ElevateKit /opt/cobaltstrike/elevatekit
        echo
    fi

    if [ -d /opt/cobaltstrike/RedSiege-C2concealer/.git ]; then
        echo -e "${BLUE}Updating CS - RedSiege C2concealer.${NC}"
        cd /opt/cobaltstrike/RedSiege-C2concealer/ ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - RedSiege C2concealer.${NC}"
        git clone https://github.com/RedSiege/C2concealer /opt/cobaltstrike/RedSiege-C2concealer
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

    if [ -d /opt/cobaltstrike/mgeeky-scripts/.git ]; then
        echo -e "${BLUE}Updating CS - mgeeky cobalt arsenal.${NC}"
        cd /opt/cobaltstrike/mgeeky-scripts/ ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - mgeeky cobalt arsenal.${NC}"
        git clone https://github.com/mgeeky/cobalt-arsenal /opt/cobaltstrike/mgeeky-scripts
    echo
    fi

    if [ -d /opt/cobaltstrike/tylous-sourcepoint/.git ]; then
        echo -e "${BLUE}Updating CS - Tylous SourcePoint.${NC}"
        cd /opt/cobaltstrike/tylous-sourcepoint/ ; git pull
        echo
    else
        echo -e "${YELLOW}Installing CS - Tylous SourcePoint.${NC}"
        git clone https://github.com/Tylous/SourcePoint /opt/cobaltstrike/tylous-sourcepoint
        cd /opt/cobaltstrike/tylous-sourcepoint/
        go get gopkg.in/yaml.v2
        go build SourcePoint.go
        echo
    fi
fi

# -----------------------------------------------------------------------------------------------

if [ -d /opt/discover/.git ]; then
    echo -e "${BLUE}Updating Discover.${NC}"
    cd /opt/discover ; git pull
    echo
fi

if ! command -v dnstwist &> /dev/null; then
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
    echo
    echo -e "${YELLOW}Setting up Domain Hunter virtual environment.${NC}"
    python3 -m venv /opt/Domain-Hunter-venv
    /opt/Domain-Hunter-venv/bin/python -m pip install pytesseract
#    /opt/Domain-Hunter-venv/bin/pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org pytesseract
    chmod 755 /opt/Domain-Hunter/domainhunter.py
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
    git clone https://github.com/RedSiege/Egress-Assess /opt/Egress-Assess
    echo
    echo -e "${YELLOW}Setting up Egress-Assess virtualenv.${NC}"
    python3 -m venv /opt/Egress-Assess-venv
    /opt/Egress-Assess-venv/bin/python -m pip install -r /opt/Egress-Assess/requirements.txt
    # If you are in a corp env that is doing MITM with SSL, use the following line instead. Do the same for all Python repos.
#    pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade | grep -v 'already satisfied'
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

if ! command -v feroxbuster &> /dev/null; then
    echo -e "${YELLOW}Installing feroxbuster.${NC}"
    apt install -y feroxbuster
    echo
fi

if ! command -v gobuster &> /dev/null; then
    echo -e "${YELLOW}Installing gobuster.${NC}"
    apt install -y gobuster
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

if [ -d /opt/manspider/.git ]; then
    echo -e "${BLUE}Updating MAN-SPIDER.${NC}"
    cd /opt/manspider/ ; git pull
    echo
else
    echo -e "${YELLOW}Installing MAN-SPIDER.${NC}"
    git clone https://github.com/blacklanternsecurity/MANSPIDER /opt/manspider
    apt install -y antiword tesseract-ocr
    echo
fi

if ! command -v nishang &> /dev/null; then
    echo -e "${YELLOW}Installing nishang.${NC}"
    apt install -y nishang
    echo
fi

echo -e "${BLUE}Updating Nmap scripts.${NC}"
nmap --script-updatedb | grep -Eiv '(starting|seconds)' | sed 's/NSE: //'
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

if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then
    echo -e "${YELLOW}Expanding Rockyou list.${NC}"
    zcat /usr/share/wordlists/rockyou.txt.gz > /usr/share/wordlists/rockyou.txt
    rm /usr/share/wordlists/rockyou.txt.gz
    echo
fi

if ! command -v rustc &> /dev/null; then
    echo -e "${YELLOW}Installing Rust.${NC}"
    apt install -y rustc
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
    /opt/theHarvester-venv/bin/python -m pip install -r /opt/theHarvester/requirements.txt --upgrade | grep -v 'already satisfied'
#    /opt/theHarvester-venv/bin/pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt --upgrade | grep -v 'already satisfied'
    echo
else
    echo -e "${YELLOW}Installing theHarvester.${NC}"
    git clone https://github.com/laramies/theHarvester /opt/theHarvester
    echo
    echo -e "${YELLOW}Setting up theHarvester virtualenv.${NC}"
    python3 -m venv /opt/theHarvester-venv
    /opt/theHarvester-venv/bin/python -m pip install -r /opt/theHarvester/requirements.txt
#    /opt/theHarvester-venv/bin/pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
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

if ! command -v xlsx2csv &> /dev/null; then
    echo -e "${YELLOW}Installing xlsx2csv.${NC}"
    apt install -y xlsx2csv
    echo
fi

if ! command -v xml_grep &> /dev/null; then
    echo -e "${YELLOW}Installing xml_grep.${NC}"
    apt install -y xml-twig-tools
    echo
fi

if ! command -v xspy &> /dev/null; then
    echo -e "${YELLOW}Installing xspy.${NC}"
    apt install -y xspy
    echo
fi

if [ ! -f /opt/xwatchwin/xwatchwin ]; then
    echo -e "${YELLOW}Installing xwatchwin.${NC}"
    apt install -y imagemagick libxext-dev xutils-dev
    wget http://www.ibiblio.org/pub/X11/contrib/utilities/xwatchwin.tar.gz -O /tmp/xwatchwin.tar.gz
    tar zxvf /tmp/xwatchwin.tar.gz -C /tmp/
    rm /tmp/xwatchwin.tar.gz
    mv /tmp/xwatchwin/ /opt/
    cd /opt/xwatchwin/

    # Patch source code
    sed -i 's/_BSD_SOURCE/_DEFAULT_SOURCE/g' /opt/xwatchwin/xwatchwin.c
    sed -i 's/_SVID_SOURCE/_DEFAULT_SOURCE/g' /opt/xwatchwin/xwatchwin.c
    sed -i 's/^WinNamesEqual(/int WinNamesEqual(/g' /opt/xwatchwin/xwatchwin.c

    xmkmf && make && make install
    rm /usr/bin/xwatchwin
    echo
fi

echo -e "${BLUE}Updating locate database.${NC}"
updatedb

exit
