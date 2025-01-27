#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Check for root
if [ $EUID -eq 0 ]; then
    echo
    echo "[!] This script cannot be ran as root."
    echo
    exit 1
fi

f_terminate() {
    SAVE_DIR=$HOME/data/cancelled-$(date +%H:%M:%S)
    echo
    echo "[!] Terminating."
    echo
    echo -e "${YELLOW}Saving data to $SAVE_DIR.${NC}"

    cd "$DISCOVER"
    mv "$HOME"/data/"$DOMAIN" "$SAVE_DIR" 2>/dev/null
    mv emails hosts names records squatting subdomains tmp* whois* z* doc pdf ppt txt xls "$SAVE_DIR" 2>/dev/null

    echo
    echo "[*] Saving complete."
    echo
    exit 1
}

# Catch process termination
trap f_terminate SIGHUP SIGINT SIGTERM

clear
f_banner

# Check if Firefox is running
if pgrep firefox > /dev/null; then
    echo
    echo "[!] Close Firefox before running script."
    echo
    exit 1
fi

echo -e "${BLUE}Uses ARIN, DNSRecon, dnstwist, subfinder, sublist3r,${NC}"
echo -e "${BLUE}theHarvester, Metasploit, Whois, and multiple websites.${NC}"
echo
echo -e "${BLUE}[*] Acquire API keys for maximum results with theHarvester.${NC}"
echo -e "${BLUE}[*] Add keys to /root/.theHarvester/api-keys.yaml${NC}"
echo
echo "$MEDIUM"
echo
echo "Usage"
echo
echo "Company: Target"
echo "Domain:  target.com"
echo
echo "$MEDIUM"
echo
echo -n "Company: "
read -r COMPANY

# Check for no answer, need dbl brackets to handle a space in the name
if [[ -z "$COMPANY" ]]; then
    f_error
fi

echo -n "Domain:  "
read -r DOMAIN

# Check for no answer
if [ -z "$DOMAIN" ]; then
    f_error
fi

# Check for a valid domain
if [[ ! "$DOMAIN" =~ ^([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,63}$ ]]; then
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    echo -e "${RED}[!] Invalid domain.${NC}"
    echo
    echo -e "${RED}$SMALL${NC}"
    echo
    exit 1
fi

COMPANYURL=$( printf "%s\n" "$COMPANY" | sed 's/ /%20/g; s/\&/%26/g; s/\,/%2C/g' )

cp -R "$DISCOVER"/report/ "$HOME"/data/"$DOMAIN"
sed -i "s/#COMPANY#/$COMPANY/" "$HOME"/data/"$DOMAIN"/index.htm
sed -i "s/#DOMAIN#/$DOMAIN/" "$HOME"/data/"$DOMAIN"/index.htm
sed -i "s/#DATE#/$RUNDATE/" "$HOME"/data/"$DOMAIN"/index.htm

echo
echo "$MEDIUM"
echo

###############################################################################################################################

# Number of tests
TOTAL=40

echo "ARIN"
echo "    Email                (1/$TOTAL)"

# Fetch ARIN data
if ! curl -ks "https://whois.arin.net/rest/pocs;domain=$DOMAIN" -o tmp.xml; then
    echo
    echo "[!] Failed to fetch ARIN data."
    echo
fi

# Check for results in the XML file
if ! grep -q 'No Search Results' tmp.xml; then
    # Extract handles and URLs
    xmllint --format tmp.xml | grep 'handle' | cut -d '>' -f2 | cut -d '<' -f1 | sort -u > zurls.txt
    xmllint --format tmp.xml | grep 'handle' | cut -d '"' -f2 | sort -u > zhandles.txt

    # Process each URL for email extraction
    while read -r LINE; do
        curl -k -s "$LINE" > tmp2.xml
        xml_grep 'email' tmp2.xml --text_only >> tmp
    done < zurls.txt

    # Filter and format emails
    grep -v '_' tmp | tr 'A-Z' 'a-z' | sort -u > zarin-emails
fi

# Cleanup temporary files
rm tmp* zurls.txt 2>/dev/null

###############################################################################################################################

echo "    Names                (2/$TOTAL)"
if [ -f zhandles.txt ]; then
    while read -r LINE; do
        curl -ks "https://whois.arin.net/rest/poc/$LINE.txt" | grep 'Name' >> tmp
    done < zhandles.txt

    # Process names
    grep -Eiv "($COMPANY|@|abuse|center|domainnames|helpdesk|hostmaster|network|support|technical|telecom)" tmp > tmp2
    sed 's/Name:           //g' tmp2 | tr 'A-Z' 'a-z' | sed 's/\b\(.\)/\u\1/g' > tmp3
    awk -F", " '{print $2,$1}' tmp3 | sed 's/  / /g' | sort -u > zarin-names
fi

# Cleanup temporary files
rm tmp* zhandles.txt 2>/dev/null
echo

###############################################################################################################################

echo "DNSRecon                 (3/$TOTAL)"
dnsrecon -d "$DOMAIN" -n 8.8.8.8 -t std > tmp 2>/dev/null
grep -Eiv '(all queries will|could not|dnskeys|dnssec|error|it is resolving|nsec3|performing|records|recursion|txt|version|wildcard resolution)' tmp | sed 's/\[\*\]//g; s/\[+\]//g; s/^[ \t]*//' | column -t | sort | sed 's/[ \t]*$//' > records
grep 'TXT' tmp | sed 's/\[\*\]//g; s/\[+\]//g; s/^[ \t]*//' | sort | sed 's/[ \t]*$//' >> records

cat records >> "$HOME"/data/"$DOMAIN"/data/records.htm
echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/records.htm

# Cleanup temporary file
rm tmp 2>/dev/null
echo

###############################################################################################################################

echo "dnstwist                 (4/$TOTAL)"
dnstwist --registered "$DOMAIN" > tmp
sed -E 's/\b([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b//g' tmp | grep -v 'original' | sed 's/!ServFail/        /g; s/MX:$//g; s/MX:localhost//g; s/[ \t]*$//' | column -t | sed 's/[ \t]*$//' | sed -E 's/([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/ /g' | sed 's/::28f//g; s/::28//g; s/::2e1//g; s/::200//g; s/:://g' > squatting
echo

###############################################################################################################################

echo "subfinder                (5/$TOTAL)"
/opt/subfinder/v2/cmd/subfinder/subfinder -d "$DOMAIN" -silent | sort -u > zsubfinder
echo

###############################################################################################################################

echo "sublist3r                (6/$TOTAL)"
sublist3r -d "$DOMAIN" > tmp 2>/dev/null
sed 's/\x1B\[[0-9;]*m//g' tmp | sed '/^ /d' | grep -Eiv '(!|enumerating|enumeration|searching|total unique)' | tr 'A-Z' 'a-z' | sort -u > zsublist3r
echo

###############################################################################################################################

echo "theHarvester"
source /opt/theHarvester-venv/bin/activate
echo "    anubis               (7/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b anubis | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zanubis
echo "    baidu                (8/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b baidu | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zbaidu
echo "    bevigil              (9/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b bevigil | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zbevigil
echo "    binaryedge           (10/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b binaryedge | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zbinaryedge
echo "    bing                 (11/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b bing | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zbing
echo "    bing API             (12/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b bingapi | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zbing-api
echo "    bufferoverun         (13/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b bufferoverun | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zbufferoverun
echo "    censys               (14/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b censys | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zcensys
echo "    certspotter          (15/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b certspotter | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zcertspotter
echo "    criminalip           (16/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b criminalip | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zcriminalip
echo "    crtsh                (17/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b crtsh | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zcrtsh
echo "    duckduckgo           (18/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b duckduckgo | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zduckduckgo
echo "    fullhunt             (19/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b fullhunt | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zfullhunt
echo "    github-code          (20/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b github-code | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zgithub-code
echo "    hackertarget         (21/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b hackertarget | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zhackertarget
echo "    hunter               (22/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b hunter | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zhunter
echo "    hunterhow            (23/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b hunterhow | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zhunterhow
echo "    intelx               (24/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b intelx | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zintelx
echo "    netlas               (25/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b netlas | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > znetlas
echo "    otx                  (26/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b otx | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zotx
echo "    pentesttools         (27/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b pentesttools | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zpentesttools
echo "    projectdiscovery     (28/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b projectdiscovery | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zprojectdiscovery
echo "    rapiddns             (29/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b rapiddns | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zrapiddns
echo "    securityTrails       (30/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b securityTrails | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zsecuritytrails
echo "    sitedossier          (31/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b securityTrails | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zsitedossier
echo "    subdomaincenter      (32/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b subdomaincenter | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zsubdomaincenter
echo "    subdomainfinderc99   (33/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b subdomainfinderc99 | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zsubdomainfinderc99
echo "    threatminer          (34/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b threatminer | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zthreatminer
echo "    urlscan              (35/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b urlscan | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zurlscan
echo "    yahoo                (36/$TOTAL)"
/opt/theHarvester/theHarvester.py -d "$DOMAIN" -b yahoo | grep -Eiv '(!|\*|--|\[|searching|yaml)' | sed '/^$/d' | sort -u > zyahoo
deactivate

# Cleanup temporary files
rm tmp*
echo

###############################################################################################################################

echo "Metasploit               (37/$TOTAL)"
msfconsole -q -x "use auxiliary/gather/search_email_collector; set DOMAIN $DOMAIN; run; exit y" > tmp 2>/dev/null
grep @"$DOMAIN" tmp | awk '{print $2}' | tr 'A-Z' 'a-z' | sort -u > zmsf
echo

###############################################################################################################################

echo "Whois"
echo "    Domain               (38/$TOTAL)"
whois -H "$DOMAIN" > tmp 2>/dev/null
sed 's/^[ \t]*//' tmp > tmp2
grep -Eiv '(#|%|<a|=-=-=-=|;|access may|accuracy|additionally|affiliates|afilias except|and dns hosting|and limitations|any use of|at www.|be sure|at the end|by submitting|by the terms|can easily|circumstances|clientdeleteprohibited|clienttransferprohibited|clientupdateprohibited|com laude|commercial purposes|company may|compilation|complaint will|contact information|contact us|contacting|copy and paste|currently set|database|data contained|data presented|database|date of|details|dissemination|domaininfo ab|domain management|domain names in|domain status: ok|electronic processes|enable high|entirety|except as|existing|ext:|failure|facsimile|following terms|for commercial|for detailed|for information|for more|for the|get noticed|get a free|guarantee its|href|If you|in europe|in most|in obtaining|in the address|includes|including|information is|informational purposes|intellectual|is not|is providing|its systems|learn|legitimate|makes this|markmonitor|minimum|mining this|minute and|modify|must be sent|name cannot|namesbeyond|not to use|note:|notice|obtaining information about|of moniker|of this data|or hiding any|or otherwise support|other use of|please|policy|prior written|privacy is|problem reporting|professional and|prohibited without|promote your|protect the|protecting|public interest|queried|queries|receive|receiving|redacted for|register your|registrars|registration record|relevant|repackaging|request|reserves all rights|reserves the|responsible for|restricted to network|restrictions|see business|server at|solicitations|sponsorship|status|support questions|support the transmission|supporting|telephone, or facsimile|temporary|that apply to|that you will|the right|the data is|The fact that|the transmission|this listing|this feature|this information|this service is|to collect or|to entities|to report any|to suppress|to the systems|transmission of|trusted partner|united states|unlimited|unsolicited advertising|users may|version 6|via e-mail|visible|visit aboutus.org|visit|web-based|when you|while believed|will use this|with many different|with no guarantee|we reserve|whitelist|whois|you agree|You may not)' tmp2 > tmp3
# Remove lines starting with "*"
sed '/^*/d' tmp3 > tmp4
# Remove lines starting with "-"
sed '/^-/d' tmp4 > tmp5
# Remove lines starting with http
sed '/^http/d' tmp5 > tmp6
# Remove lines starting with US
sed '/^US/d' tmp6 > tmp7
# Clean up phone numbers
sed 's/+1.//g' tmp7 > tmp8
# Remove leading whitespace from file
awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp8 > tmp9
# Remove trailing whitespace from each line
sed 's/[ \t]*$//' tmp9 > tmp10
# Compress blank lines
cat -s tmp10 > tmp11
# Remove lines that end with various words then a colon or period(s)
grep -Eiv '(2:$|3:$|address.$|address........$|address.........$|ext.:$|fax:$|fax............$|fax.............$|province:$|server:$)' tmp11 > tmp12
# Remove line after "Domain Servers:"
sed -i '/^Domain Servers:/{n; /.*/d}' tmp12
# Remove blank lines from end of file
awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp12 > tmp13
# Format output
sed 's/: /:#####/g' tmp13 | column -s '#' -t > whois-domain

###############################################################################################################################

echo "    IP                   (39/$TOTAL)"
DOMAINIP=$(ping -c1 "$DOMAIN" | grep PING | cut -d '(' -f2 | cut -d ')' -f1)
whois "$DOMAINIP" > tmp
# Remove blank lines from the beginning of a file
grep -Eiv '(#|%|comment|remarks)' tmp | sed '/./,$!d' > tmp2
# Remove blank lines from the end of a file
sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' tmp2 > tmp3
# Compress blank lines
cat -s tmp3 > tmp4
# Print with the second column starting at 25 spaces
awk '{printf "%-25s %s\n", $1, $2}' tmp4 | sed 's/+1-//g' > whois-ip

# Cleanup temporary files
rm tmp*
echo

###############################################################################################################################

echo "intodns.com              (40/$TOTAL)"
wget -q http://www.intodns.com/"$DOMAIN" -O tmp
cat tmp | sed '1,32d; s/<table width="99%" cellspacing="1" class="tabular">/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/g; s/Test name/Test/g; s/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback" class="thickbox feedback">send feedback<\/a>//g; s/ background-color: #ffffff;//; s/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/<table class="table table-bordered">/; s/<td class="icon">/<td class="inc-table-cell-status">/g; s/<tr class="info">/<tr>/g' | grep -Eiv '(processed in|ua-2900375-1|urchintracker|script|work in progress)' | sed '/footer/I,+3 d; /google-analytics/I,+5 d' > tmp2
cat tmp2 >> "$HOME"/data/"$DOMAIN"/pages/config.htm

# Add new icons
sed -i 's|/static/images/error.gif|\.\./assets/images/icons/fail.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
sed -i 's|/static/images/fail.gif|\.\./assets/images/icons/fail.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
sed -i 's|/static/images/info.gif|\.\./assets/images/icons/info.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
sed -i 's|/static/images/pass.gif|\.\./assets/images/icons/pass.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
sed -i 's|/static/images/warn.gif|\.\./assets/images/icons/warn.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
sed -i 's|\.\.\.\.|\.\.|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
# Insert missing table tag
sed -i 's/.*<thead>.*/    <table border="4">\n&/' "$HOME"/data/"$DOMAIN"/pages/config.htm
# Add blank lines below table
sed -i 's/.*<\/table>.*/&\n<br>\n<br>/' "$HOME"/data/"$DOMAIN"/pages/config.htm
# Remove unnecessary JS at bottom of page
sed -i '/Math\.random/I,+6 d' "$HOME"/data/"$DOMAIN"/pages/config.htm
# Clean up
sed -i 's/I could use the nameservers/The nameservers/g' "$HOME"/data/"$DOMAIN"/pages/config.htm
sed -i 's/below to performe/below can perform/g; s/ERROR: //g; s/FAIL: //g; s/I did not detect/Unable to detect/g; s/I have not found/Unable to find/g; s/It may be that I am wrong but the chances of that are low.//g; s/Good.//g; s/Ok. //g; s/OK. //g; s/Oh well, //g; s/This can be ok if you know what you are doing.//g; s/That is NOT OK//g; s/That is not so ok//g; s/The reverse (PTR) record://g; s/the same ip./the same IP./g; s/The SOA record is://g; s/WARNING: //g; s/You have/There are/g; s/you have/there are/g; s/use on having/use in having/g; s/You must be/Be/g; s/Your/The/g; s/your/the/g' "$HOME"/data/"$DOMAIN"/pages/config.htm

# Cleanup temporary files
rm tmp*

###############################################################################################################################

# Find eamils (cat is needed here)
cat z* | grep "@$DOMAIN" | grep -v '[0-9]' | sed "/^'/d" | grep -Eiv '(_|,|firstname|lastname|test|www|xxx|zzz)' | sort -u > emails

# Find hosts
cat z* | awk -F: '{print $NF}' | grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -Eiv '(0.0.0.0|1.1.1.1|1.1.1.2|8.8.8.8|127.0.0.1)' | sort -u | $SIP > hosts

# Find names (cat is needed here)
cat z* | grep -Eiv '(@|:|\.|atlanta|boston|bufferoverun|captcha|detroit|google|integers|maryland|must be|north carolina|philadelphia|planning|postmaster|resolutions|search|substring|united|university)' | sed 's/ And / and /; s/ Av / AV /g; s/Dj/DJ/g; s/iii/III/g; s/ii/II/g; s/ It / IT /g; s/Jb/JB/g; s/ Of / of /g; s/Macd/MacD/g; s/Macn/MacN/g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mch/McH/g; s/Mci/McI/g; s/Mcj/McJ/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcp/McP/g; s/Mcq/McQ/g; s/Mcs/McS/g; s/Mcv/McV/g; s/Tj/TJ/g; s/ Ui / UI /g; s/ Ux / UX /g; /[0-9]/d; /^ /d; /^$/d' | sort -u > names

# Find subdomains
cat z* | cut -d ':' -f2 | grep "\.$DOMAIN" | grep -Eiv '(@|/|www)' | awk '{print $1}' | grep "\.$DOMAIN$" | tr 'A-Z' 'a-z' | sort -u > subdomains

# Find documents (not sure if its needed here)
cat z* | grep -Ei '\.doc$|\.docx$' | sort -u > doc
cat z* | grep -Ei '\.ppt$|\.pptx$' | sort -u > ppt
cat z* | grep -Ei '\.xls$|\.xlsx$' | sort -u > xls
cat z* | grep -i '\.pdf$' | sort -u > pdf
cat z* | grep -i '\.txt$' | sort -u > txt

# Remove empty files in the current folder
find . -type f -empty -delete

###############################################################################################################################

# Generate report and htm data
echo "Summary" > zreport
echo "$SMALL" >> zreport
echo > tmp

if [ -f emails ]; then
    emailcount=$(wc -l emails | cut -d ' ' -f1)
    echo "Emails            $emailcount" >> zreport
    echo "Emails ($emailcount)" >> tmp
    echo "$SMALL" >> tmp
    cat emails >> tmp
    echo >> tmp
    cat emails >> "$HOME"/data/"$DOMAIN"/data/emails.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/emails.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/emails.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/emails.htm
fi

if [ -f hosts ]; then
    hostcount=$(wc -l hosts | cut -d ' ' -f1)
    echo "Hosts             $hostcount" >> zreport
    echo "Hosts ($hostcount)" >> tmp
    echo "$LARGE" >> tmp
    cat hosts >> tmp
    echo >> tmp
    cat hosts >> "$HOME"/data/"$DOMAIN"/data/hosts.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/hosts.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/hosts/names.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/hosts/names.htm
fi

if [ -f names ]; then
    namecount=$(wc -l names | cut -d ' ' -f1)
    echo "Names             $namecount" >> zreport
    echo "Names ($namecount)" >> tmp
    echo "$LARGE" >> tmp
    cat names >> tmp
    echo >> tmp
    cat names >> "$HOME"/data/"$DOMAIN"/data/names.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/names.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/names.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/names.htm
fi

if [ -f records ]; then
    recordcount=$(wc -l records | cut -d ' ' -f1)
    echo "DNS Records       $recordcount" >> zreport
    echo "DNS Records ($recordcount)" >> tmp
    echo "$LARGE" >> tmp
    cat records >> tmp
    echo >> tmp
fi

if [ -f squatting ]; then
    squattingcount=$(wc -l squatting | cut -d ' ' -f1)
    echo "Squatting         $squattingcount" >> zreport
    echo "Squatting ($squattingcount)" >> tmp
    echo "$LARGE" >> tmp
    cat squatting >> tmp
    echo >> tmp
    cat squatting >> "$HOME"/data/"$DOMAIN"/data/squatting.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/squatting.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/squatting.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/squatting.htm
fi

if [ -f subdomains ]; then
    urlcount=$(wc -l subdomains | cut -d ' ' -f1)
    echo "Subdomains        $urlcount" >> zreport
    echo "Subdomains ($urlcount)" >> tmp
    echo "$LARGE" >> tmp
    cat subdomains >> tmp
    echo >> tmp
    cat subdomains >> "$HOME"/data/"$DOMAIN"/data/subdomains.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/subdomains.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/subdomains.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/subdomains.htm
fi

if [ -f xls ]; then
    xlscount=$(wc -l xls | cut -d ' ' -f1)
    echo "Excel             $xlscount" >> zreport
    echo "Excel Files ($xlscount)" >> tmp
    echo "$LARGE" >> tmp
    cat xls >> tmp
    echo >> tmp
    cat xls >> "$HOME"/data/"$DOMAIN"/data/xls.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/xls.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/xls.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/xls.htm
fi

if [ -f pdf ]; then
    pdfcount=$(wc -l pdf | cut -d ' ' -f1)
    echo "PDF               $pdfcount" >> zreport
    echo "PDF Files ($pdfcount)" >> tmp
    echo "$LARGE" >> tmp
    cat pdf >> tmp
    echo >> tmp
    cat pdf >> "$HOME"/data/"$DOMAIN"/data/pdf.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/pdf.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/pdf.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/pdf.htm
fi

if [ -f ppt ]; then
    pptcount=$(wc -l ppt | cut -d ' ' -f1)
    echo "PowerPoint        $pptcount" >> zreport
    echo "PowerPoint Files ($pptcount)" >> tmp
    echo "$LARGE" >> tmp
    cat ppt >> tmp
    echo >> tmp
    cat ppt >> "$HOME"/data/"$DOMAIN"/data/ppt.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/ppt.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/ppt.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/ppt.htm
fi

if [ -f txt ]; then
    txtcount=$(wc -l txt | cut -d ' ' -f1)
    echo "Text              $txtcount" >> zreport
    echo "Text Files ($txtcount)" >> tmp
    echo "$LARGE" >> tmp
    cat txt >> tmp
    echo >> tmp
    cat txt >> "$HOME"/data/"$DOMAIN"/data/txt.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/txt.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/txt.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/txt.htm
fi

if [ -f doc ]; then
    doccount=$(wc -l doc | cut -d ' ' -f1)
    echo "Word              $doccount" >> zreport
    echo "Word Files ($doccount)" >> tmp
    echo "$LARGE" >> tmp
    cat doc >> tmp
    echo >> tmp
    cat doc >> "$HOME"/data/"$DOMAIN"/data/doc.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/doc.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/doc.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/doc.htm
fi

cat tmp >> zreport

if [ -f whois-domain ]; then
    echo "Whois Domain" >> zreport
    echo "$LARGE" >> zreport
    cat whois-domain >> zreport
    cat whois-domain >> "$HOME"/data/"$DOMAIN"/data/whois-domain.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/whois-domain.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/whois-domain.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/whois-domain.htm
fi

if [ -f whois-ip ]; then
    echo >> zreport
    echo "Whois IP" >> zreport
    echo "$LARGE" >> zreport
    cat whois-ip >> zreport
    cat whois-ip >> "$HOME"/data/"$DOMAIN"/data/whois-ip.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/whois-ip.htm
else
    echo "No data found." >> "$HOME"/data/"$DOMAIN"/data/whois-ip.htm
    echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/whois-ip.htm
fi

cat zreport >> "$HOME"/data/"$DOMAIN"/data/passive-recon.htm
echo "</pre>" >> "$HOME"/data/"$DOMAIN"/data/passive-recon.htm

rm tmp* zreport

# Ensure the destination directory exists then move files
mkdir -p "$HOME/data/$DOMAIN/tools"
mv emails hosts names records squatting subdomains tmp* whois* z* doc pdf ppt txt xls "$HOME/data/$DOMAIN/tools/" 2>/dev/null
cd "$CWD"

echo
echo "$MEDIUM"
echo
echo
echo -e "The supporting data folder is located at ${YELLOW}$HOME/data/$DOMAIN/${NC}\n"

###############################################################################################################################

f_runlocally

USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.39 Mobile Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0"
    "Mozilla/5.0 (X11; Linux i686; rv:132.0) Gecko/20100101 Firefox/132.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15"
    "Mozilla/5.0 (Android 15; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0"
)

URLS=(
    "https://dnsdumpster.com"
    "https://dockets.justia.com/search?parties=%22$COMPANYURL%22&cases=mostrecent"
    "https://networksdb.io/search/org/%22$COMPANYURL%22"
    "https://phonebook.cz"
    "https://shdn.io/analyze?target=$DOMAIN"
    "https://www.shodan.io/search?query=$DOMAIN"
    "https://www.google.com/search?q=%22$COMPANYURL%22+logo"
    "https://www.google.com/search?q=site:http://s3.amazonaws.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://blob.core.windows.net+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://drive.google.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://googleapis.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:pastebin.com+%22$DOMAIN%22+password"
    "https://www.google.com/search?q=site:$DOMAIN+username+OR+password+OR+login+-Find"
    "https://www.google.com/search?q=site:$DOMAIN+filetype%3Adoc+OR+filetype%3Adocx"
    "https://www.google.com/search?q=site:$DOMAIN+filetype%3Axls+OR+filetype%3Axlsx"
    "https://www.google.com/search?q=site:$DOMAIN+filetype%3Appt+OR+filetype%3Apptx"
    "https://www.google.com/search?q=site:$DOMAIN+filetype%3Atxt"
    "https://www.google.com/search?q=site:$DOMAIN+%22index+of/%22+OR+%22parent+directory%22"
    "https://www.google.com/search?q=site:$DOMAIN+intext:%22internal+use+only%22"
    "https://www.google.com/search?q=site:$DOMAIN+intext:%22proprietary+and+confidential%22"
    "https://$DOMAIN"
)

for ((i = 0; i < ${#URLS[@]}; i++)); do
    USER_AGENT="${USER_AGENTS[$((i % ${#USER_AGENTS[@]}))]}"
    firefox "${URLS[$i]}" --user-agent="$USER_AGENT" &
    sleep $((RANDOM % 4 + 3))
done
