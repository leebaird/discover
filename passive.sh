#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

# Check for root
if [ $EUID -eq 0 ]; then
    echo
    echo -e "${YELLOW}[!] This script cannot be ran as root.${NC}"
    echo
    exit 1
fi

f_terminate(){
    OUTPUT_DIR=$HOME/data/cancelled-$(date +%H:%M)
    echo
    echo "[!] Terminating."
    echo
    echo -e "${YELLOW}Saving data to $OUTPUT_DIR.${NC}"

    cd "$DISCOVER" || exit
    mv "$HOME"/data/"$DOMAIN" "$OUTPUT_DIR" 2>/dev/null
    mv names emails hosts private-ips private-subs public-ips records squatting subdomains tmp* whois* z* doc pdf ppt txt xls "$OUTPUT_DIR" 2>/dev/null

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
if pgrep -x "firefox|firefox-bin" > /dev/null; then
	echo
    echo "[!] Close all Firefox instances before running script."
	echo
    exit 1
fi

echo -e "${BLUE}Uses ARIN, DNSRecon, dnstwist, subfinder, sublist3r,${NC}"
echo -e "${BLUE}theHarvester, Metasploit, Whois, and multiple websites.${NC}"
echo
echo -e "${BLUE}[*] Acquire API keys for maximum results with theHarvester.${NC}"
echo -e "${BLUE}[*] Add keys to $HOME/.theHarvester/api-keys.yaml${NC}"
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
sed -i "s/#DATE#/$DATESTAMP/" "$HOME"/data/"$DOMAIN"/index.htm

echo
echo "$MEDIUM"
echo

###############################################################################################################################

# Number of tests
COUNT=1
TOTAL=63

###############################################################################################################################

f_arin() {
    echo "ARIN"
    echo "    Email                ($COUNT/$TOTAL)"
    ((COUNT++))

    if ! curl -ks "https://whois.arin.net/rest/pocs;domain=$DOMAIN" -o tmp.xml; then
        echo "[!] Failed to fetch ARIN data"
        rm tmp.xml 2>/dev/null
    fi

    if ! grep -q 'No Search Results' tmp.xml; then
        xmllint --format tmp.xml | grep 'handle' | cut -d '>' -f2 | cut -d '<' -f1 | sort -u > zurls
        xmllint --format tmp.xml | grep 'handle' | cut -d '"' -f2 | sort -u > zhandles

        while read -r LINE; do
            curl -ks "$LINE" > tmp2.xml
            xml_grep 'email' tmp2.xml --text_only >> tmp 2>/dev/null
        done < zurls

        if [ -s tmp ]; then
            grep -Eiv "(_|error)" tmp | tr '[:upper:]' '[:lower:]' | grep "$DOMAIN" | sort -u > zarin-emails
        fi
    fi

    rm tmp* zurls 2>/dev/null

    echo "    Names                ($COUNT/$TOTAL)"
    ((COUNT++))
    if [ -f zhandles ]; then
        while read -r LINE; do
            curl -ks "https://whois.arin.net/rest/poc/$LINE.txt" | grep 'Name' >> tmp
        done < zhandles

        if [ -f tmp ]; then
            grep -Eiv "($COMPANY|@|abuse|center|domainnames|helpdesk|hostmaster|network|support|technical|telecom)" tmp > tmp2
            sed 's/Name:           //g' tmp2 | tr '[:upper:]' '[:lower:]' | sed 's/\b\(.\)/\u\1/g' > tmp3
            awk -F", " '{print $2,$1}' tmp3 | sed 's/  / /g' | sed '/^ /d' | sort -u > zarin-names
        fi
    fi

    rm tmp* zhandles 2>/dev/null
    echo
}

###############################################################################################################################

f_dnsrecon() {
    echo "DNSRecon                 ($COUNT/$TOTAL)"
    ((COUNT++))
    local DNSRECON=''
    if [ -x /opt/dnsrecon-venv/bin/dnsrecon ] && /opt/dnsrecon-venv/bin/dnsrecon --version >/dev/null 2>&1; then
        DNSRECON=/opt/dnsrecon-venv/bin/dnsrecon
    elif command -v dnsrecon >/dev/null 2>&1 && dnsrecon --version >/dev/null 2>&1; then
        DNSRECON=$(command -v dnsrecon)
    fi

    if [ -n "$DNSRECON" ]; then
        "$DNSRECON" -d "$DOMAIN" -n 8.8.8.8 -t std > tmp 2>&1
        grep -Eiv '(all queries will|bind version|completed|could not|dnskeys|dnssec|error|enumeration for|it is resolving|nsec |nsec3|performing|records|recursion|starting enumeration|txt |wildcard resolution)' tmp | sed -E 's/^.*INFO[[:space:]]+//; s/\[\*\]//g; s/\[+\]//g; s/^[ \t]*//' | grep -Eiv '^$' | column -t | sort -u | sed 's/[ \t]*$//' > records
        grep -i 'TXT' tmp | sed -E 's/^.*INFO[[:space:]]+//; s/\[\*\]//g; s/\[+\]//g; s/^[ \t]*//' | sort -u | sed 's/[ \t]*$//' >> records
    else
        echo -e "${YELLOW}[!] dnsrecon is unavailable (broken on Python 3.13+). Run Discover update to install a compatible version.${NC}"
        : > records
    fi

    rm tmp 2>/dev/null
    echo
}

###############################################################################################################################

f_dnstwist() {
    echo "dnstwist                 ($COUNT/$TOTAL)"
    ((COUNT++))
    dnstwist --registered -f csv "$DOMAIN" > tmp
    awk -F',' '
    NR==1 || $1 == "*original" { next }
    $6 == "" || $6 == "!ServFail" { next }
    {
        ip = ($3 != "" && $3 != "!ServFail") ? $3 : ""
        ns = "NS:" $6
        mx = ($5 != "" && $5 != "!ServFail") ? "MX:" $5 : ""
        printf "%s\t%s\t%s\t%s\t%s\n", $1, $2, ip, ns, mx
    }' tmp > squatting
    rm tmp 2>/dev/null
    echo
}

###############################################################################################################################

f_intodns() {
    echo "intodns.com              ($COUNT/$TOTAL)"
    ((COUNT++))
    wget -q http://www.intodns.com/"$DOMAIN" -O tmp
    # shellcheck disable=SC2002
    cat tmp | sed '1,32d; s/<table width="99%" cellspacing="1" class="tabular">/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/g; s/Test name/Test/g; s/ <a href="feedback\/?KeepThis=true&amp;TB_iframe=true&amp;height=300&amp;width=240" title="intoDNS feedback" class="thickbox feedback">send feedback<\/a>//g; s/ background-color: #ffffff;//; s/<center><table width="85%" cellspacing="1" class="tabular"><\/center>/<table class="inc-dns-config table">/; s/<td class="icon">/<td class="inc-table-cell-status">/g; s/<tr class="info">/<tr>/g' | grep -Eiv '(processed in|ua-2900375-1|urchintracker|script|work in progress)' | sed '/footer/I,+3 d; /google-analytics/I,+5 d' > tmp2
    cat tmp2 >> "$HOME"/data/"$DOMAIN"/pages/config.htm

    sed -i 's|/static/images/error.gif|\.\./assets/images/icons/fail.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's|/static/images/fail.gif|\.\./assets/images/icons/fail.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's|/static/images/info.gif|\.\./assets/images/icons/info.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's|/static/images/pass.gif|\.\./assets/images/icons/pass.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's|/static/images/warn.gif|\.\./assets/images/icons/warn.png|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's|\.\.\.\.|\.\.|g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's/<table border="4">/<table class="inc-dns-config table">/g; s/<table class="table table-bordered">/<table class="inc-dns-config table">/g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    grep -q 'inc-dns-config' "$HOME"/data/"$DOMAIN"/pages/config.htm || \
        sed -i '0,/<thead>/{s/<thead>/    <table class="inc-dns-config table">\n<thead>/}' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's/.*<\/table>.*/&\n<br>\n<br>/' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i '/Math\.random/I,+6 d' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's/I could use the nameservers/The nameservers/g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    sed -i 's/below to performe/below can perform/g; s/ERROR: //g; s/FAIL: //g; s/I did not detect/Unable to detect/g; s/I have not found/Unable to find/g; s/It may be that I am wrong but the chances of that are low.//g; s/Good.//g; s/Ok. //g; s/OK. //g; s/Oh well, //g; s/This can be ok if you know what you are doing.//g; s/That is NOT OK//g; s/That is not so ok//g; s/The reverse (PTR) record://g; s/the same ip./the same IP./g; s/The SOA record is://g; s/WARNING: //g; s/You have/There are/g; s/you have/there are/g; s/use on having/use in having/g; s/You must be/Be/g; s/Your/The/g; s/your/the/g' "$HOME"/data/"$DOMAIN"/pages/config.htm
    echo
    rm tmp* 2>/dev/null
}

###############################################################################################################################

f_metasploit() {
    echo "Metasploit               ($COUNT/$TOTAL)"
    ((COUNT++))
    msfconsole -q -x "use auxiliary/gather/search_email_collector; set DOMAIN $DOMAIN; run; exit y" > tmp 2>/dev/null
    grep @"$DOMAIN" tmp | awk '{print $2}' | tr '[:upper:]' '[:lower:]' | sort -u > zmsf
    [ ! -s zmsf ] && rm -f zmsf
    rm -f tmp
    echo
}

###############################################################################################################################

f_subfinder() {
    echo "subfinder                ($COUNT/$TOTAL)"
    ((COUNT++))
    subfinder -d "$DOMAIN" -silent | sort -u > zsubfinder
    echo
}

###############################################################################################################################

f_sublist3r() {
    echo "sublist3r                ($COUNT/$TOTAL)"
    ((COUNT++))
    sublist3r -d "$DOMAIN" > tmp 2>/dev/null
    sed 's/\x1B\[[0-9;]*m//g' tmp | sed '/^ /d' | grep -Eiv '(!|enumerating|enumeration|searching|total unique)' | tr '[:upper:]' '[:lower:]' | sort -u > zsublist3r
    echo
    rm tmp 2>/dev/null
}

###############################################################################################################################

run_harvester() {
    local source=$1
    printf "    %-20s (%s/%s)\n" "${source}" "${COUNT}" "${TOTAL}"
    theHarvester -d "$DOMAIN" -b "$source" -r 2>&1 | grep -Ev ' - INFO - ' | grep -Eiv '(!|\*|--|=|\[|\:\:|failed to detect|no response|retrying|searching|yaml)' | sed '/^$/d;/:$/d; /^AS/d; s|https://||g; s|www\.||g' | sort -u > "z${source}"
    ((COUNT++))
}

f_theharvester() {
    local sources_no_api=(baidu certspotter commoncrawl crtsh duckduckgo gitlab hudsonrock netcraft omnisint otx rapiddns robtex subdomaincenter subdomainfinderc99 thc threatcrowd urlscan waybackarchive yahoo)
    local source

    echo "theHarvester"
    cd "$HOME/theHarvester"
    source .venv/bin/activate

    for source in "${sources_no_api[@]}"; do
        run_harvester "$source"
    done

    mv z* "$DISCOVER" 2>/dev/null
    deactivate
    cd "$DISCOVER"
    find . -type f -empty -delete
    echo
}

f_theharvester_api() {
    local sources_api=(bevigil bitbucket brave bufferoverun builtwith censys chaos criminalip dehashed dnsdumpster fofa fullhunt github-code hackertarget haveibeenpwned hunter hunterhow intelx leakix leaklookup mojeek netlas onyphe pentesttools projectdiscovery rocketreach securityscorecard securityTrails tomba venacus virustotal whoisxml windvane zoomeye)
    local source

    echo "theHarvester (API)"
    echo "    These sources require API keys."
    cd "$HOME/theHarvester"
    source .venv/bin/activate

    for source in "${sources_api[@]}"; do
        run_harvester "$source"
    done

    mv z* "$DISCOVER" 2>/dev/null
    deactivate
    cd "$DISCOVER"
    find . -type f -empty -delete
    echo
}

###############################################################################################################################

f_whois_domain() {
    echo "Whois"
    echo "    Domain               ($COUNT/$TOTAL)"
    ((COUNT++))
    whois -H "$DOMAIN" > tmp 2>/dev/null
    sed 's/^[ \t]*//' tmp > tmp2
    grep -Eiv '(#|%|<a|=-=-=-=|;|access may|accuracy|additionally|affiliates|afilias except|and dns hosting|and limitations|any use of|at www.|be sure|at the end|by submitting|by the terms|can easily|circumstances|clientdeleteprohibited|clienttransferprohibited|clientupdateprohibited|com laude|commercial purposes|company may|compilation|complaint will|contact information|contact us|contacting|copy and paste|currently set|database|data contained|data presented|database|date of|details|dissemination|domaininfo ab|domain management|domain names in|domain status: ok|electronic processes|enable high|entirety|except as|existing|ext:|failure|facsimile|following terms|for commercial|for detailed|for information|for more|for the|get noticed|get a free|guarantee its|href|If you|in europe|in most|in obtaining|in the address|includes|including|information is|informational purposes|intellectual|is not|is providing|its systems|learn|legitimate|makes this|markmonitor|minimum|mining this|minute and|modify|must be sent|name cannot|namesbeyond|not to use|note:|notice|obtaining information about|of moniker|of this data|or hiding any|or otherwise support|other use of|please|policy|prior written|privacy is|problem reporting|professional and|prohibited without|promote your|protect the|protecting|public interest|queried|queries|receive|receiving|redacted for|register your|registrars|registration record|relevant|repackaging|request|reserves all rights|reserves the|responsible for|restricted to network|restrictions|see business|server at|solicitations|sponsorship|status|support questions|support the transmission|supporting|telephone, or facsimile|temporary|that apply to|that you will|the right|the data is|The fact that|the transmission|this listing|this feature|this information|this service is|to collect or|to entities|to report any|to suppress|to the systems|transmission of|trusted partner|united states|unlimited|unsolicited advertising|users may|version 6|via e-mail|visible|visit aboutus.org|visit|web-based|when you|while believed|will use this|with many different|with no guarantee|we reserve|whitelist|whois|you agree|You may not)' tmp2 > tmp3
    sed '/^*/d' tmp3 > tmp4
    sed '/^-/d' tmp4 > tmp5
    sed '/^http/d' tmp5 > tmp6
    sed '/^US/d' tmp6 > tmp7
    sed 's/+1.//g' tmp7 > tmp8
    awk '!d && NF {sub(/^[[:blank:]]*/,""); d=1} d' tmp8 > tmp9
    sed 's/[ \t]*$//' tmp9 > tmp10
    cat -s tmp10 > tmp11
    grep -Eiv '(2:$|3:$|address.$|address........$|address.........$|ext.:$|fax:$|fax............$|fax.............$|province:$|server:$)' tmp11 > tmp12
    sed -i '/^Domain Servers:/{n; /.*/d}' tmp12
    awk '/^[[:space:]]*$/{p++;next} {for(i=0;i<p;i++){printf "\n"}; p=0; print}' tmp12 > tmp13
    sed 's/: /:#####/g' tmp13 | column -s '#' -t | sed 's/[ \t]*$//' > whois-domain
    rm tmp*
}

###############################################################################################################################

f_whois_ip() {
    echo "    IP                   ($COUNT/$TOTAL)"
    ((COUNT++))
    local DOMAINIP
    DOMAINIP=$(dig +short "$DOMAIN" | head -1)
    [ -n "$DOMAINIP" ] || return 0
    whois "$DOMAINIP" > tmp
    grep -Eiv '(#|%|comment|remarks)' tmp | sed '/./,$!d' > tmp2
    sed -e :a -e '/^\n*$/{$d;N;ba' -e '}' tmp2 > tmp3
    cat -s tmp3 > tmp4
    awk '{printf "%-25s %s\n", $1, $2}' tmp4 | sed 's/+1-//g' > whois-ip
    rm tmp* 2>/dev/null

    if [ ! -s whois-ip ]; then
        rm -f whois-ip
        return 0
    fi

    if grep -qiE '^no[[:space:]]+whois' whois-ip; then
        rm -f whois-ip
        return 0
    fi

    if ! grep -qiE '^(inetnum|inet6num|netrange|netname|orgname|organization|descr|org-name|cust-name|owner):' whois-ip; then
        rm -f whois-ip
    fi
}

###############################################################################################################################

f_aggregate() {
    cat z* | grep "\@$DOMAIN" | grep -v '[0-9]' | grep -Eiv "(_|,|'|firstname|lastname|test|www|xxx|zzz)" | sort -u > emails

    cat z* | grep -Eiv '(@|:|\.|>|additionally|atlanta|boston|bufferoverun|captcha|detroit|exception|found character|google|integers|maryland|must be|north carolina|philadelphia|planning|postmaster|resolutions|search|substring|united|university|while scanning)' | sed 's/ And / and /; s/ Av / AV /g; s/Dj/DJ/g; s/iii/III/g; s/ii/II/g; s/ It / IT /g; s/Jb/JB/g; s/ Of / of /g; s/Macd/MacD/g; s/Macn/MacN/g; s/Mca/McA/g; s/Mcb/McB/g; s/Mcc/McC/g; s/Mcd/McD/g; s/Mce/McE/g; s/Mcf/McF/g; s/Mcg/McG/g; s/Mch/McH/g; s/Mci/McI/g; s/Mcj/McJ/g; s/Mck/McK/g; s/Mcl/McL/g; s/Mcm/McM/g; s/Mcn/McN/g; s/Mcp/McP/g; s/Mcq/McQ/g; s/Mcs/McS/g; s/Mcv/McV/g; s/Tj/TJ/g; s/ Ui / UI /g; s/ Ux / UX /g; /[0-9]/d; /^ /d; /^$/d' | sort -u > names

    cat z* | awk -F: '{print $NF}' | grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -Eiv '\b(0\.0\.0\.0|1\.1\.1\.1|1\.1\.1\.2|8\.8\.8\.8|127\.0\.0\.1|127\.0\.0\.53)\b|\.0$' | sort -u | sort -n -u -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > hosts

    while IFS= read -r IP; do
        if [[ $IP =~ ^10\..* ]] || \
           [[ $IP =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]] || \
           [[ $IP =~ ^192\.168\..* ]]; then
            echo "$IP" >> private-ips
        else
            echo "$IP" >> public-ips
        fi
    done < hosts

    cat z* | grep -Eiv '(•|@|\+|;|::|,|>|//|\b1\.1\.1\.1\b|\b127\.0\.0\.53\b|failed to|no response|www)' | sed '/^[0-9]\|^\.\|^-/d' | sed '/\.$/d' | grep '\.' | sed 's/:/ /g' | column -t | tr '[:upper:]' '[:lower:]' | sort -u | awk '$2 ~ /[a-z]/ {next} NF==1{if(a) print l; a=$1; l=$0; next} $1==a{print; a=""; next} a{print l; a=""} 1; END{if(a) print l}' | sed 's/[ \t]*$//' > tmp

    echo -e "${BLUE}[*] Resolving subdomains with no IPs using dig.${NC}"

    local total current ip col1 col2 second_column line
    total=$(wc -l < tmp)
    current=0
    > tmp2
    while read -r col1 col2; do
        ((current++))
        echo -ne "\r    $current of $total"
        if [ -z "$col2" ]; then
            ip=$(dig +short "$col1" | grep -Eo '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -n 1)
            if [ -n "$ip" ] && [ "$ip" != "1.1.1.1" ] && [ "$ip" != "127.0.0.53" ]; then
                echo "$col1 $ip" >> tmp2
            fi
        else
            echo "$col1 $col2" >> tmp2
        fi
    done < tmp
    echo

    column -t tmp2 > subdomains
    rm tmp tmp2 2>/dev/null

    while IFS= read -r line; do
        second_column=$(echo "$line" | awk '{print $2}')

        if [[ -n $second_column ]] && ( [[ $second_column =~ ^10\..* ]] || \
           [[ $second_column =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\..* ]] || \
           [[ $second_column =~ ^192\.168\..* ]] ); then
            echo "$line" >> tmp
        fi
    done < subdomains

    column -t tmp > private-subs
    rm tmp 2>/dev/null

    cat z* | grep -Ei '\.(doc|docx)$' | sort -u > doc
    cat z* | grep -Ei '\.(ppt|pptx)$' | sort -u > ppt
    cat z* | grep -Ei '\.(xls|xlsx)$' | sort -u > xls
    cat z* | grep -i '\.pdf$' | sort -u > pdf
    cat z* | grep -i '\.txt$' | sort -u > txt

    find . -type f -empty -delete
}

###############################################################################################################################

f_report_append_pre_page(){
    local SRC="$1"
    local PAGE="$2"

    if [ -n "$SRC" ] && [ -f "$SRC" ]; then
        cat "$SRC" >> "$PAGE"
    else
        echo "No data found." >> "$PAGE"
    fi

    {
        echo "</pre>"
        echo "    </div>"
        echo "</div>"
        echo
        echo "</body>"
        echo "</html>"
    } >> "$PAGE"
}

f_report_append_squatting_page(){
    local PAGE="$1"

    if [ -f squatting ] && [ -s squatting ]; then
        python3 - squatting >> "$PAGE" <<'PY'
import csv
import html
import sys

def parse_row(raw):
    raw = raw.strip()
    if not raw:
        return None

    if "\t" in raw:
        row = next(csv.reader([raw], delimiter="\t"))
        while len(row) < 5:
            row.append("")
        fuzzer, domain, ipaddr, ns, mx = [cell.strip() for cell in row[:5]]
    else:
        parts = raw.split()
        if len(parts) < 2:
            return None
        fuzzer, domain = parts[0], parts[1]
        ipaddr = ns = mx = ""
        for part in parts[2:]:
            if part.startswith("NS:"):
                ns = part
            elif part.startswith("MX:"):
                mx = part
            elif not ipaddr:
                ipaddr = part

    if ipaddr.startswith("NS:"):
        if not ns:
            ns = ipaddr
        ipaddr = ""
    elif ipaddr.startswith("MX:"):
        if not mx:
            mx = ipaddr
        ipaddr = ""

    if not domain:
        return None
    return fuzzer, domain, ipaddr, ns, mx

path = sys.argv[1]
lines = []
with open(path, newline="") as handle:
    for raw in handle:
        parsed = parse_row(raw)
        if not parsed:
            continue
        fuzzer, domain, ipaddr, ns, mx = parsed
        lines.append(
            "                <tr>"
            f"<td>{html.escape(fuzzer)}</td>"
            f'<td class="inc-col-domain">{html.escape(domain)}</td>'
            f"<td>{html.escape(ipaddr)}</td>"
            f"<td>{html.escape(ns)}</td>"
            f"<td>{html.escape(mx)}</td>"
            "</tr>"
        )

if not lines:
    lines.append('                <tr><td colspan="5">No data found.</td></tr>')

print("\n".join(lines))
PY
    else
        echo '                <tr><td colspan="5">No data found.</td></tr>' >> "$PAGE"
    fi

    {
        echo "            </tbody>"
        echo "        </table>"
        echo "    </div>"
        echo "</div>"
        echo
        echo '<script src="../assets/javascript/inc-data-table.js"></script>'
        echo "</body>"
        echo "</html>"
    } >> "$PAGE"
}

f_report_append_subdomains_page(){
    local PAGE="$1"

    if [ -f private-subs ]; then
        cat private-subs >> "$PAGE"
        echo >> "$PAGE"
        echo "$LARGE" >> "$PAGE"
        echo >> "$PAGE"
    fi

    if [ -f subdomains ]; then
        cat subdomains >> "$PAGE"
    elif [ ! -f private-subs ]; then
        echo "No data found." >> "$PAGE"
    fi

    {
        echo "</pre>"
        echo "    </div>"
        echo "</div>"
        echo
        echo "</body>"
        echo "</html>"
    } >> "$PAGE"
}

###############################################################################################################################

f_report() {
    echo "Summary" > zreport
    echo "$SMALL" >> zreport
    echo > tmp

    if [ -f names ]; then
    namecount=$(wc -l names | cut -d ' ' -f1)
    echo "Names                 $namecount" >> zreport
    echo "Names ($namecount)" >> tmp
    echo "$SMALL" >> tmp
    cat names >> tmp
    echo >> tmp
    f_report_append_pre_page names "$HOME"/data/"$DOMAIN"/pages/names.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/names.htm
fi

if [ -f emails ]; then
    emailcount=$(wc -l emails | cut -d ' ' -f1)
    echo "Emails                $emailcount" >> zreport
    echo "Emails ($emailcount)" >> tmp
    echo "$SMALL" >> tmp
    cat emails >> tmp
    echo >> tmp
    f_report_append_pre_page emails "$HOME"/data/"$DOMAIN"/pages/emails.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/emails.htm
fi

if [ -f records ]; then
    recordcount=$(wc -l records | cut -d ' ' -f1)
    echo "DNS Records           $recordcount" >> zreport
    echo "DNS Records ($recordcount)" >> tmp
    echo "$LARGE" >> tmp
    cat records >> tmp
    echo >> tmp
    f_report_append_pre_page records "$HOME"/data/"$DOMAIN"/pages/records.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/records.htm
fi

if [ -f squatting ]; then
    squattingcount=$(wc -l squatting | cut -d ' ' -f1)
    echo "Squatting             $squattingcount" >> zreport
    echo "Squatting ($squattingcount)" >> tmp
    echo "$LARGE" >> tmp
    column -t -s $'\t' squatting >> tmp
    echo >> tmp
    f_report_append_squatting_page "$HOME"/data/"$DOMAIN"/pages/squatting.htm
else
    f_report_append_squatting_page "$HOME"/data/"$DOMAIN"/pages/squatting.htm
fi

if [ -f public-ips ]; then
    publicipcount=$(wc -l public-ips | cut -d ' ' -f1)
    echo "Hosts                 $publicipcount" >> zreport
    echo "Hosts ($publicipcount)" >> tmp
    echo "$LARGE" >> tmp
    cat public-ips >> tmp
    echo >> tmp
    f_report_append_pre_page public-ips "$HOME"/data/"$DOMAIN"/pages/hosts.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/hosts.htm
fi

if [ -f private-subs ]; then
    privatesubcount=$(wc -l private-subs | cut -d ' ' -f1)
    echo "Private Subdomains    $privatesubcount" >> zreport
    echo "Private Subdomains ($privatesubcount)" >> tmp
    echo "$LARGE" >> tmp
    cat private-subs >> tmp
    echo >> tmp
fi

if [ -f subdomains ]; then
    subcount=$(wc -l subdomains | cut -d ' ' -f1)
    echo "Subdomains            $subcount" >> zreport
    echo "Subdomains ($subcount)" >> tmp
    echo "$LARGE" >> tmp
    cat subdomains >> tmp
    echo >> tmp
fi

f_report_append_subdomains_page "$HOME"/data/"$DOMAIN"/pages/subdomains.htm

if [ -f xls ]; then
    xlscount=$(wc -l xls | cut -d ' ' -f1)
    echo "Excel                 $xlscount" >> zreport
    echo "Excel Files ($xlscount)" >> tmp
    echo "$LARGE" >> tmp
    cat xls >> tmp
    echo >> tmp
    f_report_append_pre_page xls "$HOME"/data/"$DOMAIN"/pages/xls.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/xls.htm
fi

if [ -f pdf ]; then
    pdfcount=$(wc -l pdf | cut -d ' ' -f1)
    echo "PDF                   $pdfcount" >> zreport
    echo "PDF Files ($pdfcount)" >> tmp
    echo "$LARGE" >> tmp
    cat pdf >> tmp
    echo >> tmp
    f_report_append_pre_page pdf "$HOME"/data/"$DOMAIN"/pages/pdf.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/pdf.htm
fi

if [ -f ppt ]; then
    pptcount=$(wc -l ppt | cut -d ' ' -f1)
    echo "PowerPoint            $pptcount" >> zreport
    echo "PowerPoint Files ($pptcount)" >> tmp
    echo "$LARGE" >> tmp
    cat ppt >> tmp
    echo >> tmp
    f_report_append_pre_page ppt "$HOME"/data/"$DOMAIN"/pages/ppt.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/ppt.htm
fi

if [ -f txt ]; then
    txtcount=$(wc -l txt | cut -d ' ' -f1)
    echo "Text                  $txtcount" >> zreport
    echo "Text Files ($txtcount)" >> tmp
    echo "$LARGE" >> tmp
    cat txt >> tmp
    echo >> tmp
    f_report_append_pre_page txt "$HOME"/data/"$DOMAIN"/pages/txt.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/txt.htm
fi

if [ -f doc ]; then
    doccount=$(wc -l doc | cut -d ' ' -f1)
    echo "Word                  $doccount" >> zreport
    echo "Word Files ($doccount)" >> tmp
    echo "$LARGE" >> tmp
    cat doc >> tmp
    echo >> tmp
    f_report_append_pre_page doc "$HOME"/data/"$DOMAIN"/pages/doc.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/doc.htm
fi

cat tmp >> zreport

if [ -f whois-domain ]; then
    echo "Whois Domain" >> zreport
    echo "$LARGE" >> zreport
    cat whois-domain >> zreport
    f_report_append_pre_page whois-domain "$HOME"/data/"$DOMAIN"/pages/whois-domain.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/whois-domain.htm
fi

if [ -f whois-ip ]; then
    echo >> zreport
    echo "Whois IP" >> zreport
    echo "$LARGE" >> zreport
    cat whois-ip >> zreport
    f_report_append_pre_page whois-ip "$HOME"/data/"$DOMAIN"/pages/whois-ip.htm
else
    f_report_append_pre_page "" "$HOME"/data/"$DOMAIN"/pages/whois-ip.htm
fi

    f_report_append_pre_page zreport "$HOME"/data/"$DOMAIN"/pages/report.htm

    rm tmp* zreport 2>/dev/null

    mkdir -p "$HOME/data/$DOMAIN/tools"
    mv names emails hosts private-ips private-subs public-ips records squatting subdomains tmp* whois* z* doc pdf ppt txt xls "$HOME/data/$DOMAIN/tools/" 2>/dev/null
    cd "$PWD" || exit

    echo
    echo "$MEDIUM"
    echo
    echo -e "The supporting data folder is located at ${YELLOW}$HOME/data/$DOMAIN/${NC}\n"
}

###############################################################################################################################

f_firefox() {
    local USER_AGENTS OTHER_URLS GOOGLE_URLS url USER_AGENT sleep_time

    USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 Edg/147.0.3912.86"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
    "Mozilla/5.0 (X11; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:145.0) Gecko/20100101 Firefox/145.0"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/147.0.6778.73 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1"
    "Mozilla/5.0 (Linux; Android 15; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.6778.39 Mobile Safari/537.36"
    "Mozilla/5.0 (Android 15; Mobile; rv:145.0) Gecko/145.0 Firefox/145.0"
    )

    OTHER_URLS=(
    "https://dnsdumpster.com"
    "https://dockets.justia.com/search?parties=%22$COMPANYURL%22&cases=mostrecent"
    "https://intelx.io/?s=%40$DOMAIN&b=leaks.public.wikileaks,leaks.public.general,dumpster,documents.public.scihub"
    "https://networksdb.io/search/org/%22$COMPANYURL%22"
    "https://phonebook.cz"
    "https://shdn.io/analyze?target=$DOMAIN"
    "https://www.shodan.io/search?query=$DOMAIN"
    "https://$DOMAIN"
    )

    GOOGLE_URLS=(
    "https://www.google.com/search?q=%22$COMPANYURL%22+logo"
    "https://www.google.com/search?q=site:http://s3.amazonaws.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://blob.core.windows.net+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:dev.azure.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://drive.google.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:http://googleapis.com+%22$DOMAIN%22"
    "https://www.google.com/search?q=site:pastebin.com+%22$DOMAIN%22+password"
    "https://www.google.com/search?q=site:$DOMAIN+username+OR+password+OR+login+-Find"
    "https://www.google.com/search?q=site:$DOMAIN+ext:(doc+|docx+|xls+|xlsx+|ppt+|pptx)"
    "https://www.google.com/search?q=site:$DOMAIN+(filetype:pdf+OR+filetype:txt)"
    "https://www.google.com/search?q=site:$DOMAIN+%22index+of/%22+OR+%22parent+directory%22"
    "https://www.google.com/search?q=site:$DOMAIN+(%22highly+confidential%22+OR+%22restricted+access%22+OR+%22sensitive+data%22+OR+%22social+security+number%22+OR+%22passport+number%22+OR+%22employee+details%22+OR+%22salary+report%22+OR+%22performance+review%22+OR+%22personal+information%22+OR+%22internal+use+only%22+OR+%22proprietary+and+confidential%22)"
    "https://www.google.com/search?q=site:$DOMAIN+intitle%3Alogin+%7C+inurl%3Alogin+%7C+intitle%3Asignin+%7C+inurl%3Asignin+%7C+inurl%3Asecure"
    )

    for url in "${OTHER_URLS[@]}"; do
        USER_AGENT="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$USER_AGENT" 2>/dev/null &
        sleep $((RANDOM % 4 + 3))
    done

    for url in "${GOOGLE_URLS[@]}"; do
        USER_AGENT="${USER_AGENTS[$((RANDOM % ${#USER_AGENTS[@]}))]}"
        firefox "$url" --user-agent="$USER_AGENT" 2>/dev/null
        sleep $((RANDOM % 8 + 8))
    done
}

###############################################################################################################################

# Comment out functions for tools you don't want to run.

f_arin
f_dnsrecon
f_dnstwist
f_intodns
f_metasploit
f_subfinder
f_sublist3r
f_theharvester
f_theharvester_api
f_whois_domain
f_whois_ip
f_aggregate
f_report

###############################################################################################################################

f_runlocally
f_firefox

