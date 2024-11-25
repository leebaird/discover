#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

echo "recon-ng"
echo
echo "For historic purposes."
exit

echo "marketplace refresh" > passive.rc
echo "marketplace install all" >> passive.rc
echo "workspaces create $DOMAIN" >> passive.rc
echo "db insert companies" >> passive.rc
echo "$COMPANYURL" >> passive.rc
sed -i 's/%26/\&/g; s/%20/ /g; s/%2C/\,/g' passive.rc
echo "none" >> passive.rc
echo "none" >> passive.rc
echo "db insert domains" >> passive.rc
echo "$DOMAIN" >> passive.rc
echo "none" >> passive.rc

if [ -f emails ]; then
    cp emails /tmp/tmp-emails
    cat "$DISCOVER"/resource/recon-ng-import-emails.rc >> passive.rc
fi

if [ -f names ]; then
    echo "last_name#first_name#title" > /tmp/names.csv
    cat names >> /tmp/names.csv
    cat "$DISCOVER"/resource/recon-ng-import-names.rc >> passive.rc
fi

cat "$DISCOVER"/resource/recon-ng.rc >> passive.rc
cat "$DISCOVER"/resource/recon-ng-cleanup.rc >> passive.rc
sed -i "s/yyy/$DOMAIN/g" passive.rc

recon-ng -r "$CWD"/passive.rc

###############################################################################################################################

grep '@' /tmp/emails | awk '{print $2}' | grep -Eiv '(>|query|select)' | sort -u > emails2
cat emails emails2 | sort -u > emails-final

grep '|' /tmp/names | grep -v last_name | sort -u | sed 's/|/ /g' | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > names-final

grep '/' /tmp/networks | grep -v 'Spooling' | awk '{print $2}' | $SIP > tmp
cat tmp networks | sort -u | $SIP > networks-final

grep "\.$DOMAIN" /tmp/subdomains | grep -Eiv '(\*|%|>|select|www)' | awk '{print $2,$4}' | sed 's/|//g' | column -t | sort -u > tmp
#cat subdomains tmp | grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -Eiv '(outlook|www)' | tr 'A-Z' 'a-z' | column -t | sort -u | sed 's/[ \t]*$//' > subdomains-final
cat subdomains tmp | grep -Eiv '(outlook|www)' | tr 'A-Z' 'a-z' | column -t | sort -u | sed 's/[ \t]*$//' > subdomains-final

# Find hosts
cat z* subdomains-final | grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -Eiv '(0.0.0.0|1.1.1.1|1.1.1.2|8.8.8.8|127.0.0.1)' | sort -u | $SIP > hosts

find . -type f -empty -delete
