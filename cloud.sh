#!/usr/bin/env bash

# by Lee Baird (@discoverscripts)

set -euo pipefail

echo
echo "Seach cloud providers for spillage."
echo
echo -n "Domain: "
read -r domain

# Check for no answer
if [ -z "$domain" ]; then
    echo
    echo "[!] No domain entered."
    echo
    exit 1
fi

xdg-open https://www.google.com/search?q=site:http://s3.amazonaws.com+%22"$domain"%22 &
sleep 4
xdg-open https://www.google.com/search?q=site:http://blob.core.windows.net+%22"$domain"%22 &
sleep 5
xdg-open https://www.google.com/search?q=site:http://googleapis.com+%22"$domain"%22 &
sleep 6
xdg-open https://www.google.com/search?q=site:http://drive.google.com+%22"$domain"%22 &
