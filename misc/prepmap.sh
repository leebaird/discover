#!/usr/bin/bash

# https://www.darrinward.com/lat-long/

cat /root/tmp | egrep -v '(\+|latitude|returned|Spooling|stop)' | sed 's/| //g' | sed 's/|//g' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/    /,/g' | sed 's/  /,/g' | sed '/^$/d' > /root/latlong.txt
echo
echo
