#!/bin/bash
clear

DIR=/root/Desktop/compare-sites
DIFFONLY=false

usage(){
echo
echo
echo "Compare changes to home pages."
echo
echo
echo "Where file contains a list of URLs to be compared."
echo "Usage: $0 [options] file"
echo
echo "Options:"
echo " -c Compare versions."
echo " -o Output directory. Default: /root/Desktop/compare-sites"
echo
echo
}

ts2date(){
date -d "1970-01-01 $1 sec"
}

while getopts "o:c" OPTION; do
case $OPTION in
          o) DIR="$OPTARG";;
          c) DIFFONLY=true;;
          *) echo && echo && exit;;
     esac
done

shift $(($OPTIND - 1))
FILE=$*

if [ -z $FILE ]; then
     usage
     exit
fi

if [ ! -f $FILE ]; then
     echo
     echo
     echo "File does not exist."
     echo
     echo
     exit
fi

if [ ! -d $DIR ]; then
     mkdir $DIR
fi

FILEHASH=${FILEHASH%%$FILE} # remove input file name from hash string (sha256sum)
HDIR="$DIR/$FILEHASH"
VERSION=1

while [ -f $HDIR/$VERSION ]; do
     VERSION=$(($VERSION + 1))
done

if ! $DIFFONLY; then
     date +%s > $HDIR/$VERSION
     echo
     echo
     echo "Downloading:"

     for URL in $(cat $FILE); do
          HASH=$(sha256sum <<<$URL | tr -d " -")
          echo "[*] $URL"
          wget -q $URL -O $HDIR/$URL-$HASH-$VERSION
     done

     echo
     echo "======================================================================"
else
     VERSION=$(($VERSION - 1))
fi

if [ $VERSION -gt 1 ]; then
     echo
     echo "Versions:"

     for ((i=1; i<=${VERSION}; i++)); do
          echo $i - $(ts2date $(cat $HDIR/$i))
     done

     echo
     echo -n "Base version: "
     read A
     echo -n "Compare with: "
     read B

     [ -z $A ] && A="1";
     [ -z $B ] && B=$VERSION

     for URL in $(cat $FILE); do
          echo
          echo "======================================================================"
          echo
          echo -e "\e[1;34m$URL\e[0m"
          HASH=$(sha256sum <<<$URL | tr -d " -")
          diff $HDIR/$URL-$HASH-$A $HDIR/$URL-$HASH-$B | grep '<iframe src='
          # frames, window.location, window.href
     done
fi
