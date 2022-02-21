#!/usr/bin/bash

echo
echo -n "Enter the location of your folder: "
read -e location

# Check for no answer
if [[ -z $location ]]; then
     echo 'No answer.'
     echo
     exit
fi

# Check for wrong answer
if [ ! $location ]; then
     echo 'Wrong location.'
     echo
     exit
fi

cd $location

sed -i 's|href="https://github.com/leebaird/discover"|href="https://www.acme.org"|g' index.htm
cd pages/
sed -i 's|href="https://github.com/leebaird/discover"|href="https://www.acme.org"|g' *.htm

firefox ../index.htm &
