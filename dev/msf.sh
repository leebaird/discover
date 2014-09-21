#!/bin/bash

clear

user=$(grep 'rapid7_database_user' /opt/metasploit/properties.ini | cut -d '=' -f2)
password=$(grep 'database_password' /opt/metasploit/properties.ini | cut -d '=' -f2)
port=$(grep 'postgres_port' /opt/metasploit/properties.ini | cut -d '=' -f2)
name=$(grep 'database_name' /opt/metasploit/properties.ini | cut -d '=' -f2)

service postgresql start
service metasploit start

echo
echo 'Be patientient while Metasploit loads and connects to the database (~75 sec).'
echo

echo db_connect $user:$password@127.0.0.1:$port/$name > /tmp/msf
msfconsole -r /tmp/msf
