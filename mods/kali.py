#!/usr/bin/python3

import platform
import subprocess


YELLOW = '\033[93m'
ENDC = '\033[0m'


if platform.linux_distribution()[2] == 'sana':
    subprocess.getstatusoutput('msfdb reinit')
    print('{0}Updating Kali 2.0{1}\n'.format(YELLOW, ENDC))
    subprocess.getstatusoutput('apt-get update; apt-get -y upgrade; apt-get clean')
else:
    print('{0}Updating Kali{1}\n'.format(YELLOW, ENDC))
    subprocess.getstatusoutput('apt-get update; apt-get -y dist-upgrade; apt-get -y autoremove; apt-get -y autoclean')

