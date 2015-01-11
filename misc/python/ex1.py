#!/usr/bin/env python

import os
import sys

os.system('clear')
port = raw_input('\nEnter a valid port: ')

if port == '':
     print '\nYou did not enter anything.\n\n'
     sys.exit(1)

try:
     val = int(port)
except ValueError:
     print('\nThat is not an number.\n\n')
     sys.exit(1)

if int(port) not in range(1,65535):
     print '\nThat is an invalid port.\n\n'
else:
     print '\nThat is a valid port.\n\n'

