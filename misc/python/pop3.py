#!/usr/bin/python
import socket

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

try:
     print "[*] Sending evil buffer."
     socket.setdefaulttimeout(3)           # Sets a 3 sec timeout
     s.connect(('10.0.0.22',110))          # Connect to IP, POP3 port
     data = s.recv(1024)                   # Receive banner
     print data                            # Print banner

     s.send('USER test' + '\r\n')          # Send username "test"
     data = s.recv(1024)                   # Receive reply
     print data                            # Print reply

     s.send('PASS test' + '\r\n')          # Send password "test"
     data = s.recv(1024)                   # Receive reply
     print data                            # Print reply

     s.close()                             # Close socket
     print "\n[*] Done"
except:
     print "[!] Could not connect to the POP3 server."
