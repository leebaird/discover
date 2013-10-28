#!/usr/bin/env python

f = open('tmp','r')                                # Setup a read connection to file
filedata = f.read()                                # Read the file
f.close()                                          # Close the connection
filedata = filedata.split('\n')                    # Turn into a list

##############################

out = []                                           # Create an empty array

for i in filedata:
     if '@' in i:                                  # grep '@'
          if not 'apples' in i:                    # grep -v 'apples'
               out.append(i.lower())               # Append to array and change to lower case

out = list(set(out))                               # Make list unique
out.sort()                                         # Sort

for j in out:
     print j
