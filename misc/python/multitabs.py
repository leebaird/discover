# multitabs.py
#
# By Lee Baird
# Feel free to contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
##############################################################################################################

os.system('clear')
banner()

runlocally()

print colorblue.format('Open multiple tabs in Firefox with:')
print
print '1. List containing IPs and/or URLs.'
print '2. Directories from a domain\'s robot.txt.'
print '3. Previous menu'
print
choice = raw_input('Choice: ')

if choice == "1":
     print
     location = raw_input('Enter the location of your list: ')

     if os.path.isfile(location):
          f = open(location,'r') # Setup a read connection directory
          filedata = f.read() # Read the file
          f.close() # Close the connection
          filedata = filedata.split('\n') # Turn into a list
          filedata = [x for x in filedata if not x == ""] # Ignore blank lines

          port = raw_input('Port: ')

          if port.isdigit():
               if int(port) in range(1,65535):
                    if port == "21":
                         for i in filedata:
                              webbrowser.open('ftp://'+i)
                              time.sleep(1)
                    elif port == "80":
                         for i in filedata:
                              webbrowser.open('http://'+i)
                              time.sleep(1)
                    elif port == "443":
                         for i in filedata:
                              webbrowser.open('https://'+i)
                              time.sleep(1)
                    else:
                         for i in filedata:
                              webbrowser.open('http://'+i+':'+port)
                              time.sleep(1)
               else:
                    error()
          else:
               error()
     else:
          error()

if choice == "2":
     print
     print line
     print
     print 'Usage: target.com or target-IP'
     print
     domain = raw_input('Domain: ')

     # Check for no answer
     if domain == "":
          error()

     response = urllib2.urlopen('http://'+domain+'/robots.txt')
     robots = response.read()
     robots = robots.split('\n')
     
     for i in robots:
          if 'Disallow' in i:
               j = i.split(' ')
               f = open(os.path.expanduser('~')+'/'+domain+'-robots.txt','a')
               f.write(j[1]+'\n')
               f.close()
               webbrowser.open('http://'+domain+j[1])
               time.sleep(1)

     print
     print line
     print
     print '***Scan complete.***'
     print
     print 'The new report is located at /'+user+'/'+domain+'-robots.txt'
     print
     print
     sys.exit(0)

if choice == "3":
     main()
else:
     error()
