# recon.py
#
# By Lee Baird
# Feel free to contact me via chat or email with any feedback or suggestions that you may have:
# leebaird@gmail.com
#
##############################################################################################################

os.system('clear')
banner()

print colorblue.format('RECON')
print
print '1.  Company'
print '2.  Person'
print '3.  Previous menu'
print
choice = raw_input('Choice: ')

if choice == "1":
     os.system('clear')
     banner()
     print colorblue.format('RECON')
     print
     print '1.  Passive'
     print '2.  Active'
     print '3.  Previous menu'
     print
     choice = raw_input('Choice: ')

     if choice == "1":
          print
          print line
          print
          print 'Usage: target.com'
          print
          domain = raw_input('Domain: ')

          # Check for no answer
          if domain == "":
               error()

          print
          print line
          print

          # If folder doesn't exist, create it
          if not os.path.exists('/'+user+'/'+domain):
               os.makedirs('/'+user+'/'+domain)

          # Number of tests
          total = 27

          print 'goofile                   (1/'+str(total)+')'
          os.system('goofile -d '+domain+' -f doc > tmp')
          os.system('goofile -d '+domain+' -f docx >> tmp')
          os.system('goofile -d '+domain+' -f pdf >> tmp')          
          os.system('goofile -d '+domain+' -f ppt >> tmp')
          os.system('goofile -d '+domain+' -f pptx >> tmp')
          os.system('goofile -d '+domain+' -f txt >> tmp')          
          os.system('goofile -d '+domain+' -f xls >> tmp')
          os.system('goofile -d '+domain+' -f xlsx >> tmp')

          f_doc = open('doc.txt','a')
          f_pdf = open('pdf.txt','a')
          f_ppt = open('ppt.txt','a')          
          f_txt = open('txt.txt','a')
          f_xls = open('xls.txt','a')          
          
          f = open('tmp','r')                                # Setup a read connection to file
          filedata = f.read()                                # Read the file
          f.close()                                          # Close the connection
          filedata = filedata.split('\n')                    # Turn into a list

          for i in filedata:
               if domain in i:
                    if not 'Searching in' in i:
                         if '.doc' in i:
                              if not '.pdf, .ppt, .xls' in i:
                                   f_doc.write(i.lower()+'\n')
                         elif '.pdf' in i:
                              f_pdf.write(i.lower()+'\n')
                         elif '.ppt' in i:
                              f_ppt.write(i.lower()+'\n')                              
                         elif '.txt' in i:
                              f_txt.write(i.lower()+'\n')                              
                         elif '.xls' in i:
                              f_xls.write(i.lower()+'\n')                              

          # Files need sorted.
          
          f_doc.close()
          f_pdf.close()
          f_ppt.close()
          f_txt.close()                    
          f_xls.close()
          
          ##############################################################

          runlocally()

          webbrowser.open('https://www.arin.net')
          time.sleep(1)
          webbrowser.open('http://toolbar.netcraft.com/site_report?url=http://www.'+domain)
          time.sleep(1)
          webbrowser.open('http://uptime.netcraft.com/up/graph?site=www.'+domain)
          time.sleep(1)
          webbrowser.open('http://www.shodanhq.com/search?q='+domain)
          time.sleep(1)
          webbrowser.open('http://www.jigsaw.com/')
          time.sleep(1)
          webbrowser.open('http://pastebin.com/')
          time.sleep(1)
          webbrowser.open('http://www.google.com/#q=filetype%3Axls+OR+filetype%3Axlsx+site%3A'+domain)
          time.sleep(1)
          webbrowser.open('http://www.google.com/#q=filetype%3Appt+OR+filetype%3Apptx+site%3A'+domain)
          time.sleep(1)
          webbrowser.open('http://www.google.com/#q=filetype%3Adoc+OR+filetype%3Adocx+site%3A'+domain)
          time.sleep(1)
          webbrowser.open('http://www.google.com/#q=filetype%3Apdf+site%3A'+domain)
          time.sleep(1)
          webbrowser.open('http://www.google.com/#q=filetype%3Atxt+site%3A'+domain)
          time.sleep(1)
          webbrowser.open('http://www.sec.gov/edgar/searchedgar/companysearch.html')
          time.sleep(1)
          webbrowser.open('http://www.google.com/finance/')
          goodbye()

     if choice == "2": 
          print 'Active - Coming soon...'
          goodbye()

     if choice == "3":
          execfile('recon.py')
     else: 
          error()

if choice == "2": 
     runlocally()
     print
     print line
     print

     firstname = raw_input('First name: ')
     if firstname == "":
          error()
     print
     lastname = raw_input('Last name: ')
     if lastname == "":
          error()

     webbrowser.open('http://www.123people.com/s/'+firstname+'+'+lastname)
     time.sleep(1)
     webbrowser.open('http://www.411.com/name/'+firstname+'-'+lastname)
     time.sleep(1)
     webbrowser.open('http://www.cvgadget.com/person/'+firstname+'/'+lastname)
     time.sleep(1)
     webbrowser.open('http://www.peekyou.com/'+firstname+'_'+lastname)
     time.sleep(1)
     webbrowser.open('http://phonenumbers.addresses.com/people/'+firstname+'+'+lastname)
     time.sleep(1)
     webbrowser.open('http://search.nndb.com/search/nndb.cgi?nndb=1&omenu=unspecified&query='+firstname+'+'+lastname)
     time.sleep(1)
     webbrowser.open('http://www.spokeo.com/search?q='+firstname+'+'+lastname+'&s3=t24')
     time.sleep(1)
     webbrowser.open('http://www.zabasearch.com/query1_zaba.php?sname='+firstname+'%20'+lastname+'&state=ALL&ref=$ref&se=$se&doby=&city=&name_style=1&tm=&tmr=')

     main()

if choice == "3":
     main()
else: 
     error()

