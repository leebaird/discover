#!/usr/bin/env python3


from src.core.discovercore import Discover
from src.core.menus import *
from src.core.webapis import *



Discover.banner()
DiscoverMenus.main_menu()
#domain = input('Enter domain to lookup: ')
#data = requests.get(DiscoverWebAPIS.dnslookup(domain=domain)).text
#print(data)