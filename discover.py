#!/usr/bin/env python3


from src.core.discovercore import Discover
from src.core.menus import *
from src.core.webapis import *
import requests



Discover.banner()
lookup = input('Enter domain to lookup: ')
data = requests.get(DiscoverWebAPIS.dnslookup(lookup))
print(data)