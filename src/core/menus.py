#!/usr/bin/env python3
# coding=utf-8


from src.core.discovercore import DiscoverColours


class DiscoverMenus:

    @staticmethod
    def mainmenu():
        print('''{0}
        RECON
        1.  Domain
        2.  Person
        3.  Parse salesforce

        SCANNING
        4.  Generate target list
        5.  CIDR
        6.  List
        7.  IP, range, or domain

        WEB
        8.  Open multiple tabs in Firefox

        MISC
        9. Crack WiFi
        10. Parse XML
        11. Generate a malicious payload
        12. Start a Metasploit listener
        13. Update
        14. Exit{1}'''.format(DiscoverColours.blue, DiscoverColours.end))
