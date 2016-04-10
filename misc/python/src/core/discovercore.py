#!/usr/bin/python3

from colorama import Fore


class Discover(object):
    @staticmethod
    def banner():
        print('______  ___ ______ ______  _____  _    _ ______  _____')
        print('|     \  |  |____  |      |     |  \  /  |_____ |____/')
        print('|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_')
        print()
        print('By Lee Baird')

    @staticmethod
    def os_check():
        """Checking to make sure the OS is supported"""
        with open('/etc/os-release', 'r') as OS:
            data = OS.read()
            if 'kali' in data:
                print()
            else:
                print(Fore.RED + '[!]OS not supported')