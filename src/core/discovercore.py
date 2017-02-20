#!/usr/bin/env python3
# coding=utf-8

import os
from . import __VERSION__

class Discover(object):

    @staticmethod
    def banner():
        print('______  ___ ______ ______  _____  _    _ ______  _____')
        print('|     \  |  |____  |      |     |  \  /  |_____ |____/')
        print('|_____/ _|_ _____| |_____ |_____|   \/   |_____ |    \_')
        print()
        print('By Lee Baird')
        print('Version: {0}'.format(__VERSION__))

    @staticmethod
    def kali_check():
        """Checking to make sure the OS is supported"""
        with open('/etc/os-release', 'r') as OS:
            data = OS.read()
            if 'kali' in data:
                return True
            else:
                return False


class DiscoverColours(object):
        cyan = "\033[96m"
        blue = "\033[94m"
        green = "\033[92m"
        yellow = "\033[93m"
        red = "\033[91m"
        end = "\033[0m"
