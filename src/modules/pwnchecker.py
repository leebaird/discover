#!/usr/bin/env python3
# coding=utf-8
# Created by Jay Townsend aka L1ghtn1ng



import argparse
import requests

import src.core.webapis as webapi

parser = argparse.ArgumentParser(description='A tool to check if your email account has been in a breach By Jay Townsend')
parser.add_argument('-e', '--email-account', help='Email account(s) to lookup', required=True)
args = parser.parse_args()

headers = {'User-agent': 'HIBP Discover module https://github.com/leebaird/discover/'}
request = requests.get(webapi.DiscoverWebAPIS.haveibeenpwned(args.email_account), headers=headers)

if request.status_code == 404:
    print('Cannot find your account(s)')
else:
    entries = request.json()
    for entry in entries:
        print('Domain:', entry['Domain'])
        print('DateAdded:', entry['AddedDate'])
        print('BreachDate:', entry['BreachDate'])
        print(entry['Description'])
        print('IsSensitive:', entry['IsSensitive'])
        print('IsVerified:', entry['IsVerified'])
        print('PwnCount:', entry['PwnCount'])
