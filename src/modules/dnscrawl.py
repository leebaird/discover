#!/usr/bin/env python3
# coding=utf-8

# Created by Jay Townsend aka L1ghtn1ng
# I Jay Townsend here by grant Lee Baird to use this in discover project
# TODO add zone transfer feature

import dns.name
import dns.message
import dns.query
import dns.flags
import dns.rdatatype
import dns.exception
import argparse


parser = argparse.ArgumentParser(description='A script to get DNS information for a domain')
parser.add_argument('-d', '--domain', help='Domain to lookup', required=True)
parser.add_argument('-t', '--type', help='Record type to lookup', default='a')
parser.add_argument('-n', '--name-server',
                    help='Name server to use for the lookup, default is Googles', default='8.8.8.8')

args = parser.parse_args()
ADDITIONAL_RDCLASS = 65535
domain = dns.name.from_text(args.domain)

if not domain.is_absolute():
    domain = domain.concatenate(dns.name.root)

try:
    request = dns.message.make_query(domain, dns.rdatatype.ANY)
    request.flags |= dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                       dns.rdatatype.OPT, create=True, force_unique=True)
    response = dns.query.tcp(request, args.name_server)

    if 'See draft-ietf-dnsop-refuse-any' in response.answer[0].to_text():
        request = dns.message.make_query(domain, args.type)
        request.flags |= dns.flags.AD
        request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                           dns.rdatatype.OPT, create=True, force_unique=True)
        response = dns.query.tcp(request, args.name_server)
        for answer in response.answer:
            print(answer)
    else:
        for answer in response.answer:
            print(answer)

except dns.exception.Timeout:
    print('A timeout has occurred, make sure you can reach the target DNS Server(s)')
