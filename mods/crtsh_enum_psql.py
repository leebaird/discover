#!/usr/bin/env python3

__author__ = 'Bharath'
__version__ = "0.1.0"

import json
import logging
import re
import sys

from os.path import abspath

try:
    import psycopg2
except ImportError:
    raise ImportError('\n\033[33mpsycopg2 library missing. pip3 install -r requirements.txt\033[1;m\n')

try:
    import click
except ImportError:
    raise ImportError('\n\033[33mclick library missing. pip3 install -r requirements.txt\033[1;m\n')

try:
    import dns.resolver
except ImportError:
    raise ImportError('\n\033[33mdnspython library missing. pip3 install -r requirements.txt\033[1;m\n')

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

DB_HOST = 'crt.sh'
DB_NAME = 'certwatch'
DB_USER = 'guest'
DB_PASSWORD = ''


def connect_to_db(domain_name):
    try:
        conn = psycopg2.connect("dbname={0} user={1} host={2}".format(DB_NAME, DB_USER, DB_HOST))
        conn.autocommit = True
        cursor = conn.cursor()
        cursor.execute("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(domain_name))
    except ConnectionError:
        logging.info("\n\033[1;31m[!] Unable to connect to the database\n\033[1;m")
    return cursor


def get_unique_domains(cursor, domain_name):
    unique_domains = []
    for result in cursor.fetchall():
        matches = re.findall(r"\'(.+?)\'", str(result))
        for subdomain in matches:
            if subdomain not in unique_domains:
                if ".{}".format(domain_name) in subdomain:
                    unique_domains.append(subdomain)
    return unique_domains


def do_dns_resolution(unique_domains):
    dns_resolution_results = {}
    for domain in set(unique_domains):
        domain = domain.replace('*.', '')
        dns_resolution_results[domain] = {}
        try:
            for qtype in ['A', 'CNAME']:
                dns_answer = dns.resolver.query(domain,qtype, raise_on_no_answer=False)
                if dns_answer.rrset is None:
                    pass
                elif dns_answer.rdtype == 1:
                    a_records = [str(i) for i in dns_answer.rrset]
                    dns_resolution_results[domain]["A"] = a_records
                elif dns_answer.rdtype == 5:
                    cname_records = [str(i) for i in dns_answer.rrset]
                    dns_resolution_results[domain]["CNAME"] = cname_records
                else:
                    dns_resolution_results[domain]["A"] = "bla"
                    dns_resolution_results[domain]["CNAME"] = "bla bla"
        except dns.resolver.NXDOMAIN:
            dns_resolution_results[domain]["A"] = "No such domain"
            pass
        except dns.resolver.Timeout:
            dns_resolution_results[domain]["A"] = "Timed out while resolving"
            dns_resolution_results[domain]["CNAME"] = "Timed out error while resolving"
            pass
        except dns.exception.DNSException:
            dns_resolution_results[domain]["A"] = "Unknown error while resolving"
            dns_resolution_results[domain]["CNAME"] = "Unknown error while resolving"
            pass
    return dns_resolution_results


def print_json_results(domain, dns_resolution_results):
    print(json.dumps(dns_resolution_results))
    results_file = "{}_results.json".format(domain)
    with open(results_file, 'w+') as results_file:
        json.dump(dns_resolution_results, results_file, default=str)
        file_path = abspath(results_file.name)
    logging.info("\033[1;32m[+] Results written to JSON file : {}\033[1;m".format(file_path))


@click.command()
@click.argument('domain')
@click.option('--resolve/--no-resolve', '-r', default=False, help='Enable/Disable DNS resolution')
@click.option('--output', '-o', default='json', help='Output in JSON format')
def main(domain, resolve, output):
    domain_name = domain
    cursor = connect_to_db(domain_name)
    unique_domains = get_unique_domains(cursor, domain_name)

    if resolve == False:
        for domain in unique_domains:
            print(domain)
        sys.exit()
    else:
        dns_resolution_results = do_dns_resolution(unique_domains)
        print_json_results(domain, dns_resolution_results)


if __name__ == '__main__':
    main()
