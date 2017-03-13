#!/usr/bin/env python3


class DiscoverWebAPIS(object):

    @staticmethod
    def dnslookup(domain: str) -> str:
        """ HackerOne DNS lookup limited to 100 queries a day
        :param domain:
        :return: str
        """
        return 'http://api.hackertarget.com/dnslookup/?q={}'.format(domain)

    @staticmethod
    def haveibeenpwned(email_account: str) -> str:
        """
        HaveIBeenPwned.com email account(s) breach API
        This service tells you I you have been in any breaches
        :param email_account: str
        :return: str
        """
        return 'https://haveibeenpwned.com/api/v2/breachedaccount/{0}'.format(email_account)
