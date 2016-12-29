#!/usr/bin/python3



class DiscoverWebAPIS:

    @staticmethod
    def dnslookup(domain: str) -> str:
        """ HackerOne DNS lookup limited to 100 quires a day
        :param domain:
        :return:
        """
        return 'http://api.hackertarget.com/dnslookup/?q={}'.format(domain)
