#!/usr/bin/python3



class DiscoverWebAPIS:

    @staticmethod
    def dnslookup(domain: str) -> str:
        """ HackerTarget.com API limited to 100 quires a day
        :param domain:
        :return: str:
        """
        return 'http://api.hackertarget.com/dnslookup/?q={}'.format(domain)
