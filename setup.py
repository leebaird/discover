#!/usr/bin/env python3

from setuptools import setup
from .src.core import __VERSION__

setup(
    name='Discover',
    version=__VERSION__,
    url='http://github.com/leebaird/discover/',
    license='MIT',
    author='Lee Baird',
    author_email='leebaird@gmail.com',
    description='A Python framework for doing OSINT on a targert for a pentest ',
    install_requires=[
        'shodan>=1.7.1',
        'dnspython>=1.15.0',
        'requests>=2.18.1'
    ])
