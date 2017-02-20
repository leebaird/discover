#!/usr/bin/env python3

from setuptools import setup

setup(
    name='Discover',
    url='http://github.com/leebaird/discover/',
    license='MIT',
    author='Lee Baird',
    author_email='leebaird@gmail.com',
    install_requires=[
        'shodan>=1.6.3',
        'dnspython>=1.15.0',
        'requests>=2.13.0'
    ])
