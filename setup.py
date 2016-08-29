#!/usr/bin/env python3

from setuptools import setup

setup(
    name='Discover',
    url='http://github.com/leebaird/discover/',
    license='MIT',
    author='Lee Baird',
    author_email='leebaird@gmail.com',
    zip_safe=False,
    install_requires=[
        'shodan>=1.5.5',
        'dnspython>=1.14.0',
    ])
