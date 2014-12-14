#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Setup for the APRS Python Module.
Source:: https://github.com/ampledata/aprs
"""


__title__ = 'pygatt'
__version__ = '1.0.0'
__author__ = 'Greg Albrecht <gba@onbeep.com>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2014 OnBeep, Inc.'


import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup  # pylint: disable=F0401,E0611


def publish():
    """Function for publishing package to pypi."""
    if sys.argv[-1] == 'publish':
        os.system('python setup.py sdist upload')
        sys.exit()


publish()


setup(
    name='pygatt',
    version=__version__,
    description='Python GATT Module',
    author='Greg Albrecht',
    author_email='gba@onbeep.com',
    packages=['pygatt'],
    package_data={'': ['LICENSE', 'NOTICE']},
    license=open('LICENSE').read(),
    long_description=open('README.rst').read(),
    url='https://github.com/ampledata/pygatt',
    install_requires=['pexpect'],
    setup_requires=[
      'coverage==3.7.1',
      'nose==1.3.1'
    ],
    package_dir={'pygatt': 'pygatt'},
    zip_safe=False,
    include_package_data=True
)
