import os
import sys

__title__ = 'pygatt'
__version__ = '1.0.1'
__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs'

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
    author='Greg Albrecht <gba@orionlabs.co',
    author_email='gba@orionlabs.co',
    packages=['pygatt'],
    package_data={'': ['LICENSE', 'NOTICE']},
    license=open('LICENSE').read(),
    long_description=open('README.mkd').read(),
    url='https://github.com/ampledata/pygatt',
    install_requires=[
        'pyserial',
        'enum34',
        'click',
    ],
    extras_require={
        'GATTTOOL': ["pexpect"],
    },
    package_dir={'pygatt': 'pygatt'},
    zip_safe=False,
    include_package_data=True
)
