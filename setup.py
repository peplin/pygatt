import os
import sys

__title__ = 'pygatt'
__version__ = '2.0.1'
__license__ = 'Apache License, Version 2.0 and MIT License'
__copyright__ = 'Copyright 2015 Stratos Inc. and Orion Labs'

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup  # pylint: disable=F0401,E0611


def publish():
    """Function for publishing package to pypi."""
    if sys.argv[-1] == 'publish':
        os.system('python setup.py sdist upload')
        sys.exit()


publish()

setup(
    name=__title__,
    version=__version__,
    description='Python GATT Module',
    author='Greg Albrecht <gba@orionlabs.co',
    author_email='gba@orionlabs.co',
    packages=find_packages(exclude=("tests", "tests.*")),
    package_data={'': ['LICENSE', 'NOTICE']},
    license=open('LICENSE').read(),
    long_description=open('README.mkd').read(),
    url='https://github.com/peplin/pygatt',
    install_requires=[
        'pyserial',
        'enum34'
    ],
    setup_requires=[
        'coverage >= 3.7.1',
        'nose >= 1.3.7'
    ],
    extras_require={
        'GATTTOOL': ["pexpect"],
    },
    package_dir={'pygatt': 'pygatt'},
    zip_safe=False,
    include_package_data=True
)
