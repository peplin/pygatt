__title__ = 'pygatt'
__version__ = '3.1.0'
__license__ = 'Apache License, Version 2.0 and MIT License'
__copyright__ = 'Copyright 2015 Stratos Inc. and Orion Labs'

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup  # pylint: disable=F0401,E0611

setup(
    name=__title__,
    version=__version__,
    description='Python Bluetooth LE (LowEnergy) and GATT Library',
    author='Chris Peplin <github@rhubarbtech.com>',
    author_email='github@rhubarbtech.com',
    packages=find_packages(exclude=("tests", "tests.*")),
    package_data={'': ['LICENSE']},
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
