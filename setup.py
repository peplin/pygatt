from setuptools import setup, find_packages

from pygatt.version import get_version

setup(name='pygatt',
    version=get_version(),
    author='Christopher Peplin',
    author_email='peplin@getprotean.com',
    license='MIT',
    packages=find_packages(exclude=["tests", "tests.*"])
)
