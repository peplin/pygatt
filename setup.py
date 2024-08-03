__title__ = "pygatt"
__version__ = "5.0.0"
__license__ = "Apache License, Version 2.0 and MIT License"
__copyright__ = "Copyright 2015 Stratos Inc. and Orion Labs"

try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup  # pylint: disable=F0401,E0611

with open("README.rst") as f:
    readme = f.read()
with open("CHANGELOG.rst") as f:
    changelog = f.read()

setup(
    name=__title__,
    version=__version__,
    description="Python Bluetooth LE (Low Energy) and GATT Library",
    author="Chris Peplin <github@rhubarbtech.com>",
    author_email="github@rhubarbtech.com",
    packages=find_packages(exclude=("tests", "tests.*")),
    package_data={"": ["LICENSE"]},
    license="Apache 2.0 and MIT",
    long_description=readme + "\n\n" + changelog,
    url="https://github.com/peplin/pygatt",
    install_requires=["pyserial", "enum-compat"],
    setup_requires=["coverage == 5.5", "pytest == 8.3.2"],
    extras_require={
        "GATTTOOL": ["pexpect"],
    },
    package_dir={"pygatt": "pygatt"},
    zip_safe=False,
    include_package_data=True,
    classifiers=(
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ),
)
