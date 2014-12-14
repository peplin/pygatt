#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Utils for pygatt Module.
"""

__author__ = 'Greg Albrecht <gba@onbeep.com>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2014 OnBeep, Inc.'


import re
import subprocess

import pexpect


# TODO(gba): Replace with Fabric.
def reset_bluetooth_controller(hci_device='hci0'):
    """
    Re-initializses Bluetooth Controller Interface.
    This is accomplished by bringing down and up the interface.

    :param interface: Interface to re-initialize.
    :type interface: str
    """
    subprocess.Popen(["sudo", "hciconfig", hci_device, "down"]).wait()
    subprocess.Popen(["sudo", "hciconfig", hci_device, "up"]).wait()


# TODO(gba): Replace with Fabric.
def lescan(timeout=5, use_sudo=True):
    """
    Performs a BLE scan using hcitool.

    :param timeout: Time (in seconds) to wait for the scan to complete.
    :param use_sudo: Perform scan as superuser.
    :type timeout: int
    :type use_sudo: bool
    :return: List of BLE devices found.
    :rtype: list
    """
    if use_sudo:
        cmd = 'sudo hcitool lescan'
    else:
        cmd = 'hcitool lescan'

    scan = pexpect.spawn(cmd)

    # "lescan" doesn't exit, so we're forcing a timeout here:
    try:
        scan.expect('foooooo', timeout=timeout)
    except pexpect.TIMEOUT:
        devices = {}
        for line in scan.before.split('\r\n'):
            match = re.match(
                r'(([0-9A-Fa-f][0-9A-Fa-f]:?){6}) (\(?[\w]+\)?)', line)

            if match is not None:
                name = match.group(1)
                devices[name] = {
                    'address': match.group(1),
                    'name': match.group(3)
                }

    return [device for device in devices.values()]
