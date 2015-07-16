from __future__ import print_function

import logging
import platform
import re
import subprocess
import sys
try:
    import pexpect
except Exception as e:
    if platform.system() != 'Windows':
        print("WARNING:", e, file=sys.stderr)

from exceptions import BluetoothLEError


"""
MODIFIED Utils for pygatt Module.
"""

__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs'


logger = logging.getLogger(__name__)


def reset_bluetooth_controller(hci_device='hci0', bled112=None):
    """
    Re-initializses Bluetooth Controller Interface.
    This is accomplished by bringing down and up the interface.

    interface -- Interface to re-initialize.
    bled112 -- (BLED112 only) BLED112Backend object to use.
    """
    if bled112 is None:  # GATTTOOL
        # TODO(gba): Replace with Fabric.
        subprocess.Popen(["sudo", "systemctl", "restart", "bluetooth"]).wait()
        subprocess.Popen(["sudo", "hciconfig", hci_device, "reset"]).wait()
    else:  # BLED112Backend object
        bled112.disconnect(fail_quietly=True)
        bled112.delete_stored_bonds()


def lescan(timeout=5, use_sudo=True, bled112=None):
    """
    Performs a BLE scan.

    When using GATTTOOL, if you don't want to use 'sudo', you must add a few
    'capabilities' to your system. If you have libcap installed, run this to
    enable normal users to perform LE scanning:
        setcap 'cap_net_raw,cap_net_admin+eip' `which hcitool`
    If you do use sudo, the hcitool subprocess becomes more difficult to
    terminate cleanly, and may leave your Bluetooth adapter in a bad state.

    timeout -- Time (in seconds) to wait for the scan to complete.
    use_sudo -- (GATTTOOL only) Perform scan as superuser.
    bled112 -- (BLED112 only) BLED112Backend object to use.

    Returns a list of BLE devices found.
    """
    if bled112 is None:  # GATTTOOL
        # TODO(gba): Replace with Fabric.
        cmd = 'hcitool lescan'
        if use_sudo:
            cmd = 'sudo %s' % cmd

        logger.info("Starting BLE scan")
        scan = pexpect.spawn(cmd)
        # "lescan" doesn't exit, so we're forcing a timeout here:
        try:
            scan.expect('foooooo', timeout=timeout)
        except pexpect.EOF:
            message = "Unexpected error when scanning"
            if "No such device" in scan.before:
                message = "No BLE adapter found"
            logger.error(message)
            raise BluetoothLEError(message)
        except pexpect.TIMEOUT:
            devices = {}
            for line in scan.before.split('\r\n'):
                match = re.match(
                    r'(([0-9A-Fa-f][0-9A-Fa-f]:?){6}) (\(?[\w]+\)?)', line)

                if match is not None:
                    address = match.group(1)
                    name = match.group(3)
                    if name == "(unknown)":
                        name = None

                    if address in devices:
                        if (devices[address]['name'] is None) and (name is not
                                                                   None):
                            logger.info("Discovered name of %s as %s",
                                        address, name)
                            devices[address]['name'] = name
                    else:
                        logger.info("Discovered %s (%s)", address, name)
                        devices[address] = {
                            'address': address,
                            'name': name
                        }
            logger.info("Found %d BLE devices", len(devices))
            return [device for device in devices.values()]
        return []
    else:  # BLED112
        bled112.scan(scan_time=timeout*1000)
        devs_dict = bled112.get_devices_discovered()
        devices = []
        for address, info in devs_dict.iteritems():
            devices.append({
                'address': address,
                'name': info.name,
                'rssi': info.rssi
            })
        return devices
