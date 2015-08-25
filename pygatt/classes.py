from __future__ import print_function

import logging

from constants import DEFAULT_CONNECT_TIMEOUT_S, LOG_LEVEL, LOG_FORMAT
from pygatt.backends import GATTToolBackend

log = logging.getLogger(__name__)


class BluetoothLEDevice(object):
    """
    Interface for a Bluetooth Low Energy device that can use either the Bluegiga
    BGAPI (cross platform) or GATTTOOL (Linux only) as the backend.

    TODO pass the instantiated backend in as an argument
    """
    def __init__(self, mac_address, backend, logfile=None):
        """
        Initialize.

        mac_address -- a string containing the mac address of the BLE device in
                       the following format: "XX:XX:XX:XX:XX:XX"
        backend -- an instantiated instance of a BLEBacked.
        logfile -- the file in which to write the logs.

        Example:

            dongle = pygatt.backends.BGAPIBackend('/dev/ttyAMC0')
            my_ble_device = pygatt.classes.BluetoothLEDevice(
                '01:23:45:67:89:ab', bgapi=dongle)
        """
        self._backend = backend
        self._mac_address = mac_address

        log.setLevel(LOG_LEVEL)
        if logfile is not None:
            handler = logging.FileHandler(logfile)
        else:  # print to stderr
            handler = logging.StreamHandler()
        formatter = logging.Formatter(fmt=LOG_FORMAT)
        handler.setLevel(LOG_LEVEL)
        handler.setFormatter(formatter)
        log.addHandler(handler)

    def bond(self):
        """
        Create a new bond or use an existing bond with the device and make the
        current connection bonded and encrypted.
        """
        log.info("bond")
        self._backend.bond()

    def connect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        """
        Connect to the BLE device.

        timeout -- the length of time to try to establish a connection before
                   returning.

        Example:

            my_ble_device.connect(timeout=5)

        """
        log.info("connect")
        self._backend.connect(self._mac_address, timeout=timeout)

    def char_read(self, uuid):
        """
        Reads a Characteristic by UUID.

        uuid -- UUID of Characteristic to read as a string.

        Returns a bytearray containing the characteristic value on success.
        Returns None on failure.

        Example:
            my_ble_device.char_read('a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b')
        """
        log.info("char_read %s", uuid)
        return self._backend.char_read_uuid(uuid)

    def char_write(self, uuid, value, wait_for_response=False):
        """
        Writes a value to a given characteristic handle.

        uuid -- the UUID of the characteristic to write to.
        value -- the value as a bytearray to write to the characteristic.
        wait_for_response -- wait for response after writing (GATTTOOL only).

        Example:
            my_ble_device.char_write('a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b',
                                     bytearray([0x00, 0xFF]))
        """
        log.info("char_write %s", uuid)
        handle = self._backend.get_handle(uuid)
        self._backend.char_write(handle, value,
                                 wait_for_response=wait_for_response)

    def encrypt(self):
        """
        Form an encrypted, but not bonded, connection.
        """
        log.info("encrypt")
        self._backend.encrypt()

    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the BLE
        device.

        Returns the RSSI value in dBm on success.
        Returns None on failure.
        """
        log.info("get_rssi")
        return self._backend.get_rssi()

    def run(self):
        """
        Run a background thread to listen for notifications (GATTTOOL only).
        """
        log.info("run")
        # TODO This is an odd architecture, why does the backend have to bleed
        # up to this level?
        if isinstance(self._backend, GATTToolBackend):
            self._backend.run()

    def stop(self):
        """
        Stop the any background threads and disconnect.
        """
        log.info("stop")
        self._backend.stop()

    def subscribe(self, uuid, callback=None, indication=False):
        """
        Enables subscription to a Characteristic with ability to call callback.

        uuid -- UUID as a string of the characteristic to subscribe to.
        callback -- function to be called when a notification/indication is
                    received on this characteristic.
        indication -- use indications (requires application ACK) rather than
                      notifications (does not requrie application ACK).
        """
        log.info("subscribe to %s with callback %s. indicate = %d",
                 uuid, callback.__name__, indication)
        self._backend.subscribe(uuid, callback=callback, indication=indication)
