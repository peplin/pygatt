from __future__ import print_function

import logging

from constants import DEFAULT_CONNECT_TIMEOUT_S

log = logging.getLogger(__name__)


class BluetoothLEDevice(object):
    """
    Interface for a Bluetooth Low Energy device that can use either the Bluegiga
    BGAPI (cross platform) or GATTTOOL (Linux only) as the backend.
    """
    def __init__(self, mac_address, backend):
        """
        Initialize.

        mac_address -- a string containing the mac address of the BLE device in
                       the following format: "XX:XX:XX:XX:XX:XX"
        backend -- an instantiated instance of a BLEBacked.

        Example:

            dongle = pygatt.backends.BGAPIBackend('/dev/ttyAMC0')
            my_ble_device = pygatt.classes.BluetoothLEDevice(
                '01:23:45:67:89:ab', bgapi=dongle)
        """
        self._backend = backend
        self._mac_address = mac_address

    def bond(self):
        """
        Create a new bond or use an existing bond with the device and make the
        current connection bonded and encrypted.
        """
        self._backend.bond()

    def connect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        """
        Connect to the BLE device.

        timeout -- the length of time to try to establish a connection before
                   returning.

        Example:

            my_ble_device.connect(timeout=5)

        """
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
        return self._backend.char_read_uuid(uuid)

    def char_write(self, *args, **kwargs):
        """
        Writes a value to a given characteristic handle.

        uuid -- the UUID of the characteristic to write to.
        value -- the value as a bytearray to write to the characteristic.
        wait_for_response -- wait for response after writing (GATTTOOL only).

        Example:
            my_ble_device.char_write('a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b',
                                     bytearray([0x00, 0xFF]))
        """
        self._backend.char_write_uuid(*args, **kwargs)

    def encrypt(self):
        """
        Form an encrypted, but not bonded, connection.
        """
        self._backend.encrypt()

    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the BLE
        device.

        Returns the RSSI value in dBm on success.
        Returns None on failure.
        """
        return self._backend.get_rssi()

    def run(self):
        """
        Start a background thread to listen for notifications.
        """
        self._backend.start()

    def stop(self):
        """
        Stop the any background threads and disconnect.
        """
        self._backend.stop()

    def subscribe(self, *args, **kwargs):
        self._backend.subscribe(*args, **kwargs)
