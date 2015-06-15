from __future__ import print_function

# from collections import defaultdict
import logging
import logging.handlers
# import string
# import time

from bluegiga.bgble import BLED112Backend
from constants import(
    BACKEND, DEFAULT_CONNECT_TIMEOUT_S, LOG_LEVEL, LOG_FORMAT
)


class BluetoothLEDevice(object):
    """
    Interface for a Bluetooth Low Energy device that can use either the Bluegiga
    BLED112 (cross platform) or GATTTOOL (Linux only) as the backend.
    """
    def __init__(self, mac_address, backend, logfile=None):
        """
        Initialize.

        mac_address -- ??????????
        backend -- backend to use. One of pygatt.constants.backend.
        logfile -- the file in which to write the logs.
        """
        # Set up logging FIXME clean up
        logging.basicConfig(filename='example.log')  # FIXME remove
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(LOG_LEVEL)

        self._console_handler = logging.StreamHandler()
        self._console_handler.setLevel(LOG_LEVEL)
        self._formatter = logging.Formatter(LOG_FORMAT)
        self._console_handler.setFormatter(self._formatter)
        self._logger.addHandler(self._console_handler)

        # Select backend
        if backend == BACKEND['BLED112']:
            self._backend = BLED112Backend('COM7')  # FIXME port name
        elif backend == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise ValueError("backend", backend)
        self._backend_type = backend

        # Store mac_address
        self._mac_address = mac_address

    def bond(self):
        """
        Securely Bonds to the BLE device.
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def connect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        """
        Connect to the BLE device.

        timeout -- the length of time to try to establish a connection before
                   returning.

        Returns True if the connection was made successfully.
        Returns False otherwise.
        """
        if self._backend_type == BACKEND['BLED112']:
            return self._backend.connect(self._mac_address, timeout=timeout)
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def char_read(self, uuid):
        """
        Reads a Characteristic by UUID.

        uuid -- UUID of Characteristic to read as a string.

        Returns a bytearray containing the characteristic value
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def char_write(self, uuid, value, wait_for_response=False):
        """
        Writes a value to a given characteristic handle.

        uuid --
        value --
        wait_for_response --
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the BLE
        device.

        Returns the RSSI value on success.
        Returns None on failure.
        """
        if self._backend_type == BACKEND['BLED112']:
            return self._backend.get_rssi()
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def run(self):
        """Run a background thread to listen for notifications.
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def stop(self):
        """Stop the backgroud notification handler in preparation for a
        disconnect.
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def subscribe(self, uuid, callback=None, indication=False):
        """
        Enables subscription to a Characteristic with ability to call callback.

        :param uuid:
        :param callback:
        :param indication:
        :return:
        :rtype:
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

# -----------
    def _expect(self, expected):  # timeout=pygatt.constants.DEFAULT_TIMEOUT_S):
        """We may (and often do) get an indication/notification before a
        write completes, and so it can be lost if we "expect()"'d something
        that came after it in the output, e.g.:

        > char-write-req 0x1 0x2
        Notification handle: xxx
        Write completed successfully.
        >

        Anytime we expect something we have to expect noti/indication first for
        a short time.
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)

    def _handle_notification(self, msg):
        """
        Receive a notification from the connected device and propagate the value
        to all registered callbacks.
        """
        if self._backend_type == BACKEND['BLED112']:
            pass
        elif self._backend_type == BACKEND['GATTTOOL']:
            raise NotImplementedError("TODO")
        else:
            raise NotImplementedError("backend", self._backend_type)
