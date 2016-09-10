import logging

from enum import Enum

log = logging.getLogger(__name__)

DEFAULT_CONNECT_TIMEOUT_S = 5.0

BLEAddressType = Enum('BLEAddressType', 'public random')


class BLEBackend(object):
    """Abstract base class representing a Bluetooth adapter backend. See the
    `pygatt.backends` module for available implementations.
    """

    def start(self):
        """Initialize and resource required to run the backend, e.g. background
        threads, USB device connections, etc.
        """
        raise NotImplementedError()

    def stop(self):
        """Stop and free any resources required while the backend is running.
        """
        raise NotImplementedError()

    def supports_unbonded(self):
        """Return True if the backend supports unbonded communication - this is
        to make detecting the GATTTool backend easier, which at the moment is
        auto-upgrading to a bonded connection even if not requested.
        """
        return True

    def connect(self, address, timeout=DEFAULT_CONNECT_TIMEOUT_S, **kwargs):
        """Return a BLEDevice for the connection if connected, otherwise raise
        an exception.
        """
        raise NotImplementedError()

    def scan(self, *args, **kwargs):
        """
        Performs a BLE scan.

        Returns a list of BLE devices found.
        """
        raise NotImplementedError()

    def filtered_scan(self, name_filter="", *args, **kwargs):
        """
        Scan for BLE devices and filter the list to include only with a name
        that includes the given filter.

        Returns a list of BLE devices found.
        """
        devices = self.scan(*args, **kwargs)
        return [device for device in devices
                if name_filter in (device['name'] or '')]

    def clear_bond(self, address=None):
        raise NotImplementedError()


class Characteristic(object):
    """
    A GATT characteristic, including it handle value and associated descriptors.
    Only valid for the lifespan of a BLE connection, since the handle values are
    dynamic.
    """
    def __init__(self, uuid, handle):
        """
        Sets the characteritic uuid and handle.

        handle - a bytearray
        """
        self.uuid = uuid
        self.handle = handle
        self.descriptors = {
            # uuid_string: handle
        }

    def add_descriptor(self, uuid, handle):
        """
        Add a characteristic descriptor to the dictionary of descriptors.
        """
        self.descriptors[uuid] = handle

    def __str__(self):
        return "<%s uuid=%s handle=%d>" % (self.__class__.__name__,
                                           self.uuid, self.handle)
