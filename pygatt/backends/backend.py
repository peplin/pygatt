import logging

from pygatt.constants import DEFAULT_CONNECT_TIMEOUT_S

log = logging.getLogger(__name__)


class BLEBackend(object):
    """Abstract base class representing a Bluetooth adapter backend. """

    def start(self):
        raise NotImplementedError()

    def stop(self):
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
    GATT characteristic. For internal use within BGAPIBackend.
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
