import logging

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

    def connect(self, address, **kwargs):
        """Return a handle for the connection if connected, otherwise raise an
        expception.
        """
        raise NotImplementedError()

    def scan(self, *args, **kwargs):
        """
        Performs a BLE scan.

        Returns a list of BLE devices found.
        """
        raise NotImplementedError()

    def bond(self, connection_handle):
        raise NotImplementedError()

    def char_read(self, connection_handle, handle):
        raise NotImplementedError()

    def char_write(self, connection_handle, handle, value,
                   wait_for_response=False):
        raise NotImplementedError()

    def measure_rssi(self, connection_handle):
        raise NotImplementedError()

    def disconnect(self, connection_handle):
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
