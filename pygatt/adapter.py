from .constants import DEFAULT_CONNECT_TIMEOUT_S
from .classes import BLEDevice


class BLEAdapter(object):

    def __init__(self, backend):
        self.backend = backend
        self.backend.start()

    def stop(self):
        self.backend.stop()

    def connect(self, address, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        handle = self.backend.connect(address, timeout=timeout)
        return BLEDevice(address, handle, self.backend)

    def scan(self, name_filter="", *args, **kwargs):
        """
        Scan for BLE devices and filter the list to include only with a name
        that includes the given filter.

        Returns a list of BLE devices found.
        """
        devices = self.backend.scan(*args, **kwargs)
        return [device for device in devices
                if name_filter in (device['name'] or '')]