import threading
import logging

from collections import defaultdict
from binascii import hexlify

log = logging.getLogger(__name__)


class BLEBackend(object):
    """Abstract base class representing a Bluetooth adapter backend. """

    def __init__(self):
        self._callbacks = defaultdict(set)
        self._subscribed_handlers = {}

    def supports_unbonded(self):
        """Return True if the backend supports unbonded communication - this is
        to make detecting the GATTTool backend easier, which at the moment is
        auto-upgrading to a bonded connection even if not requested.
        """
        return True

    def bond(self):
        raise NotImplementedError()

    def connect(self, address, **kwargs):
        raise NotImplementedError()

    def char_read_uuid(self, uuid):
        raise NotImplementedError()

    def char_write(self, handle, value, wait_for_response=False):
        raise NotImplementedError()

    def char_write_uuid(self, uuid, value, wait_for_response=False):
        log.info("char_write %s", uuid)
        handle = self.get_handle(uuid)
        self.char_write(handle, value, wait_for_response=wait_for_response)

    def encrypt(self):
        raise NotImplementedError()

    def get_rssi(self):
        raise NotImplementedError()

    def start(self):
        self._lock = threading.Lock()

    def stop(self):
        raise NotImplementedError()

    def disconnect(self):
        raise NotImplementedError()

    def subscribe(self, uuid, callback=None, indication=False):
        """
        Enables subscription to a Characteristic with ability to call callback.

        uuid -- UUID as a string of the characteristic to subscribe.
        callback -- function to be called when a notification/indication is
                    received on this characteristic.
        indication -- use indications (requires application ACK) rather than
                      notifications (does not requrie application ACK).
        """
        log.info(
            'Subscribing to uuid=%s with callback=%s and indication=%s',
            uuid, callback, indication)
        # Expect notifications on the value handle...
        value_handle = self.get_handle(uuid)

        # but write to the characteristic config to enable notifications
        # TODO with the BGAPI backend we can be smarter and fetch the actual
        # characteristic config handle - we can also do that with gattool if we
        # use the 'desc' command, so we'll need to change the "get_handle" API
        # to be able to get the value or characteristic config handle.
        characteristic_config_handle = value_handle + 1

        properties = bytearray([
            0x2 if indication else 0x1,
            0x0
        ])

        try:
            self._lock.acquire()

            if callback is not None:
                self._callbacks[value_handle].add(callback)

            if self._subscribed_handlers.get(value_handle, None) != properties:
                self.char_write(
                    characteristic_config_handle,
                    properties,
                    wait_for_response=False
                )
                log.debug("Subscribed to uuid=%s", uuid)
                self._subscribed_handlers[value_handle] = properties
            else:
                log.debug("Already subscribed to uuid=%s", uuid)
        finally:
            self._lock.release()

    def _handle_notification(self, handle, value):
        """
        Receive a notification from the connected device and propagate the value
        to all registered callbacks.
        """

        log.info('Received notification on handle=0x%x, value=0x%s',
                 handle, hexlify(value))
        try:
            self._lock.acquire()

            if handle in self._callbacks:
                for callback in self._callbacks[handle]:
                    callback(handle, value)
        finally:
            self._lock.release()

    def get_handle(self, characteristic_uuid, descriptor_uuid=None):
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

    def scan(self, *args, **kwargs):
        """
        Performs a BLE scan.

        Returns a list of BLE devices found.
        """
        raise NotImplementedError()
