import functools
import logging

from pygatt import BLEDevice, exceptions

log = logging.getLogger(__name__)


def connection_required(func):
    """Raise an exception before calling the actual function if the device is
    not connection.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self._connected:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class GATTToolBLEDevice(BLEDevice):
    """A BLE device connection initiated by the GATTToolBackend.

    Since the GATTToolBackend can only support 1 device connection at at time,
    the device implementation defers to the backend for all functionality -
    every command has to synchronize around a the same interactive gatttool
    session, using the same connection.
    """
    def __init__(self, address, backend):
        super(GATTToolBLEDevice, self).__init__(address)
        self._backend = backend
        self._connected = True

    @connection_required
    def bond(self, *args, **kwargs):
        self._backend.bond(self, *args, **kwargs)

    @connection_required
    def char_read(self, uuid, *args, **kwargs):
        return self._backend.char_read(self, uuid, *args, **kwargs)

    @connection_required
    def char_read_handle(self, handle, *args, **kwargs):
        return self._backend.char_read_handle(self, handle, *args, **kwargs)

    @connection_required
    def char_write_handle(self, handle, *args, **kwargs):
        self._backend.char_write_handle(self, handle, *args, **kwargs)

    @connection_required
    def disconnect(self):
        self._backend.disconnect(self)
        self._connected = False

    @connection_required
    def discover_characteristics(self, *args, **kwargs):
        self._characteristics = self._backend.discover_characteristics(
            self, *args, **kwargs)
        return self._characteristics

    @connection_required
    def exchange_mtu(self, mtu, *args, **kwargs):
        return self._backend.exchange_mtu(self, mtu)

    def register_disconnect_callback(self, callback):
        self._backend._receiver.register_callback("disconnected", callback)

    def remove_disconnect_callback(self, callback):
        self._backend._receiver.remove_callback("disconnected", callback)
