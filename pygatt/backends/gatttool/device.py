import logging

from pygatt import BLEDevice, exceptions

log = logging.getLogger(__name__)


def connection_required(func):
    def wrapper(self, *args, **kwargs):
        if not self._connected:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class GATTToolBLEDevice(BLEDevice):
    def __init__(self, address, backend):
        super(GATTToolBLEDevice, self).__init__(address)
        self._backend = backend
        self._connected = True

    @connection_required
    def bond(self):
        self._backend.bond(self)

    @connection_required
    def char_read(self, uuid, *args, **kwargs):
        return self._backend.char_read(self, uuid, *args, **kwargs)

    @connection_required
    def char_write(self, uuid, *args, **kwargs):
        handle = self._backend.get_handle(uuid)
        self._backend.char_write(self, handle, *args, **kwargs)

    @connection_required
    def disconnect(self):
        self._backend.disconnect(self)
        self._connected = False

    @connection_required
    def discover_characteristics(self):
        return self._backend.discover_characteristics(self)
