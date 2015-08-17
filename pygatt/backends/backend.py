class BLEBackend(object):
    """Abstract base class representing a Bluetooth adapter backend. """

    def bond(self):
        raise NotImplementedError()

    def connect(self, address, **kwargs):
        raise NotImplementedError()

    def char_read_uuid(self, uuid):
        raise NotImplementedError()

    def char_write(self, handle, value, wait_for_response=False):
        raise NotImplementedError()

    def encrypt(self):
        raise NotImplementedError()

    def get_rssi(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def subscribe(self, uuid, callback=None, indication=False):
        raise NotImplementedError()

    def get_handle(self, characteristic_uuid, descriptor_uuid=None):
        raise NotImplementedError()
