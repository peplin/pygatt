"""
Exceptions for pygatt Module.
"""


class BluetoothLEError(Exception):
    """Exception class for pygatt."""
    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.message)


class NotConnectedError(BluetoothLEError):
    pass


class NotificationTimeout(BluetoothLEError):
    pass


class NoResponseError(BluetoothLEError):
    pass
