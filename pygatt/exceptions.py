"""
Exceptions for pygatt Module.
"""


class BLEError(Exception):
    """Exception class for pygatt."""
    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.message)


class NotConnectedError(BLEError):
    pass


class NotificationTimeout(BLEError):
    pass


class NoResponseError(BLEError):
    pass
