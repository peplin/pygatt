"""
Exceptions for pygatt Module.
"""


class BLEError(Exception):
    """Exception class for pygatt."""
    def __repr__(self):
        return "<%s %s>" % (self.__class__.__name__, self.message)

    def __str__(self):
        return repr(self)


class NotConnectedError(BLEError):
    pass


class NotificationTimeout(BLEError):
    def __init__(self, msg=None, gatttool_output=None):
        super(NotificationTimeout, self).__init__(msg)
        self.gatttool_output = gatttool_output
