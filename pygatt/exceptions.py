"""
Exceptions for pygatt Module.
"""


class BLEError(Exception):
    """Exception class for pygatt."""
    pass


class NotConnectedError(BLEError):
    pass


class NotificationTimeout(BLEError):
    def __init__(self, msg=None, gatttool_output=None):
        super(NotificationTimeout, self).__init__(msg)
        self.gatttool_output = gatttool_output
