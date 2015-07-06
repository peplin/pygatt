"""
Exceptions for pygatt Module.
"""

__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs'


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


class BLED112Error(BluetoothLEError):
    def __init__(self, msg):
        self.message = msg
