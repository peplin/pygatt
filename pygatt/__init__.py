import logging


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

# Initialize a null handler for logging to avoid printing spurious "No handlers
# could be found for logger" messages.
logging.getLogger(__name__).addHandler(NullHandler())

from .exceptions import BLEError  # noqa
from .device import BLEDevice  # noqa
from .backends import BGAPIBackend, GATTToolBackend, BLEAddressType  # noqa
