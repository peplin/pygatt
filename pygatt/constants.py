import logging


"""
Constants for pygatt Module.
"""

__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs'


# Logging
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = ('%(asctime)s %(levelname)s %(name)s.%(funcName)s:%(lineno)d'
              ' - %(message)s')

# Connection
DEFAULT_TIMEOUT_S = 0.5
DEFAULT_ASYNC_TIMEOUT_S = 0.5
DEFAULT_CONNECT_TIMEOUT_S = 5.0

# Backends
BACKEND = {
    'GATTTOOL': 0,
    'BLED112': 1,
}
