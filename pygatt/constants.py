"""
Constants for pygatt Module.
"""

import logging

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
    'BGAPI': 1,
}
