#!/usr/bin/env python
# -*- coding: utf-8 -*-

# pygatt Python Module.

"""
pygatt Python Module.
~~~~


:author: Greg Albrecht <gba@orionlabs.co>
:copyright: Copyright 2015 Orion Labs
:license: Apache License, Version 2.0
:source: <https://github.com/ampledata/pygatt>

"""

import logging

from .classes import BluetoothLEDevice  # noqa
from .exceptions import BluetoothLEError  # noqa

import pygatt.util  # noqa


# Set default logging handler to avoid "No handler found" warnings.
try:  # Python 2.7+
    from logging import NullHandler
except ImportError:
    class NullHandler(logging.Handler):
        """Default logging handler to avoid "No handler found" warnings."""
        def emit(self, record):
            """Default logging handler to avoid "No handler found" warnings."""
            pass

logging.getLogger(__name__).addHandler(NullHandler())
