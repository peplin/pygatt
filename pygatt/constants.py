#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Constants for pygatt Module.
"""

__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs, Inc.'


import logging


LOG_LEVEL = logging.DEBUG
LOG_FORMAT = ('%(asctime)s %(levelname)s %(name)s.%(funcName)s:%(lineno)d'
              ' - %(message)s')

DEFAULT_TIMEOUT_S = .5
DEFAULT_ASYNC_TIMEOUT_S = .5
DEFAULT_CONNECT_TIMEOUT_S = 5.0
