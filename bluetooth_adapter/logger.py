from __future__ import absolute_import

import logging
import logging.config


# TODO: actually use verbose option
def init_logging(verbose=False):
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'file_formatter': {
                'format': "%(asctime)s %(levelname)s - %(name)s - %(message)s"
            },
            'simple_formatter': {
                'format': "%(name)s - %(message)s"
            }
        },
        'handlers': {
            'file_handler': {
                'class': 'logging.FileHandler',
                'filename': 'bluetooth_adapter.log',
                'formatter': 'file_formatter',
            },
            'console_handler': {
                'class': 'logging.StreamHandler',
                'formatter': 'simple_formatter',
            },
        },
        'loggers': {
            'bluetooth_adapter': {
                'handlers': ['console_handler', 'file_handler'],
                'level': logging.DEBUG,
            },
        },
    })
