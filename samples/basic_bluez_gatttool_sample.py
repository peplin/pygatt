#!/usr/bin/env python

import binascii
import pygatt

YOUR_DEVICE_ADDRESS = "11:22:33:44:55:66"
# Many devices, e.g. Fitbit, use random addressing - this is required to
# connect.
ADDRESS_TYPE = "random"

adapter = pygatt.GATTToolBackend()
adapter.start()
device = adapter.connect(YOUR_DEVICE_ADDRESS, address_type=ADDRESS_TYPE)

for uuid in device.discover_characteristics().keys():
    print "Read UUID %s: %s" % (uuid, binascii.hexlify(device.char_read(uuid)))
