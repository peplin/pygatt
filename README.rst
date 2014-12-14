pygatt - Python Module for Bluetooth LE Generic Attribute Profile (GATT).
====

This Module allows reading and writing to GATT descriptors on devices such as
fitness trackers, sensors, and anything implementing standard GATT Descriptor behavior.

pygatt wraps BlueZ's `gatttool` command-line utility with a Pythonic API.


Motivation
----

`gatttool` has an interactive mode but it is difficult to use programatically.
Ideally we could use BlueZ directly, but that's a much bigger task.


Dependencies
----
* Currently only tested under Linux as it requires `gatttool` which is included with BlueZ which is a Linux library.
* BlueZ >= 5.5
    * Tested on 5.18 and 5.21
    * Ubuntu is stuck on BlueZ 4.x and does not work - you need to build BlueZ
      from source.


Installation
----
* Install via pip: `$ pip install pygatt`


Usage Example
----
Connect to a bGeigie Nano using BLEBee and decode sensor data (NMEA-like):

.. code:: python

  import pygatt

  str_buf = ''
  def print_str_buf(x,y):
      global str_buf
      str_y = "%s" % y
      if str_y == '$':
         print str_buf
         sb = str_y
      else:
         str_buf = str_buf + str_y

   pygatt.util.reset_bluetooth_controller()
   bgn = pygatt.pygatt.BluetoothLEDevice('00:07:80:71:D5:89')
   bgn.connect()
   bgn.char_write(32, bytearray([0x03, 0x00]))
   bgn.subscribe('a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b', print_str_buf)
   bgn.run()

This should print something like:

.. parsed-literal::

  $BNRDD,2359,2014-12-14T09:46:47Z,32,2,2398,A,3745.6045,N,12229.8638,W,50.40,A,8,87*5B


Author
----
Greg Albrecht <gba@onbeep.com> https://github.com/ampledata

Derived from the work of several others, see NOTICE.


License
----
Apache License, Version 2.0. See LICENSE.


Copyright
----
Copyright 2014 OnBeep, Inc.


Source
----
https://github.com/ampledata/pygatt
