pygatt
=======

This is a Python library that wraps the `gatttool` (from BlueZ) command line
utility, used for interfacing with Bluetooth LE devices. `gatttool` has an
interactive mode but it is difficult to use programatically. Ideally we could
use BlueZ directly, but that's a much bigger task.

## Dependencies

* Linux
* BlueZ >= 5.5 (includes gatttool with the latest prompt styles).
    * Tested on 5.18 and 5.21
    * Ubuntu is stuck on BlueZ 4.x and does not work - you need to build BlueZ
      from source.
* Python packages in pip-requirements.txt (installed with `pip install -r pip-requirements.txt`)
* hcitool configured for passwordless sudo

To enable the bluetooth adaptor:

    $ sudo hciconfig hci0 up

## License

This tool is based on code originally written by Michael Saunby for his
[ble-sensor-pi](https://github.com/msaunby/ble-sensor-pi) project, licensed
under the Apache 2.0 license. Some parts of his code may still be in this
project.

The new code for the `pygatt` project is also licensed under the Apache 2.0
license.

    sudo hcitool lescan


Example
====

Connect to a bGeigie Nano using BLEBee and decode sensor data (NMEA-like):

```
#!/usr/bin/env python

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

# $BNRDD,2359,2014-12-14T09:46:47Z,32,2,2398,A,3745.6045,N,12229.8638,W,50.40,A,8,87*5B
```
