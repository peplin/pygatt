pygatt
=======

This is a Python library that wraps the `gatttool` (from BlueZ) command line
utility, used for interfacing with Bluetooth LE devices. `gatttool` has an
interactive mode but it is difficult to use programatically. Ideally we could
use BlueZ directly, but that's a much bigger task.

## Dependencies

* Linux
* BlueZ >= 5.18 (includes gatttool)
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
