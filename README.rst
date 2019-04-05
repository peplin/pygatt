pygatt - Python Module for Bluetooth LE Generic Attribute Profile (GATT).
=========================================================================

This Module allows reading and writing to GATT descriptors on devices
such as fitness trackers, sensors, and anything implementing standard
GATT Descriptor behavior.

pygatt provides a Pythonic API by wrapping two different backends:

-  BlueZ (requires Linux), using the ``gatttool`` command-line utility.
-  Bluegiga's BGAPI, compatible with USB adapters like the BLED112.

Motivation
----------

Despite the popularity of BLE, we have yet to find a good programming
interface for it on desktop computers. Since most peripherals are
designed to work with smartphones, this space is neglected. One
interactive interface, BlueZ's ``gatttool``, is functional but difficult
to use programmatically. BlueZ itself obviously works, but the interface
leaves something to be desired and only works in Linux.

Requirements
------------

-  Python 2.7.5 or greater, or Python 3.5 or greater

   -  Python 2.7.3's ``struct`` library has a bug that will break PyGATT - 2.7.5
         or greater is recommended.

-  BlueZ 5.18 or greater (with gatttool) - required for the gatttool
   backend only.

   -  Tested on 5.18, 5.21, 5.35 and 5.43

-  GATTToolBackend requires Linux (i.e. not Windows compatible)

Installation
------------

Install ``pygatt`` with pip from PyPI:

::

    $ pip install pygatt

The BlueZ backend is not supported by default as it requires
``pexpect``, which can only be installed in a UNIX-based environment. If
you wish to use that backend, install the optional dependencies with:

::

    $ pip install "pygatt[GATTTOOL]"

Install the latest development version of ``pygatt`` with pip:

::

    $ pip install git+https://github.com/peplin/pygatt

Documentation
----------

The documentation for pygatt consists of:

- This README
- The code in the ``samples`` directory
- The Python docstrings in the code itself.

The ``BLEDevice`` and ``BLEBackend`` base classes are the primary interfaces for
users of the library.

Example Use
-----------

The primary API for users of this library is provided by
``pygatt.BLEBackend`` and ``pygatt.BLEDevice``. After initializing an
instance of the preferred backend (available implementations are found
in ``pygatt.backends``, use the ``BLEBackend.connect`` method to connect
to a device and get an instance of ``BLEDevice.``

.. code:: python

    import pygatt

    # The BGAPI backend will attempt to auto-discover the serial device name of the
    # attached BGAPI-compatible USB adapter.
    adapter = pygatt.BGAPIBackend()

    try:
        adapter.start()
        device = adapter.connect('01:23:45:67:89:ab')
        value = device.char_read("a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b")
    finally:
        adapter.stop()

Note that not all backends support connecting to more than 1 device at
at time, so calling ``BLEBackend.connect`` again may terminate existing
connections.

Here's the same example using the GATTTool backend. It's identical
except for the initialization of the backend:

.. code:: python

    import pygatt

    adapter = pygatt.GATTToolBackend()

    try:
        adapter.start()
        device = adapter.connect('01:23:45:67:89:ab')
        value = device.char_read("a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b")
    finally:
        adapter.stop()

Notifications Example
---------------------

This example uses the gatttool backend to connect to a device with a specific
MAC address, subscribes for notifications on a characteristic, and prints the
data returned in each notification.

.. code:: python

    import pygatt
    from binascii import hexlify

    adapter = pygatt.GATTToolBackend()

    def handle_data(handle, value):
        """
        handle -- integer, characteristic read handle the data was received on
        value -- bytearray, the data returned in the notification
        """
        print("Received data: %s" % hexlify(value))

    try:
        adapter.start()
        device = adapter.connect('01:23:45:67:89:ab')

        device.subscribe("a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b",
                         callback=handle_data)
    finally:
        adapter.stop()

Debugging
---------

While debugging software using pygatt, it is often useful to see what's
happening inside the library. You can enable debugging logging and have
it printed to your terminal with this code:

::

    import pygatt
    import logging

    logging.basicConfig()
    logging.getLogger('pygatt').setLevel(logging.DEBUG)

Can't find BGAPI device in Windows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You may need to explicitly specify the COM port of your BGAPI-compatible
device in windows, e.g.:

::

    adapter = pygatt.BGAPIBackend(serial_port='COM9')

If you provide the COM port name, but still get an error such as
``WindowsError(2, 'The system cannot find the file specified.')``, try
changing the COM port of the device to a value under 10, e.g. ``COM9``.

Authors
-------

- Jeff Rowberg @jrowberg https://github.com/jrowberg/bglib
- Greg Albrecht @ampledata https://github.com/ampledata/pygatt
- Christopher Peplin @peplin https://github.com/peplin/pygatt
- Morten Kjaergaard @mkjaergaard https://github.com/mkjaergaard/pygatt
- Michael Saunby @msaunby https://github.com/msaunby/ble-sensor-pi
- Steven Sloboda https://github.com/sloboste
- Ilya Sukhanov @IlyaSukhanov
- @dcliftreaves
- Jonathan Dan
- Ilann Adjedj
- Ralph Hempel
- Rene Jacobsen
- Marcus Georgi
- Alexandre Barachant
- Michel Rivas Hernandez
- Jean Regisser
- David Martin
- Pieter Hooimeijer
- Thomas Li Fredriksen
- Markus Proeller
- lachtanek
- Andrea Merello
- Richard Mitchell
- Daniel Santos
- Andrew Connell
- Jakub Hrabec
- John Schoenberger
- Georgi Boiko

Releasing to PyPI
-----------------

For the maintainers of the project, when you want to make a release:

-  Merge all of the changes into ``master``.
-  Update the version in ``setup.py``.
-  Update the ``CHANGELOG.mkd``
-  Tag the commit and push to GitHub (will need to push to a separate
   branch of PR first since ``master`` is a protected branch).
-  Travis CI will take care of the rest - it will build and deploy
   tagged commits to PyPI automatically.

License
-------

Copyright 2015 Stratos Inc. and Orion Labs

Apache License, Version 2.0 and MIT License. See LICENSE.
