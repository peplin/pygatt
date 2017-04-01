.. :changelog:

Release History
================

V3.1.1
------

- Improvement: Convert documentation to RST for better PyPI integration.

V3.1.0
------

-  Fix: Support platforms without ``termios`` (Windows)
-  Feature: Add ``char_read_handle`` to GATTTool backend.
-  Improvement: Warn if ``hcitool`` requires a sudo authentication.
-  Improvement: Allow BGAPI device more time to reboot for more reliable
   discovery.
-  Improvement: Interpret "invalid file descriptor" as a disconnect
   event.
-  Fix: Correctly handle service class UUIDs that aren't 16 bytes.
-  Improvement: Support BLE devices with any UTF8 character.
-  Improvement: Make gatttol prompt timeout configurable.
-  Improvement: Gracefully stop ``lescan`` to avoid leaving the adapter
   in a bad state.
-  Improvement: Allow custom timeout for discovery on GATTTool backend.
-  Fix: Make sure responses to char reads on BGAPI backend are from the
   requested handle.
-  Improvement: Raise and exception if trying to instantiate the
   GATTTool backend in Windows.
-  Improvement: If no BGAPI device attached, abort immediately.
-  Fix: Use user's configured HCI device for connection and scanning in
   GATTTool backend.

V3.0.0
------

-  [API Change] The BGAPIBackend.connect method now takes the same
   ``address_type`` argument as the GATTTool backend [BGAPI].
-  [API Change] The ``address_type`` argument on both backends now
   requires a value from a new enum, ``pygatt.BLEAddressType``, instead
   of a string.
-  Made Python 3 support a priority for both GATTTOOL and BGAPI
   backends.
-  Improve reliability of BGAPI backend by re-setting device for each
   connection.

V2.1.0
------

-  Added all standard GATT characteristics. [BGAPI]
-  Move gatttool monitor to a background thread for increased
   performance. [GATTTOOL]

V2.0.1
------

-  Feature: Allow unsubscribing from notifications.
-  Improvement: Allow more time to discover characteristics. [GATTTOOL]
-  Improvement: Allow using gatttol backend without root. [GATTTOOL]
-  Improvement: Standardize type of UUID so comparison always works (str
   vs unicode)
-  Fix: Fix packaging so the version on PyPI can be installed.
-  Fix: Fix Python 3 compatibility.

Thanks to Ilya Sukhanov and Alexey Roslyakov for the changes in this
release!

v2.0.0
------

-  New API with support for multiple BLE adapters.

