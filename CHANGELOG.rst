.. :changelog:

Release History
================

V4.0.3
------

* Fix: Regression with receiving indications with GATTTOOL backend
* Fix: Regression with subscribing to characteristics with GATTTOOL (need to use
  writes, not commands) (#234)
* Improvement: Don't require sudo for removing bonding (#234)

V4.0.1
------

* Improvement: Wait longer for characteristics discovery with BGAPI backend (#201)
* Fix: Protect against invalid BGAPI packets
* Fix: Fix parsing fields from BGAPI connection status
* Fix: Robust to non-UTF8 characters in hcitool scan results
* Fix: Log correct connection flags from BGAPI response

V4.0.0
------

* Feature: Add ``char_read_long`` for reading characteristics longer than a
  single packet (#206, #177)
* Feature: Add command to change MTU (GATTTool only) (#182)
* Feature: Allow registering callbacks for device discovery events. (#176)
* Feature: Support fetching BLE device MAC address (#150)
* Improvement: Add better serial port error handling for BGAPI. (#162)
* Improvement: Expand and allow overriding pexpect search buffer for gatttool
  output to support devices with many characteristics without negatively
  impacting performance (#209)
* Improvement: Wait before re-opening BGAPI serial port to improve detection on
  Windows. (#162)
* Improvement: Add support for Python 3.7
* Fix: Use ATT write (not command) by default for char_write
* Fix: Wait longer for ATT write according to BlueGiga spec
* Fix: Fix BGAPI device detection (#154)
* Fix: Stop leaking file descriptors when erasing BLE bonds with GATTTool
  backend (#188)
* Fix: Typos (#173)
* Drop official support for Python 3.4, 3.5 and 3.6.

V3.2.1
------

- Improvement: Officially support Python 3.6.
- Improvement: Permit use of non-standard characteristics in reserved range (#140)

V3.2.0
------

- Fix: Reliably auto-reconnect after restarting BGAPI device. Fixes a bug in
  first attempt at auto-reconnection, only worked in some environments. (#144)
- Fix: Remove spurious "no handler for logger" warnings (#143)
- Fix: Use enum-compat instead of enum34, to fix installation in Python 3.4+
- Feature: Limit search window size for GATTTool backend, to avoid high CPU
  usage for long running connections. (#123)
- Feature: Add support for write commands to BGAPIBackend (#115)

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

