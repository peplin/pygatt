ble-sensor-pi
=============

Simple example for SensorTag with RaspberryPi a Bluetooth Low Engery (BLE GATT) device

See sensortag/sensortag_test.py for a simple example of reading temperature values from the tag.
The same approach could be used to read any of the sensors.  It's also possible to have the tag
send a stream of measurements at regular intervals.  See the information here -
http://processors.wiki.ti.com/index.php/SensorTag_User_Guide
Or wait for me to add more examples.

This code was thrown together quickly to see how easy it might be to use these devices with the
RaspberryPi.  It proved to be very easy - though I struggled to find much information on BLE on 
Linux.  Other relevant search terms are GATT.

I'll post more information on my blog at http://mike.saunby.net

Note you might need to install a newer version of gatttool for this code to work.  I used the 
version included in bluez-5.2 - it's in the attrib directory.

May 2012.  I've put this code under the Apache 2.0 licence, if folks want to use it and that 
doesn't suit let me know.  I have no desire to profit from this code, nor prevent others using
or profiting if they wish.  Equally you shouldn't expect me to maintain or support it.  It's 
just stuff, use it as you wish.
