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

