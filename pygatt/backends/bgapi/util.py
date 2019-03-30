import re
import logging
import serial.tools.list_ports

log = logging.getLogger(__name__)


class USBSerialDeviceInfo(object):
    """
    Contains the information about a usb device in an easy to use way.
    """
    device_name = None  # Name of the usb device
    port_name = None    # Name of serial port to which the device is connected
    vendor_id = None    # USB vendor id
    product_id = None   # USB product id

    def __str__(self):
        if self.vendor_id is None:
            vendor_id = str(self.vendor_id)
        else:
            vendor_id = '0x{:04x}'.format(self.vendor_id)
        if self.product_id is None:
            product_id = str(self.product_id)
        else:
            product_id = '0x{:04x}'.format(self.product_id)
        return (self.device_name + ' VID=' + vendor_id + ' PID=' + product_id +
                ' on ' + self.port_name)


def extract_vid_pid(info_string):
    """
    Try different methods of extracting vendor and product IDs from a string.

    The output from serial.tools.list_ports.comports() varies so
    widely from machine to machine and OS to OS, the only option we
    have right now is to add to a list of patterns that we have seen so
    far and compare the output.

    info_string -- the string possibly containing vendor and product IDs.

    Returns a tuple of (vendor ID, product ID) if a device is found.
    If an ID isn't found, returns None.
    """

    DEVICE_STRING_PATTERNS = [
        # '...VID:PID=XXXX:XXXX...'
        re.compile('.*VID:PID=([0-9A-Fa-f]{0,4}):([0-9A-Fa-f]{0,4}).*'),

        # '...VID_XXXX...PID_XXXX...'
        re.compile('.*VID_([0-9A-Fa-f]{0,4}).*PID_([0-9A-Fa-f]{0,4}).*')
    ]

    for p in DEVICE_STRING_PATTERNS:
        match = p.match(info_string)
        if match:
            return int(match.group(1), 16), int(match.group(2), 16)
    return None


def find_usb_serial_devices(vendor_id=None, product_id=None):
    """
    Discovers USB serial device(s) connected to the machine matching the input
    arguments. If no arguments are given or both are None, returns all devices
    found.

    vendor_id -- the USB vendor id to match.
    product_id -- the USB product id to match.

    Returns a list of USBDeviceInfo objects matching the criteria given.
    """
    devices = []
    raw_devices = list(serial.tools.list_ports.comports())
    log.debug("Found %d serial USB devices", len(raw_devices))
    for device in raw_devices:
        log.debug("Checking serial USB device: %s", device)
        dev = USBSerialDeviceInfo()
        dev.port_name = device[0]
        dev.device_name = device[1]
        found_device = extract_vid_pid(device[2])
        if found_device is not None:
            dev.vendor_id, dev.product_id = found_device
            if vendor_id is None and product_id is None:
                devices.append(dev)
            elif dev.vendor_id == vendor_id and product_id is None:
                devices.append(dev)
            elif dev.product_id == product_id and vendor_id is None:
                devices.append(dev)
            elif dev.product_id == product_id and dev.vendor_id == vendor_id:
                devices.append(dev)
            log.debug("USB device: %s", dev)
    return devices
