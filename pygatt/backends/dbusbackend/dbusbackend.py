from collections import defaultdict
import logging
import string
import sys
import time
import threading
import subprocess
import dbus
import gobject

from pygatt.classes import BluetoothLEDevice
from pygatt import constants
from pygatt import exceptions
from pygatt.backends.backend import BLEBackend
from dbus.mainloop.glib import DBusGMainLoop


log = logging.getLogger(__name__)

class DBusBackend(BLEBackend):
  '''
  Backend to pygatt that uses dbus connections.
  '''

  def __init__(self, hci_device='hci0'):
    gobject.threads_init()
    dbus.mainloop.glib.threads_init()

    self._hci_device = hci_device
    self._adapter = None
    self._devices = {}
    self._callbacks = {}

    self._dbus_loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default = True)
    self._bus = dbus.SystemBus(mainloop = self._dbus_loop)

    self._mainloop = DBusBackendThread()

  def start(self):
    self._mainloop.start()

  def stop(self):
    self._mainloop.kill()

  def scan(self, timeout=10, run_as_root=False):
    manager = dbus.Interface(self._bus.get_object('org.bluez', '/'),
				'org.freedesktop.DBus.ObjectManager')
    objects = manager.GetManagedObjects()
    for path, ifaces in objects.iteritems():
      device = ifaces.get('org.bluez.Device1')
      adapter = ifaces.get('org.bluez.Adapter1')
      if adapter is not None:
        if self._hci_device == adapter['Address'] or \
            path.endswith(self._hci_device):
          obj = self._bus.get_object('org.bluez', path)
          self._adapter = dbus.Interface(obj, 'org.bluez.Adapter1')
      elif device is not None:
        self._add_device(path)
    if self._adapter is None:
      raise Exception('Bluetooth adapter not found')

    self._bus.add_signal_receiver(self._adapters_added,
      signal_name = 'InterfacesAdded')

    self._bus.add_signal_receiver(self._properties_changed,
      signal_name = 'PropertiesChanged',
      arg0 = 'org.bluez.Device1',
      path_keyword = 'path')

    self._bus.add_signal_receiver(self._properties_changed,
      signal_name = 'PropertiesChanged',
      arg0 = 'org.bluez.Adapter1',
      path_keyword = 'path')

    self._adapter.StartDiscovery()
    time.sleep(timeout)
    self._adapter.StopDiscovery()

    return [device for device in self._devices.values()]

  def connect(self, address):
    device = self._bus.get_object('org.bluez', self._devices[address]['path'])
    device.Connect(dbus_interface='org.bluez.Device1')
    log.debug('Connected to ' + self._devices[address]['path'])
    
    #Get all characteristics
    characteristics = {}
    device_iface = dbus.Interface(device, 'org.freedesktop.DBus.Properties')
    gatt_services = device_iface.Get('org.bluez.Device1', 'GattServices')
    for gatt_service in gatt_services:
      service = self._bus.get_object('org.bluez', gatt_service)
      service_iface = dbus.Interface(service, 'org.freedesktop.DBus.Properties')
      service_chars = service_iface.Get('org.bluez.GattService1', 'Characteristics')
      for service_char in service_chars:
        char = self._bus.get_object('org.bluez', service_char)
        char_iface = dbus.Interface(char, 'org.freedesktop.DBus.Properties')
        char_uuid = char_iface.Get('org.bluez.GattCharacteristic1', 'UUID')
        characteristics[char_uuid] = char

    self._devices[address]['characteristics'] = characteristics

  def disconnect(self, address):
    device = self._bus.get_object('org.bluez', self._devices[address]['path'])
    device.Disconnect(dbus_interface='org.bluez.Device1')
    log.debug('Disconnected from ' + self._devices[address]['path'])

  def char_read_uuid(self, address, uuid):
    char = self._devices[address]['characteristics'][uuid]
    char_iface = dbus.Interface(char, 'org.bluez.GattCharacteristic1')
    return char_iface.ReadValue()
    
  def char_write(self, address, uuid, value):
    char = self._devices[address]['characteristics'][uuid]
    char_iface = dbus.Interface(char, 'org.bluez.GattCharacteristic1')
    char_iface.WriteValue(value)

  def get_rssi(self, address):
    device = self._bus.get_object('org.bluez', self._devices[address]['path'])
    props_iface = dbus.Interface(device, 'org.freedesktop.DBus.Properties')
    try:
      return props_iface.Get('org.bluez.Device1', 'RSSI')
    except org.freedesktop.DBus.Error.InvalidArgs as e:
      raise NotImplementedError()
      
  def subscribe(self, address, uuid, callback, indication = False):
    log.info(
      'Subscribing to uuid=%s with callback=%s and indication=%s',
      uuid, callback, indication)

    if callback is None:
      raise Exception("Notifications require a callback function")

    char = self._devices[address]['characteristics'][uuid]
    char_iface = dbus.Interface(char, 'org.bluez.GattCharacteristic1')
    props_iface = dbus.Interface(char, 'org.freedesktop.DBus.Properties')
    signal_match = props_iface.connect_to_signal(\
      "PropertiesChanged", self._handle_callbacks, \
      path_keyword='path', sender_keyword='sender')
    self._callbacks[signal_match.sender] = {
      'sender': signal_match.sender,
      'uuid': uuid,
      'callback': callback
    }

    char_iface.StartNotify()

  def _add_device(self, path):
    device = self._bus.get_object('org.bluez', path)
    props_iface = dbus.Interface(device, 'org.freedesktop.DBus.Properties')
    address = props_iface.Get('org.bluez.Device1', 'Address')
    name = props_iface.Get('org.bluez.Device1', 'Name')

    if not address in self._devices:
      print 'Discovered %s: %s' % (address, name)
      log.info('Discovered %s: %s', address, name)
      self._devices[address] = {
        'address': address,
        'name': name,
        'path': path
     }

  def _adapters_added(self, path, interfaces):
    self._add_device(path)

  def _properties_changed(self, interface, changed, invalidated, path):
    if interface == 'org.bluez.Adapter1' and 'Discovering' in changed and changed['Discovering'] == False:
      log.debug('Stop discovering')

    if interface != 'org.bluez.Device1':
      return

    self._add_device(path)

  def _handle_callbacks(self, *args, **kwargs):
    #Find uuid from parameters
    uuid = self._callbacks[kwargs['sender']]['uuid']
    callback = self._callbacks[kwargs['sender']]['callback']

    if 'Notifying' in args[1]:
      return

    if not 'Value' in args[1]:
      raise Exception('Unable to find return values for callback')

    #Convert dbus Array into bytearray
    dbus_values = args[1]['Value']
    python_values = bytearray(dbus_values)
    
    callback(python_values, uuid=uuid)    

class DBusBackendThread(threading.Thread):
  def __init__(self):
    super(DBusBackendThread, self).__init__()
    self._mainloop = gobject.MainLoop()
    self._kill = False

  def kill(self):
    self._kill = True

  def run(self):
    context = self._mainloop.get_context()
    while not self._kill:
      context.iteration(True)

class DBusBluetoothLEDevice(BluetoothLEDevice):
    '''Have to use a subclass because the standard class assumes only one device per backend'''
    def __init__(self, mac_address, backend):
        """
        Initialize.

        mac_address -- a string containing the mac address of the BLE device in
                       the following format: "XX:XX:XX:XX:XX:XX"
        backend -- an instantiated instance of a BLEBacked.

        Example:

            dongle = pygatt.backends.BGAPIBackend('/dev/ttyAMC0')
            my_ble_device = pygatt.classes.BluetoothLEDevice(
                '01:23:45:67:89:ab', bgapi=dongle)
        """
        super(DBusBluetoothLEDevice, self).__init__(mac_address, backend)

    def bond(self):
        """
        Create a new bond or use an existing bond with the device and make the
        current connection bonded and encrypted.
        """
        log.info("bond")
        #self._backend.bond(self._mac_address)
        raise NotImplementedError()

    def connect(self, timeout=None):
        """
        Connect to the BLE device.

        Example:

            my_ble_device.connect('00:11:22:33:44:55')

        """
        log.info("connect")
        self._backend.connect(self._mac_address)

    def char_read(self, uuid):
        """
        Reads a Characteristic by UUID.

        uuid -- UUID of Characteristic to read as a string.

        Returns a bytearray containing the characteristic value on success.
        Returns None on failure.

        Example:
            my_ble_device.char_read('a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b')
        """
        log.info("char_read %s", uuid)
        return self._backend.char_read_uuid(self._mac_address, uuid)

    def char_write(self, uuid, value, wait_for_response=False):
        """
        Writes a value to a given characteristic handle.

        uuid -- the UUID of the characteristic to write to.
        value -- the value as a bytearray to write to the characteristic.
        wait_for_response -- wait for response after writing (GATTTOOL only).

        Example:
            my_ble_device.char_write('a1e8f5b1-696b-4e4c-87c6-69dfe0b0093b',
                                     bytearray([0x00, 0xFF]))
        """
        log.info("char_write %s", uuid)
        self._backend.char_write(self._mac_address, uuid, value)

    def encrypt(self):
        """
        Form an encrypted, but not bonded, connection.
        """
        log.info("encrypt")
        #self._backend.encrypt(self._mac_address)
        raise NotImplementedError()

    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the BLE
        device.

        Returns the RSSI value in dBm on success.
        Returns None on failure.
        """
        log.info("get_rssi")
        return self._backend.get_rssi(self._mac_address)

    def subscribe(self, uuid, callback=None, indication=False):
        """
        Enables subscription to a Characteristic with ability to call callback.

        uuid -- UUID as a string of the characteristic to subscribe to.
        callback -- function to be called when a notification/indication is
                    received on this characteristic.
        indication -- use indications (requires application ACK) rather than
                      notifications (does not requrie application ACK).
        """
        log.info(":s: subscribe to %s with callback %s. indicate = %d",
                 self._mac_address, uuid, callback.__name__, indication)
        self._backend.subscribe(self._mac_address, uuid, \
            callback=callback)
