import logging
import time
import pytz
import datetime
import threading
import dbus
import gobject

from pygatt.classes import BluetoothLEDevice
from pygatt import exceptions
from pygatt.backends.backend import BLEBackend
from dbus.mainloop.glib import DBusGMainLoop
from dbus import DBusException

log = logging.getLogger(__name__)

class DBusBackend(BLEBackend):
  '''
  Backend to pygatt that uses dbus connections.
  '''

  def __init__(self, hci_device='hci0', connect_timeout=5):
    gobject.threads_init()
    dbus.mainloop.glib.threads_init()

    self._hci_device = hci_device
    self._connect_timeout = connect_timeout
    self._lock = threading.Lock()
    self._devices = {}
    self._callbacks = {}

    self._dbus_loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default = True)
    self._bus = dbus.SystemBus(mainloop = self._dbus_loop)

    self._mainloop = DBusBackendThread()
    self.start()

  def start(self):
    self._mainloop.start()

  def stop(self):
    self._mainloop.kill()

  def scan(self, timeout=10, run_as_root=False):
    adapter_obj = self._bus.get_object('org.bluez', '/org/bluez/' + self._hci_device)
    adapter = dbus.Interface(adapter_obj, 'org.bluez.Adapter1')
    prop_intf = dbus.Interface(adapter_obj, 'org.freedesktop.DBus.Properties')
    prop_intf.Set('org.bluez.Adapter1', 'Powered', True)

    adapter.SetDiscoveryFilter({'Transport': 'le'})
    adapter.StartDiscovery()

    start_time = pytz.utc.localize(datetime.datetime.utcnow())
    manager = dbus.Interface(self._bus.get_object('org.bluez', '/'),
				'org.freedesktop.DBus.ObjectManager')
    objects = manager.GetManagedObjects()
    for path, ifaces in objects.iteritems():
      device = ifaces.get('org.bluez.Device1')
      if device is not None:
        self._add_device(path)
    if adapter is None:
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

    #Find difference between supposed finish time and now
    end_time = pytz.utc.localize(datetime.datetime.utcnow())
    time_taken = (end_time - start_time).total_seconds()
    if time_taken < timeout:
      time.sleep(timeout - time_taken)
    adapter.StopDiscovery()

    return [device for device in self._devices.values()]

  def connect(self, address):
    device = self._bus.get_object('org.bluez', self._devices[address]['path'])
    device.Connect(dbus_interface='org.bluez.Device1')
    
  def disconnect(self, address):
    device = self._bus.get_object('org.bluez', self._devices[address]['path'])
    device.Disconnect(dbus_interface='org.bluez.Device1')
    log.debug('Disconnected from ' + self._devices[address]['path'])
    self._devices[address]['connected'] = False

  def char_read_uuid(self, address, uuid):
    if self._devices[address]['connected'] == False:
      log.warn('Attempting to read from ' + address + ' but not connected!')
      return bytearray()
    char = self._devices[address]['characteristics'][uuid]
    char_iface = dbus.Interface(char, 'org.bluez.GattCharacteristic1')
    dbus_values = char_iface.ReadValue()
    python_values = bytearray(dbus_values)
    return python_values
    
  def char_write(self, address, uuid, value):
    if self._devices[address]['connected'] == False:
      log.warn('Attempting to write to ' + address + ' but not connected!')
      return bytearray()
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
    self._lock.acquire()

    device = self._bus.get_object('org.bluez', path)
    props_iface = dbus.Interface(device, 'org.freedesktop.DBus.Properties')
    address = props_iface.Get('org.bluez.Device1', 'Address')
    name = props_iface.Get('org.bluez.Device1', 'Name')

    #Ignore if we already have a record of the device
    if address in self._devices:
      log.debug('Already have a record of ' + address)
      self._lock.release()
      return

    #Connect to get all GATT characteristics
    log.debug('Getting GATT services for ' + str(path))
    try:
      device.Connect(dbus_interface='org.bluez.Device1')
      time.sleep(self._connect_timeout)
    except org.bluez.Error.Failed as e:
      log.warn('Could not connect to ' + str(path) + ' - already connected?')
    #Wait for GATT services to be populated
    log.debug('Should have all GATT services for ' + str(path))

    #Get all characteristics
    characteristics = {}
    device_iface = dbus.Interface(device, 'org.freedesktop.DBus.Properties')

    gatt_services = None
    try:
      gatt_services = device_iface.Get('org.bluez.Device1', 'GattServices')
    except DBusException as e:
      log.debug('Device ' + address + ' doesn\'t have any GATT services. ' + str(e))
      return

    device.Disconnect(dbus_interface='org.bluez.Device1')

    for gatt_service in gatt_services:
      service = self._bus.get_object('org.bluez', gatt_service)
      service_iface = dbus.Interface(service, 'org.freedesktop.DBus.Properties')
      service_chars = service_iface.Get('org.bluez.GattService1', 'Characteristics')
      for service_char in service_chars:
        char = self._bus.get_object('org.bluez', service_char)
        char_iface = dbus.Interface(char, 'org.freedesktop.DBus.Properties')
        char_uuid = char_iface.Get('org.bluez.GattCharacteristic1', 'UUID')
        characteristics[char_uuid] = char

    log.info('Discovered %s: %s', address, name)
    self._devices[address] = {
      'address': address,
      'name': name,
      'path': path,
      'connected': False
    }

    self._devices[address]['characteristics'] = characteristics
    self._lock.release()

  def _adapters_added(self, path, interfaces):
    self._add_device(path)
    return

  def _properties_changed(self, interface, changed, invalidated, path):
    if interface == 'org.bluez.Adapter1' and 'Discovering' in changed and changed['Discovering'] == False:
      log.debug('Stop discovering')

    if 'RSSI' in changed:
      return

    log.debug('Changed: ' + str(changed))

    if 'Connected' in changed and interface == 'org.bluez.Device1':
      device = self._bus.get_object('org.bluez', path)
      props_iface = dbus.Interface(device, 'org.freedesktop.DBus.Properties')
      address = props_iface.Get('org.bluez.Device1', 'Address')
      if changed['Connected'] == True:
        log.debug('Connected to ' + address)
        self._devices[address]['connected'] = True
      else:
        log.debug('Disconnected from ' + address)
        self._devices[address]['connected'] = False

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

            my_ble_device.connect()

        """
        log.info("Connect to %s", self._mac_address)
        self._backend.connect(self._mac_address)

    def disconnect(self, timeout=None):
        """
        Disconnect from the BLE device.

        Example:

            my_ble_device.disconnect()

        """
        log.info("Connect to %s", self._mac_address)
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

    def run(self):
        #Don't actually need to do anything
        return

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
