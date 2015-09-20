from collections import defaultdict
import logging
import string
import sys
import time
import threading
import subprocess
import dbus
import dbus.mainloop
import gobject

from pygatt import constants
from pygatt import exceptions
from pygatt.backends.backend import BLEBackend

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

    self._dbus_loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default = True)
    self._bus = dbus.SystemBus(mainloop = self._dbus_loop)

    self._mainloop = DbusBackendThread()

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

  def disconnect(self, address):
    device = self._bus.get_object('org.bluez', self._devices[address]['path'])
    device.Disconnect(dbus_interface='org.bluez.Device1')
    log.debug('Disconnected from ' + self._devices[address]['path'])

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

class DbusBackendThread(threading.Thread):
  def __init__(self):
    super(DbusBackendThread, self).__init__()
    self._mainloop = gobject.MainLoop()
    self._kill = False

  def kill(self):
    self._kill = True

  def run(self):
    context = self._mainloop.get_context()
    while not self._kill:
      context.iteration(True)
