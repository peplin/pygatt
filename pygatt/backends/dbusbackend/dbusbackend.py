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
    self._hci_device = hci_device
    self._adapter = None
    self._devices = {}

    self._dbus_loop = dbus.mainloop.glib.DBusGMainLoop(set_as_default = True)
    dbus.mainloop.glib.threads_init()
    self._bus = dbus.SystemBus(mainloop = self._dbus_loop)

    self._mainloop = None

  def scan(self, timeout=10, run_as_root=False):
    manager = dbus.Interface(self._bus.get_object('org.bluez', '/'),
				'org.freedesktop.DBus.ObjectManager')
    objects = manager.GetManagedObjects()
    for path, ifaces in objects.iteritems():
      adapter = ifaces.get('org.bluez.Adapter1')
      if adapter is None:
        continue
      if self._hci_device == adapter['Address'] or \
          path.endswith(self._hci_device):
        obj = self._bus.get_object('org.bluez', path)
        self._adapter = dbus.Interface(obj, 'org.bluez.Adapter1')
        break
    if self._adapter is None:
      raise Exception('Bluetooth adapter not found')

    self._bus.add_signal_receiver(self._adapters_added,
      signal_name = 'InterfacesAdded')

    self._bus.add_signal_receiver(self._properties_changed,
      signal_name = 'PropertiesChanged',
      arg0 = 'org.bluez.Device1',
      path_keyword = 'path')

    self._bus.add_signal_receiver(self._property_changed,
      dbus_interface = 'org.bluez.Adapter1',
      signal_name = 'PropertyChanged')

    self._adapter.StartDiscovery()

    gobject.threads_init()
    self._mainloop = gobject.MainLoop()
    gobject.timeout_add(timeout * 1000, self._mainloop.quit)
    self._mainloop.run()
    self._adapter.StopDiscovery()

    return [device for device in self._devices.values()]

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
        'name': name
     }

  def _adapters_added(self, path, interfaces):
    self._add_device(path)

  def _properties_changed(self, interface, changed, invalidated, path):
    if interface != 'org.bluez.Device1':
      return

    self._add_device(path)

  def _property_changed(name, value):
    if (name == 'Discovering' and not value):
      self._mainloop.quit()
