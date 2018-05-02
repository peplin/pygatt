# -*- coding: utf-8 -*-
# Copyright (c) 2016, Andreas brauchli <a.brauchli@elementarea.net>

import logging
import time
from functools import partial
from gi.repository import GLib
from pydbus import SystemBus
from threading import Thread
from itertools import chain

from pygatt.exceptions import NotConnectedError, BLEError
from pygatt.backends import BLEBackend
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from pygatt.backends.bluez.device import BluezBLEDevice

log = logging.getLogger(__name__)


class DBusHelper(object):
    """ Helper class for DBus operations """

    DBUS_OBJECT_MANAGER_INTERFACE = 'org.freedesktop.DBus.ObjectManager'
    DBUS_PROPERTIES_INTERFACE = 'org.freedesktop.DBus.Properties'

    SERVICE_NAME = 'org.bluez'
    ADAPTER_INTERFACE = SERVICE_NAME + '.Adapter1'
    DEVICE_INTERFACE = SERVICE_NAME + '.Device1'
    GATT_CHAR_INTERFACE = SERVICE_NAME + '.GattCharacteristic1'

    def __init__(self, dbus, hci_path='/org/bluez/hci0'):
        self._bus = dbus
        self._hci_path = hci_path

    def get(self, *args, **kwargs):
        return self._bus.get(*args, **kwargs)

    def object_by_path(self, path, interface=None):
        """
        Retrieve a dbus object by path

        path -- dbus path of the object to retrieve
        interface -- (string) interface to fetch for given object. If specified,
                     only the object's interface-handle is returned. A KeyError
                     is raised if the object does not support the interface.
        """
        obj = self._bus.get(DBusHelper.SERVICE_NAME, path)
        if interface:
            return obj[interface]
        return obj

    def objects_by_property(self, props, interface, base_path=None):
        """
        Retrieve dbus objects by specific properties

        The full dbus object is returned, not just the seeked interface.

        props -- dict of property:value pairs to match on given objects'
                     interface
        interface -- interface that must be implemented by the object
        base_path -- where to look for the dbus object. Default root (/)
        """
        # Scope it so that we only get objects under our hci device
        if base_path is None:
            base_path = self._hci_path

        matches = []
        for path, ifaces in self.get_managed_objects(base_path):
            if interface not in ifaces:
                continue
            i = ifaces.get(interface)
            match = True
            for p, v in props.items():
                if (p not in i) or (i[p] != v):
                    match = False
                    break
            if match:
                matches.append(self.object_by_path(path))
        return matches

    def get_managed_objects(self, search_path=None):
        if search_path is None :
            search_path = self._hci_path
        obj_manager = self.object_by_path('/',
                interface=self.DBUS_OBJECT_MANAGER_INTERFACE)
        return ((path, ifaces)
                for (path, ifaces)
                in obj_manager.GetManagedObjects().items()
                if path.startswith(search_path))


class BluezBackend(BLEBackend):
    """
    Backend to pygatt that uses BlueZ's dbus interface on the system bus.

    Works with bluez >= 5.42, prior 5.x versions may work when the experimental
    interfaces are enabled by starting the daemon with the `-E' flag.
    """

    def __init__(self, hci_device=None, scan_filter={}, main_loop=None):
        """
        Initialize the Bluez backend

        hci_device -- When set, use this adapter. Use any adapter otherwise
        scan_filter -- a dict of filter options. Supported Keys and value types:
                        UUIDs [str], RSSI int (threshold),
                        Pathloss int (threshold), Transport str (le|bredr|auto)
        main_loop -- an external GLib.MainLoop already running, default None is
                     used to run one internally
        """
        if main_loop:
            self._main_loop = main_loop
            self._main_loop_thread = None
        else:
            self._main_loop = GLib.MainLoop()
            self._main_loop_thread = Thread(target=self._main_loop.run)
        self._subscriptions = []

        hci_path = '/org/bluez/hci0'
        if not hci_device is None :
            hci_path = '/org/bluez/' + hci_device

        self._bus = DBusHelper(SystemBus(), hci_path)
        try:
            self._adapter = self.find_adapter(hci_device)
        except BLEError as e:
            if hci_device:
                raise BLEError("Bluetooth adapter `{}' not found".format(
                        hci_device))
            raise e
        if not self._adapter.Powered:
            raise BLEError("Bluetooth adapter `{}' not powered".format(
                    hci_device))

        self._scan_filter = scan_filter
        self._discovered_devices = {}
        self._connected_devices = set()

    def find_adapter(self, pattern=None):
        return self.find_adapter_in_objects(self._bus.get_managed_objects('/'),
                                            pattern)

    def find_adapter_in_objects(self, objects, pattern=None):
        for path, ifaces in objects:
            adapter = ifaces.get(DBusHelper.ADAPTER_INTERFACE)
            if adapter is None:
                continue

            try:
                if (not pattern and adapter.Powered) or \
                       (pattern == adapter['Address'] or
                        path.endswith(pattern)):
                    return self._bus.object_by_path(path,
                            interface=DBusHelper.ADAPTER_INTERFACE)
            except AttributeError:
                pass

        raise BLEError("No bluetooth adapter found")

    def device_matches_scan_filter(self, device):
        if 'UUIDs' in self._scan_filter:
            has_uuid = False
            for uuid in self._scan_filter['UUIDs']:
                if device.UUIDs.contains(uuid):
                    has_uuid = True

            if not has_uuid:
                return False

        if 'RSSI' in self._scan_filter:
            if device['RSSI'] < self._scan_filter['RSSI']:
                return False

        # TODO: filter for Transport (str), Pathloss (int)
        # there doesn't seem to be properties for those on org.bluez.Device1
        return True

    def add_prediscovered_devices(self):
        """ "Discover" devices cached by bluez """
        objects = self._bus.get_managed_objects()
        for path, ifaces in objects:
            dev = ifaces.get(DBusHelper.DEVICE_INTERFACE)
            if dev is None:
                continue

            if self.device_matches_scan_filter(dev):
                self._discovered_devices[path] = dev

    def interfaces_added(self, path, interfaces):
        """ Called when a new dbus-interface is added """
        if DBusHelper.DEVICE_INTERFACE not in interfaces:
            return

        properties = interfaces[DBusHelper.DEVICE_INTERFACE]

        if path in self._discovered_devices:
            self._discovered_devices[path] = {
                    chain(self._discovered_devices[path].items(), properties.items())
            }
        else:
            self._discovered_devices[path] = properties

    def interfaces_removed(self, path, interfaces):
        if path in self._discovered_devices:
            del self._discovered_devices[path]

    def properties_changed(self, path, interface, changed, invalidated):
        """ Called when properties change on an object """
        if interface != DBusHelper.DEVICE_INTERFACE:
            return

        if path in self._discovered_devices:
            self._discovered_devices[path] = {
                    chain(self._discovered_devices[path].items(), changed.items())
            }
        else:
            # We expect every object in our dictionary to have an 'Address'
            # this was added due to a real exception that was thrown.
            if 'Address' in changed :
                self._discovered_devices[path] = changed

        if 'Address' in self._discovered_devices[path]:
            address = self._discovered_devices[path]['Address']
        else:
            address = "<unknown>"

    def subscribe_dbus(self):
        object_manager = self._bus.object_by_path('/',
                interface=DBusHelper.DBUS_OBJECT_MANAGER_INTERFACE)
        iface_subscr = object_manager.InterfacesAdded.connect(
                self.interfaces_added)
        self._subscriptions.append(iface_subscr)

        properties = self._bus.object_by_path(self._adapter._path,
                interface=DBusHelper.DBUS_PROPERTIES_INTERFACE)
        prop_subscr = properties.PropertiesChanged.connect(
                partial(self.properties_changed, self._adapter._path))
        self._subscriptions.append(prop_subscr)

    def unsubscribe_dbus(self):
        for i in self._subscriptions:
            i.disconnect()

        self._subscriptions = []

    def supports_unbonded(self):
        return False

    def start(self):
        self.add_prediscovered_devices()
        if self._main_loop_thread:
            self._main_loop_thread.start()

        self.subscribe_dbus()
        log.debug("Started")

    def stop(self):
        """ Disconnect any connected device and stops listening to device events
        """
        log.debug("Stopping")
        self.unsubscribe_dbus()
        for device in self._connected_devices:
            if device and device.connected:
                device.disconnect()
        self._connected_devices = set()

        if self._main_loop_thread:
            self._main_loop.quit()
            # Wait for thread..
            # self._main_loop_thread.join()
        self._discovered_devices = {}
        log.info("Stopped")

    def scan(self, timeout=10, scan_filter=None):
        """
        Start a Bluetooth LE discovery scan
        timeout -- scan for this number of seconds
        scan_filter -- dictionary with scan filter or None to use the one
                       defined on instance initialization.
        """
        log.info("Starting BLE scan")
        self._adapter.SetDiscoveryFilter(scan_filter or self._scan_filter)
        self._adapter.StartDiscovery()
        # update is async and triggers the dbus path subscriptions, so
        # sleep until we're done
        time.sleep(timeout)
        self._adapter.StopDiscovery()
        log.info("Found %d BLE devices", len(self._discovered_devices))
        log.debug("%s", self._discovered_devices)
        return self._discovered_devices.values()

    def connect(self, address, timeout=DEFAULT_CONNECT_TIMEOUT_S,
                address_type='public'):
        """ Connect to a BLE device

        address -- (string) the bluetooth address of the device e.g.
                   "00:11:22:33:44:55"
        timeout -- Timeout in seconds to attempt a connection
        address_type -- UNUSED, left for compatibility and potentially future
                        usage
        """
        for bledev in self._connected_devices:
            if bledev.address == address:
                return bledev

        log.info("... new connection")
        # Bluz requires a scan to have seen a device before it ends up
        # in the dbus device tree.
        self.scan(timeout=10)
        device_found = False
        out_path = None
        dev = None
        for path, dev in self._discovered_devices.items():
            if dev['Address'] == address:
                device_found = True
                out_path = path
                break

        if not device_found:
            errstr = "Device with address {} not found".format(address)
            raise NotConnectedError(errstr)

        bledevice = BluezBLEDevice(address, out_path, self._bus, self)
        bledevice.connect(timeout=timeout)
        self._connected_devices.add(bledevice)
        return bledevice
