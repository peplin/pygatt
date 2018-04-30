import functools
import logging
import time
import copy

from gi.repository import GLib
from pygatt import BLEDevice
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from pygatt.exceptions import NotConnectedError

log = logging.getLogger(__name__)


def connection_required(func):
    """Raise an exception before calling the actual function if the device is
    not connection.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self._connected:
            raise NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class BluezBLEDevice(BLEDevice):
    """A BLE device connection initiated by the Bluez (DBUS) backend.
    """
    def __init__(self, address, dbus_path, dbus_helper, _backend):
        super(BluezBLEDevice, self).__init__(address)
        self._dbus_path = dbus_path
        self._dbus = dbus_helper
        self._connected = False
        self._subscribed_characteristics = {}
        self._uuid_to_handle = {}
        # This might seem odd but we need to know which bluetooth device
        # created us to allow orselves to be removed by the correct adapter.
        self._backend = _backend

    def subscribe(self, uuid, callback=None, indication=False):
        uuid = str(uuid)
        if uuid in self._subscribed_characteristics:
            self._subscribed_characteristics[uuid].add(callback)
            return

        # we need to filter items by the actual DEVICE we are trying to talk to
        # ex. We have two HR monitors on the same HCI device. How do we make
        # sure we are talking to the correct one?
        base_search_path = self._get_device_path()

        objs = self._dbus.objects_by_property({'UUID': uuid},
                interface=self._dbus.GATT_CHAR_INTERFACE,
                base_path=base_search_path)
        log.debug("Subscribing to %s (%d objs)", uuid, len(objs))

        for o in objs:
            log.debug(".. on service: %s", o[self._dbus.GATT_CHAR_INTERFACE].Service)
            o[self._dbus.DBUS_PROPERTIES_INTERFACE].PropertiesChanged.connect(
                    functools.partial(self.properties_changed,
                                      service=o.Service, uuid=uuid))
            el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
            self._subscribed_characteristics[uuid] = set((callback,))
            self._uuid_to_handle[uuid] = self._create_handle(o.Service, uuid)
            el_gatt_o.StartNotify()

    def unsubscribe(self, uuid):
        uuid = str(uuid)
        if uuid not in self._subscribed_characteristics:
            return

        objs = self._dbus.objects_by_property({'UUID': uuid},
                interface=self._dbus.GATT_CHAR_INTERFACE)
        for o in objs:
            el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
            if el_gatt_o.Notifying:
                el_gatt_o.StopNotify()
            del(self._subscribed_characteristics[uuid])

    def properties_changed(self, interface, changed, invalidated,
                           service=None, uuid=None):
        log.debug("Property changed on service: %s, uuid %s", service, uuid)
        if uuid is not None and uuid in self._subscribed_characteristics:
            for cb in self._subscribed_characteristics[uuid]:
                #cb(interface, changed, invalidated, service=service, uuid=uuid)
                if 'Value' in changed :
                    cb(self._create_handle(service, uuid),
                       bytes(changed['Value']))
        elif uuid is not None:
            log.error("No subscription for UUID {}".format(uuid))

    def _notification_handles(self, uuid):
        uuid_parts = uuid.split('-')
        uuid_parts[0] = ('%08d' % (int(uuid_parts[0]) + 1))
        uuid_notification = '-'.join(uuid_parts)
        return uuid, uuid_notification

    # Our handle is a unique string for each device that can be used to find
    # our way back to our calling object. Including the 'self' pointer and
    # managing this on the class side would be preferred but this is to retain
    # backwards compatibility
    def _create_handle(self, service, uuid):
        return str(service)+'__'+str(uuid)

    def _get_device_path(self):
        service_addr = self.address.replace(':', '_')
        base_search_path = self._dbus._hci_path + '/dev_' + service_addr
        return base_search_path

    def get_handle(self, char_uuid):
        char_uuid = str(char_uuid)
        return self._uuid_to_handle[char_uuid]

    def _get_device_bus_object(self, timeout, is_connect):
        bus_obj = None
        timeout_time = time.time() + timeout
        while True:
            try:
                # we don't use object_by_path here because it doesn't support
                # timeout
                bus_obj = self._dbus.get(self._dbus.SERVICE_NAME,
                                 self._dbus_path,
                                 timeout=timeout)
                if is_connect :
                    bus_obj.Trusted = True
                    bus_obj.Connect()
                else :
                    bus_obj.Disconnect()

                break

            except GLib.Error as e:
                # TODO remove print
                print((e.code, e.message))
                if is_connect :
                    log.error("Error connecting to %s: %d %s",
                          self.address, e.code, e.message)
                else :
                    log.error("Error disconnecting from %s: %d %s",
                          self.address, e.code, e.message)
                sleep = 0.1
                if e.code == 24:  # Timeout was reached
                    sleep = 2
                elif e.code == 36:  # Operation already in progress,
                                    # Software caused connection abort
                    pass

                if time.time() + sleep >= timeout_time:
                    raise NotConnectedError(
                            "Connection to {} timed out".format(self.address))

                time.sleep(sleep)
        return bus_obj

    @connection_required
    def bond(self, *args, **kwargs):
        raise NotImplementedError()

    @connection_required
    def clear_bond(self, address=None):
        raise NotImplementedError()

    @connection_required
    def char_read(self, uuid, *args, **kwargs):
        """
        Reads a Characteristic by uuid.
        :param uuid: UUID of Characteristic to read.
        :type uuid: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        uuid = str(uuid)
        log.debug("Char read from %s", uuid)
        base_search_path = self._get_device_path()
        objects = self._dbus.get_managed_objects(search_path=base_search_path)
        for path, ifaces in objects:
            iface = ifaces.get(self._dbus.GATT_CHAR_INTERFACE)
            if iface is None or iface['UUID'] != uuid:
                if iface is not None: log.debug(iface['UUID'])
                continue
            dbus_obj = self._dbus.object_by_path(path,
                    interface=self._dbus.GATT_CHAR_INTERFACE)
            v = dbus_obj.ReadValue({})
            return bytearray(v)
        raise Exception("UUID {} not found".format(uuid))

    @connection_required
    def char_write(self, uuid, value, wait_for_response=False):
        uuid = str(uuid)
        base_search_path = self._get_device_path()
        objs = self._dbus.objects_by_property({'UUID': uuid},
                                              base_path=base_search_path)
        for o in objs:
            log.debug("Writing to %s", o.Service)
            el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
            el_gatt_o.WriteValue(value, {})

    @connection_required
    def char_write_handle(self, handle, *args, **kwargs):
        raise NotImplementedError()

    @property
    def services_resolved(self):
        dbus_dev_obj = self._dbus.object_by_path(self._dbus_path,
                interface=self._dbus.DEVICE_INTERFACE)
        return bool(dbus_dev_obj.ServicesResolved)

    @property
    def connected(self):
        return self._connected

    def connect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        """ Connect to this BLE device

        timeout -- Timeout in seconds to attempt a connection
        """
        if self._connected:
            return

        log.info("Connecting to %s", self.address)

        bus_obj = self._get_device_bus_object(timeout, is_connect=True)

        self._connected = True

        if not self.services_resolved:
            log.info("Services not (all) resolved yet, " +
                     "discovery continues in the background")

    def disconnect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        char_keys = copy.copy([self._subscribed_characteristics.keys()])
        for o in char_keys:
            self.unsubscribe(o)

        try :
            bus_obj = self._get_device_bus_object(timeout, is_connect=False)
        except Exception as e :
            print(e)
            print("Disconnecting caused an error but we keep moving forward.")

        self._connected = False

        self._backend._adapter.RemoveDevice(self._get_device_path())
        #self._backend._adapter.RemoveDevice(self._dbus.object_by_path(self._get_device_path()))
        log.info("Disconnected from %s", self.address)

    def discover_characteristics(self,
                                 timeout=DEFAULT_CONNECT_TIMEOUT_S):
        dbus_obj = self._dbus.object_by_path(self._dbus_path,
                                            interface=self._dbus.DEVICE_INTERFACE)

        log.debug("Service discovery not finished before timeout")
        while not dbus_obj.ServicesResolved:
            if time.time() >= timeout:
                break
            time.sleep(0.1)

        if not dbus_obj.ServicesResolved:
            log.warn("Service discovery not finished after timeout")

        characteristics = dbus_obj.UUIDs

        # A generic object with a None handle, to match the interface
        class obj(object):
            def handle(self):
                return None

        o = obj()
        self._characteristics = dict(zip(characteristics,
            [o for i in range(len(characteristics))]))
        return self._characteristics

    def get_rssi(self):
        try:
            return self._dbus.object_by_path(self._dbus_path).RSSI
        except:
            log.info("Failed to get RSSI for device {}".format(
                    self.address))
            return float('nan')
