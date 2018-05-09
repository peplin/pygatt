import functools
import logging
import time
import copy

from gi.repository import GLib
from pygatt import BLEDevice
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from pygatt.exceptions import NotConnectedError

log = logging.getLogger(__name__)

g_prop_changed = {}

def handle_prop(*args, dev_n_uuid=None) :
    if dev_n_uuid in g_prop_changed :
        for func in g_prop_changed[dev_n_uuid] :
            func(*args)
    else :
        print('ERROR: property callback on non-subscribed prop')
        print('prop: ' + str(dev_n_uuid))

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
    def __init__(self, address, dbus_path, dbus_helper, _backend, is_troublesome=False):
        super(BluezBLEDevice, self).__init__(address)
        self._dbus_path = dbus_path
        self._dbus = dbus_helper
        self._dbus_obj_cache = {}
        self._connected = False
        self._subscribed_characteristics = {}
        self._uuid_to_handle = {}
        # This might seem odd but we need to know which bluetooth device
        # created us to allow orselves to be removed by the correct adapter.
        self._backend = _backend
        self._is_troublesome = is_troublesome
        self._last_time_connected = None

    def subscribe(self, uuid, callback=None, indication=False):
        global g_prop_changed
        uuid = str(uuid).lower()
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
            part_func = functools.partial(self.properties_changed,
                                      service=o.Service, uuid=uuid)
            dev_n_uuid = self._create_handle(o.Service, uuid)
            self._subscribed_characteristics[uuid] = set((callback,))
            self._uuid_to_handle[uuid] = dev_n_uuid
            if dev_n_uuid in g_prop_changed :
                g_prop_changed[dev_n_uuid].append(part_func)
                el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
                if not el_gatt_o.Notifying == True :
                    el_gatt_o.StartNotify()
            else :
                g_prop_changed[dev_n_uuid] = []
                g_prop_changed[dev_n_uuid].append(part_func)
                prop_changed = o[self._dbus.DBUS_PROPERTIES_INTERFACE].PropertiesChanged
                part_global_func = functools.partial(handle_prop, dev_n_uuid=dev_n_uuid)
                prop_changed.connect(part_global_func)
                el_gatt_o = o[self._dbus.GATT_CHAR_INTERFACE]
                el_gatt_o.StartNotify()

    def unsubscribe(self, uuid):
        uuid = str(uuid)
        if uuid not in self._subscribed_characteristics:
            return

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
        char_uuid = str(char_uuid).lower()
        if not char_uuid in self._uuid_to_handle:
            raise NotConnectedError(
                                    "handle not found in get_handle {}".format(char_uuid))

        return self._uuid_to_handle[char_uuid]

    def _troublesome_device_check(self):
        # If we get into this mode where the software thinks that
        # a connect operation is still going on then we normally
        # aren't able to get out of it. The dongle blinks like it is
        # connected but the Connect function will just keep throwing
        # this 36 error. (Disconnecting and doing a number of
        # other remedies didn't seem to work either)
        #
        # Interesting analysis of this error:
        # https://www.spinics.net/lists/linux-bluetooth/msg65856.html
        # Pull quote: "in bt_io_connect callback so it is very likely this is from the kernel"
        if self._is_troublesome == True :
            # After much hand wringing I have found that time is the only way to know
            # that there is a problem.
            if self._last_time_connected != None and time.time() > (self._last_time_connected + (2*60)):
                import sys; sys.exit(36)
            else :
                print("Not restarted")
                print(time.time())
                if self._last_time_connected != None :
                    print((self._last_time_connected + (2*60)))

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
                if is_connect == True :
                    print("In is_connect")
                    if bus_obj.Connected == True :
                        print('Connecting while Connected?')
                        # for devices without issues this is probably ok
                        if self._is_troublesome == True :
                            self._troublesome_device_check()
                            raise NotConnectedError('Connecting while Connected?')
                    bus_obj.Trusted = True
                    bus_obj.Connect()
                    while bus_obj.Connected == False :
                        if time.time() + sleep >= timeout_time:
                            raise NotConnectedError(
                                    "Connection to {} timed out".format(self.address))
                    self._last_time_connected = time.time()
                else :
                    print("In disconnect")
                    bus_obj.Disconnect()
                    while bus_obj.Connected == True :
                        if time.time() + sleep >= timeout_time:
                            raise NotConnectedError(
                                    "Connection to {} timed out".format(self.address))

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
                    if is_connect == True:
                        self._troublesome_device_check()
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
        uuid = str(uuid).lower()
        log.debug("Char read from %s", uuid)
        try :
            if uuid in self._dbus_obj_cache :
                dbus_obj = self._dbus_obj_cache[uuid]
                v = dbus_obj.ReadValue({})
                return bytearray(v)

            base_search_path = self._get_device_path()
            objects = self._dbus.get_managed_objects(search_path=base_search_path)
            for path, ifaces in objects:
                iface = ifaces.get(self._dbus.GATT_CHAR_INTERFACE)
                if iface is None or iface['UUID'] != uuid:
                    if iface is not None: log.debug(iface['UUID'])
                    continue
                dbus_obj = self._dbus.object_by_path(path,
                        interface=self._dbus.GATT_CHAR_INTERFACE)
                self._dbus_obj_cache[uuid] = dbus_obj

                v = dbus_obj.ReadValue({})
                return bytearray(v)
            raise NotConnectedError("UUID {} not found".format(uuid))
        except GLib.GError as e:
            raise NotConnectedError(
                                    "char_read threw error {}".format(uuid))


    @connection_required
    def char_write(self, uuid, value, wait_for_response=False):
        uuid = str(uuid).lower()
        log.debug("Char write from %s", uuid)
        try :
            if uuid in self._dbus_obj_cache :
                dbus_obj = self._dbus_obj_cache[uuid]
                dbus_obj.WriteValue(value, {})
                return
            base_search_path = self._get_device_path()
            objects = self._dbus.get_managed_objects(search_path=base_search_path)
            for path, ifaces in objects:
                iface = ifaces.get(self._dbus.GATT_CHAR_INTERFACE)
                if iface is None or iface['UUID'] != uuid:
                    if iface is not None: log.debug(iface['UUID'])
                    continue
                dbus_obj = self._dbus.object_by_path(path,
                        interface=self._dbus.GATT_CHAR_INTERFACE)
                dbus_obj.WriteValue(value, {})
                return 
            raise NotConnectedError("UUID {} not found".format(uuid))
        except GLib.GError as e:
            raise NotConnectedError(
                                    "char_write threw error {}".format(uuid))

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
        #if self._connected:
        #    return

        log.info("Connecting to %s", self.address)
        print("Connecting to ", self.address)

        bus_obj = self._get_device_bus_object(timeout, is_connect=True)
        if not bus_obj is None and bus_obj.Connected == True:
            self._connected = True
        else :
            raise NotConnectedError() 

        resolve_timeout = 30
        timeout_time = time.time() + resolve_timeout
        last_print_time = time.time() + 1
        dbus_dev_obj = self._dbus.object_by_path(self._dbus_path,
                interface=self._dbus.DEVICE_INTERFACE)

        while not bool(dbus_dev_obj.ServicesResolved) :
            time.sleep(0.1)
            if time.time() >= last_print_time:
                last_print_time = time.time() + 1
                print('ServicesResolved Run')
            if time.time() >= timeout_time:
                break

        if not self.services_resolved :
            print("Services not (all) resolved yet, " +
                     "discovery continues in the background")
            raise NotConnectedError("Services couldn't be resolved")



    def disconnect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        # remove all callback_connections
        for uuid, dev_n_uuid in self._uuid_to_handle.items() :
            g_prop_changed[dev_n_uuid] = []

        char_keys = copy.copy([self._subscribed_characteristics.keys()])
        for o in char_keys:
            self.unsubscribe(o)

        try :
            bus_obj = self._get_device_bus_object(timeout, is_connect=False)
        except KeyError as e :
            print(e)
            print("Disconnecting caused an error but we keep moving forward.")

        self._connected = False

        #self._backend._adapter.RemoveDevice(self._get_device_path())
        log.info("Disconnected from %s", self.address)
        print("Disconnected from ", self.address)

    def discover_characteristics(self,
                                 timeout=DEFAULT_CONNECT_TIMEOUT_S):
        dbus_obj = self._dbus.object_by_path(self._dbus_path,
                                            interface=self._dbus.DEVICE_INTERFACE)

        log.debug("Service discovery not finished before timeout")
        timeout_time = time.time() + timeout

        while not dbus_obj.ServicesResolved:
            if time.time() >= timeout_time:
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
