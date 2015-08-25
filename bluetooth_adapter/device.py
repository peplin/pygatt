import logging


log = logging.getLogger(__name__)


# TODO: maybe subclass this from a generic BluetoothDevice later on
class BleDevice(object):

    def __init__(self, backend, mac_address, name=None,
                 scan_response_rssi=None):
        log.debug("Creating BleDevice with MAC %s", mac_address)
        self._backend = backend
        self._mac_address_string = mac_address
        self._mac_address_bytearray = bytearray(
            [int(b, 16) for b in self._mac_address_string.split(":")])
        self._name = name
        self._scan_response_rssi = scan_response_rssi
        self._services = None
        log.debug("BleDevice created")

    def __repr__(self):
        return (
            "<{0}.{1} object at {2}: {3}, {4}>"
            .format(self.__class__.__module__, self.__class__.__name__,
                    hex(id(self)), self._mac_address_string, self._name)
        )

    # TODO: This could be done with a property decorator but personally I favor
    #       the getter method here.
    def get_mac_address(self):
        """Allow the programmer to view but not change MAC address."""
        log.debug("Getting mac_address %s", self._mac_address_string)
        return self._mac_address_string

    # TODO: This could be done with a property decorator but personally I favor
    #       the getter method here.
    def get_name(self):
        """Allow the programmer to view but not change name."""
        log.debug("Getting name %s", self._name)
        return self._name

    def get_rssi(self, from_connection=False):
        log.debug("Getting RSSI from %s",
                  'connection' if from_connection else 'scan response')
        raise NotImplementedError()
        rssi = None
        if from_connection:
            raise NotImplementedError()
        else:
            rssi = self._scan_response_rssi
        assert(rssi is not None)
        log.debug("RSSI is %d dBm", rssi)
        return rssi

    def connect(self):
        log.debug("Connecting")
        self._backend.connect(self._mac_address_bytearray)
        # TODO: store a connection object
        log.debug("Connected")

    def disconnect(self):
        log.debug("Disconnecting")
        # TODO: pass in a connection object
        self._backend.disconnect(None)
        log.debug("Disconnected")

    def list_services(self):
        """Get a list of GattService objects that contain characteristics and
        their descriptors.
        """
        log.debug("Listing services")
        if self._services is None:
            # TODO: pass in a connection object
            self._services = self._backend.discover_attributes()
        log.debug("Services:")
        for s in self._services:
            log.debug(s)
            for c in s.characteristics:
                log.debug(c)
                for d in c.descriptors:
                    log.debug(d)
        return self._services

    def encrypt(self):
        log.debug("Encrypting connection")
        raise NotImplementedError()
        # TODO: pass in a connection object
        self._backend.encrypt()
        log.debug("Connection encrypted")

    def bond(self):
        log.debug("Forming bonded connection")
        raise NotImplementedError()
        # TODO: pass in a connection object
        self._backend.bond()
        log.debug("Bonded connection formed")

    def char_read(self, characteristic):
        log.debug("Reading from characteristic {0}".format(characteristic))
        # TODO: pass in a connection object
        value_bytearray = self._backend.attribute_read(characteristic)
        log.debug("Read value {0}".format([hex(b) for b in value_bytearray]))
        return value_bytearray

    def char_write(self, characteristic, value_bytearray):
        log.debug("Writing value {0} to characteristic {1}"
                  .format(value_bytearray, characteristic))
        # TODO: pass in a connection object
        self._backend.attribute_write(characteristic, value_bytearray)
        log.debug("Done writing")

    def subscribe(self, characteristic, notifications=True, indications=False,
                  callback=None):
        log.debug("Subscribing to characteristic {0}".format(characteristic))
        raise NotImplementedError()
        # TODO: pass in a connection object
        self._backend.subscribe(characteristic, notifications,
                                indications, callback)
        log.debug("Done subscribing")
