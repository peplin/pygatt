import logging

from .backends import BackendEnum, BGAPIBackend
from .device import BleDevice


log = logging.getLogger(__name__)


class BluetoothAdapterError(Exception):
    pass


class BluetoothAdapter(object):

    def __init__(self, backend):
        log.debug("Creating BluetoothAdapter with backend %s",
                  backend.name)
        self._backend = self._get_backend(backend)
        self._enabled = False
        log.debug("BluetoothAdapter created")

    def __repr__(self):
        return ("<{0}.{1} object at {2} with backend {3}>"
                .format(self.__module__.__name__, self.__class__.__name__,
                        id(self), self._backend))

    def enable(self):
        """Turn on the Bluetooth Adapter."""
        log.debug("Enabling BluetoothAdapter")
        self._backend.start()
        self._enabled = True
        log.debug("BluetoothAdapter enabled")

    def disable(self):
        """Turn off the Bluetooth Adapter."""
        log.debug("Disabling BluetoothAdapter")
        self._backend.stop()
        self._enabled = False
        log.debug("BluetoothAdapter disabled")

    def reset(self):
        """Stop all ongoing procedures and enter a known, stable state."""
        log.debug("Resetting BluetoothAdapter")
        self._require_enabled()
        raise NotImplementedError()
        self._backend.stop()
        self._backend.start()
        log.debug("BluetoothAdapter reset")

    def list_bonds(self):
        log.debug("Listing bonds")
        self._require_enabled()
        raise NotImplementedError()
        log.debug("Bonds: {0}".format([]))  # TODO actually log bonds

    def clear_bonds(self):
        log.debug("Clearing bonds")
        self._require_enabled()
        raise NotImplementedError()
        log.debug("Bonds cleared")

    def scan(self, scan_time_seconds=1):
        log.debug("Scanning for devices")
        scan_results = self._backend.scan(scan_time=scan_time_seconds*1000)
        devs = []
        for addr, d in scan_results.iteritems():
            devs.append(BleDevice(self._backend, addr, name=d.name,
                                  scan_response_rssi=d.rssi))
        log.debug("Devices found: {0}".format(devs))
        return devs

    def _require_enabled(self):
        log.debug("Checking if enabled")
        if not self._enabled:
            log.error("BluetoothAdapter not enabled")
            raise BluetoothAdapterError(
                "BluetoothAdapter must be enabled for this operation")
        log.debug("BluetoothAdapter was enabled")

    # TODO: this factory method should probably be moved to a backend related
    #       file (BluetoothAdapter shouldn't have to know how to make a backend)
    def _get_backend(self, backend):
        log.debug("Getting backend instance for %s", backend.name)
        backend_instance = None
        if backend == BackendEnum.bgapi:
            # TODO: auto-discover serial port and stuff
            serial_port = '/dev/ttyACM0'
            backend_instance = BGAPIBackend(serial_port)
        else:
            msg = "{0} is not a valid backend".format(backend)
            log.error(msg)
            raise ValueError(msg)
        log.debug("Got backend instance {0}".format(backend_instance))
        return backend_instance
