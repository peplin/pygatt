# import functools
# import logging
# import time
# import copy
#
# from gi.repository import GLib
# from pygatt import BLEDevice
# from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
# from pygatt.exceptions import NotConnectedError

log = logging.getLogger(__name__)

class ProcBluezBLEDevice(object):
    """ A Wrapper object for all requests to go to a seperate process.
    """
    def __init__(self, id_num, bluez_dev):
        self._obj_id
        self._bluez_dev = bluez_dev
        self._callbacks = {}

    def do_callback(handle, data):
        self._callbacks[handle](handle, data)

    def subscribe(self, *args, **kwargs):
        uuid = args[0]
        self._bluez_dev._do_function_call(self._obj_id, 'd_subscribe', *args, **kwargs)
        handle = self.get_handle(uuid)
        self._callbacks[handle] = kwargs['callback']

    # TODO cache handles
    def get_handle(self, *args):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_get_handle', *args, {})

    def char_read(self, *args, **kwargs):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_char_read', *args, **kwargs)

    def char_write(self, *args, **kwargs):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_char_write', *args, **kwargs)

    def connect(self, **kwargs):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_connect', (), **kwargs)

    def disconnect(self, **kwargs):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_disconnect', (), **kwargs)

    def discover_characteristics(self, **kwargs):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_discover_characteristics', (), **kwargs)

    def get_rssi(self):
        return self._bluez_dev._do_function_call(self._obj_id, 'd_get_rssi', (), {})
