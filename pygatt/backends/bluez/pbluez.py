import logging
import time
from functools import partial
from gi.repository import GLib
from pydbus import SystemBus
from threading import Thread
from itertools import chain

from multiprocessing import Process, Queue

from pygatt.exceptions import NotConnectedError, BLEError
from pygatt.backends import BLEBackend
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from pygatt.backends.bluez.device import BluezBLEDevice
from pygatt.backends.bluez.bluez import BluezBackend

log = logging.getLogger(__name__)


def g_bluez_proc(self):
    obj_id_to_obj = {}
    # obj counter 0 is a special value
    obj_counter = 1

    def callback_generic(obj_id, handle, data):
        self.q_async.put( { 'handle': handle,
                  'obj_id': obj_id,
                  'data':data } )

    while True:
        # We do this as an implicit blocking call to keep our loop from running
        # out of control.
        request = self.q_req.get()

        response = {
            'return_val' : None,
            'exception' : None,
        }

        try:
            args = request['args']
            kwargs = request['kwargs']

            if request['obj_id'] == 0 :
                if 'func_name' != '__init__' :
                    raise Exception("Invalid object id argument")
                else :
                    bleBackend = BluezBackend(**kwargs)
                    obj_id_to_obj[obj_counter] = bleBackend
                    response['return_val'] = obj_counter
                    obj_counter += 1
            else :
                obj = obj_id_to_obj[request['obj_id']]
                func_name = request['func_name']

                if func_name == 'start' :
                    obj.start()
                elif func_name == 'stop' :
                    obj.stop()
                elif func_name == 'scan' :
                    response['return_val'] = obj.scan(**kwargs)
                elif func_name == 'connect' :
                    bleDevObj= obj.connect(*args, **kwargs)
                    obj_id_to_obj[obj_counter] = bleDevObj
                    response['return_val'] = obj_counter
                    obj_counter += 1
                elif func_name == 'd_subscribe' :
                    kwargs['callback'] = partial(callback_generic, request['obj_id'])
                    response['return_val'] = obj.subscribe(*args, **kwargs)
                elif func_name == 'd_get_handle' :
                    response['return_val'] = obj.get_handle(*args)
                elif func_name == 'd_char_read' :
                    response['return_val'] = obj.char_read(*args, **kwargs)
                elif func_name == 'd_char_write' :
                    response['return_val'] = obj.char_write(*args, **kwargs)
                elif func_name == 'd_connect' :
                    response['return_val'] = obj.connect( **kwargs)
                elif func_name == 'd_disconnect' :
                    response['return_val'] = obj.disconnect( **kwargs)
                elif func_name == 'd_discover_characteristics' :
                    response['return_val'] = obj.discover_characteristics(**kwargs)
                elif func_name == 'd_get_rssi' :
                    response['return_val'] = obj.get_rssi()
                elif func_name == 'kill_self' :
                    # This returns from the entire process
                    return 0
        except Exception as e:
            response['exception'] = e

        self.q_sync.put(response)


class ProcBluezBackend(object):
    """
    This is a wrapper backend that is designed to have all glib tasks isolated
    into its own process and seperate from critial data consumption tasks.

    Pros: Memory isolation
    Cons: performance degradation for synchronous tasks
    ( Under high loads with callbacks you might actually have performance
    benefits )
    """

    def _do_function_call(self, obj_id, func_name, args, kwargs ) :
        self.q_req.put({'obj_id':obj_id,
                        'func_name':func_name,
                        'args':args,
                        'kwargs':kwargs})
        resp_dict = self.q_sync.get()
        if resp_dict['exception'] is None:
            return resp_dict['return_val']
        else :
            raise resp_dict['exception']

    def __init__(self, **kwargs):
        # init our own variables and wrap the other init call into a queue call

        self._obj_id = 0
        self.bluezdev_dict = {}
        # Requests to run function
        self.q_req = Queue()
        # responses to function requests
        self.q_sync = Queue()
        # callbacks
        self.q_async = Queue()
        # This process gets a snapshot of self AT THIS MOMENT
        # it doesn't have shared state after this.
        self.proc = Process(target=g_bluez_proc, args=(self,))
        self.proc.start()
        self._obj_id = self._do_function_call(self._obj_id, '__init__', (), kwargs)

    def consume_async_queue():
        qsize = self.q_async.qsize()
        for i in qsize :
            async_dict = self.q_async.get()
            obj_id = async_dict['obj_id']
            handle = async_dict['handle']
            data = async_dict['data']
            self.bluezdev_dict[obj_id].do_callback(handle,data)


    def start(self):
        self._do_function_call(self._obj_id, 'start', (), {})
        log.debug("Started")

    def stop(self):
        try :
            self._do_function_call(self._obj_id, 'stop', (), {})
            log.info("Stopped")
            self.q_req.put('kill_self')
            self.proc.join()
        except Exception:
            log.error("Process wont stop")
            self.proc.kill()

    def scan(self, **kwargs):
        log.info("Scanning...")
        return self._do_function_call(self._obj_id, 'scan', (), kwargs)

    def connect(self, *args, **kwargs):
        # TODO Create a Proc BluezDevice
        bluezdev_id = self._do_function_call(self._obj_id, 'connect', args, kwargs)

        bledevice = BluezBLEDevice(bluezdev_id, self)
        self.bluezdev_dict[bluezdev_id] = bledevice
        return bledevice
