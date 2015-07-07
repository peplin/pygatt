from mock import patch
import Queue
import unittest
from struct import pack, unpack


from pygatt.bled112_backend import BLED112Backend


class SerialMock(object):
    """
    Spoof a serial.Serial object.
    """
    def __init__(self, port, timeout):
        self._isOpen = True
        self._port = port
        self._timeout = timeout
        self._input = None
        self._output_queue = Queue.Queue()
        self._active_packet = None

    def open(self):
        self._isOpen = True

    def close(self):
        self._isOpen = False

    def write(self, input_data):
        self._input = input_data

    def read(self):
        if self._output_queue.empty() and self._active_packet is None:
            # Return an empty byte string.  The BLED112 backend receiver thread
            # check for len(x) > 0 on each serial read, so the return type
            # must be a valid argument of len(x)
            return b''
        else:
            if self._active_packet is not None:
                read_byte = self._active_packet[0]
                self._active_packet = self._active_packet[1:]
                if len(self._active_packet) is 0:
                    self._active_packet = None

                # BLED112 backend calls ord() on the return value, so cast to
                # a char
                return chr(read_byte)
            else:
                if not self._output_queue.empty():
                    self._active_packet = self._output_queue.get()

                # TODO return the next byte instead of wasting a cycle
                return b''

    def stage_output(self, next_output):
        self._output_queue.put(next_output)
        if self._active_packet is None:
            self._active_packet = self._output_queue.get()


# FIXME: docstring, pack unpack
def bled112_response_packet_builder(length, cmd_class_id, cmd_id, payload):
    """
    """
    # Shift out the bottom 5 low bits
    message_type = unpack('B', pack('B', length))[0] >> 5
    # Mask out the top three high bits
    length_remainder = unpack('B', pack('B', length))[0] & 0x1F

    # Pack the header
    return unpack('<BBBB',
                  pack('<BBBB',
                       message_type,
                       length_remainder,
                       cmd_class_id,
                       cmd_id)) + payload


class BLED112_BackendTests(unittest.TestCase):
    """
    Test the functionality of the BLED112Backend class.
    """
    def setUp(self):
        self.patchers = []
        patcher = patch('serial.Serial', return_value=SerialMock('dummy', 0.25))
        patcher.start()
        self.patchers.append(patcher)

    def tearDown(self):
        for patcher in self.patchers:
            try:
                patcher.stop()
            except RuntimeError:
                pass

    def test_create_BLED112_Backend(self):
        assert(BLED112Backend(serial_port='dummy', run=False) is not None)
