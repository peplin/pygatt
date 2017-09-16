# for Python 2/3 compatibility
try:
    import queue
except ImportError:
    import Queue as queue

from mock import MagicMock


class SerialMock(object):
    """
    Spoof a serial.Serial object.
    """
    def __init__(self, port, timeout):
        self._isOpen = True
        self._port = port
        self._timeout = timeout
        self._output_queue = queue.Queue()
        self._active_packet = None
        self._expected_input_queue = queue.Queue()

    def open(self):
        self._isOpen = True

    def close(self):
        self._isOpen = False

    write = MagicMock()

    def flush(self):
        pass

    def read(self):
        if self._active_packet is None:
            try:
                self._active_packet = self._output_queue.get_nowait()
            except queue.Empty:
                # When no bytes to read, serial.read() returns empty bytes
                return bytes()
        read_byte = self._active_packet[0]
        if len(self._active_packet) == 1:  # we read the last byte
            self._active_packet = None
        else:
            self._active_packet = self._active_packet[1:]
        return bytearray([read_byte])

    def stage_output(self, next_output):
        self._output_queue.put(bytearray(next_output))
