from mock import patch
from nose.tools import nottest  # assert_raises
import platform
import Queue
import unittest
from struct import pack  # , unpack


from pygatt.bled112_backend import BLED112Backend
# from pygatt.exceptions import BLED112Error


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
                return read_byte
            else:
                if not self._output_queue.empty():
                    self._active_packet = self._output_queue.get()

                # TODO return the next byte instead of wasting a cycle
                return b''

    def stage_output(self, next_output):
        self._output_queue.put(next_output)
        if self._active_packet is None:
            self._active_packet = self._output_queue.get()


class BLED112_BackendTests(unittest.TestCase):
    """
    Test the functionality of the BLED112Backend class.
    """
    def setUp(self):
        self.patchers = []
        patcher = patch('serial.Serial', return_value=SerialMock('dummy', 0.25))
        patcher.start()
        self.patchers.append(patcher)
        # Where to write BLED112 logfiles
        system = platform.system()
        self.null_file = '/dev/null'
        if system.lower() == 'windows':
            self.null_file = 'nul'

    def tearDown(self):
        for patcher in self.patchers:
            try:
                patcher.stop()
            except RuntimeError:
                pass

    @nottest
    def _stage_disconnect_packets(self, bled112, connected, fail,
                                  connection_handle=0x00):
        if connected:
            if fail:
                raise NotImplementedError()
            else:
                # Stage ble_rsp_connection_disconnect (success)
                bled112._ser.stage_output(pack(
                    '<4BBH', 0x00, 0x03, 0x03, 0x00, connection_handle, 0x0000))
                # Stage ble_evt_connection_disconnected (success by local user)
                bled112._ser.stage_output(pack(
                    '<4BBH', 0x80, 0x03, 0x03, 0x04, connection_handle, 0x0000))
        else:  # not connected always fails
            bled112._ser.stage_output(pack(
                '<4BBH', 0x00, 0x03, 0x03, 0x00, connection_handle, 0x0186))

    @nottest
    def _stage_run_packets(self, bled112):
        # Stage ble_rsp_connection_disconnect (not connected, fail)
        self._stage_disconnect_packets(bled112, False, True)
        # Stage ble_rsp_gap_set_mode (success)
        bled112._ser.stage_output(pack(
            '<4BH', 0x00, 0x02, 0x06, 0x01, 0x0000))
        # Stage ble_rsp_gap_end_procedure (fail device in wrong state)
        bled112._ser.stage_output(pack(
            '<4BH', 0x00, 0x02, 0x06, 0x04, 0x0181))
        # Stage ble_rsp_sm_set_bondable_mode
        bled112._ser.stage_output(pack(
            '<4B', 0x00, 0x00, 0x05, 0x01))

    @nottest
    def _stage_connect_packets(self, bled112, addr, connection_handle=0x00):
        # Stage ble_rsp_gap_connect_direct (success, conn handle 0x99)
        bled112._ser.stage_output(pack(
            '<4BHB', 0x00, 0x03, 0x06, 0x03, 0x0000, connection_handle))
        # Stage ble_evt_connection_status (flags = connected, completed;
        #   address_type = public; conn_interval = 7.5; timeout = 200;
        #   latency = 0; bonding = 0xFF)
        bled112._ser.stage_output(pack(
            '<4B2B6BB3HB', 0x80, 0x10, 0x03, 0x00, connection_handle, 0x05,
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], 0x00, 0x0006,
            0x0014, 0x0000, 0xFF))

    def test_create_BLED112_Backend(self):
        assert(BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False) is not None)

    def test_BLED112_Backend_run_stop(self):
        # Create bled112
        bled112 = BLED112Backend(serial_port='dummy', logfile=self.null_file,
                                 run=False)
        try:
            # Test run
            self._stage_run_packets(bled112)
            bled112.run()
        finally:
            # Make sure to stop the receiver thread
            bled112.stop()

    def test_BLED112_Backend_connect(self):
        # Create bled112
        bled112 = BLED112Backend(serial_port='dummy', logfile=self.null_file,
                                 run=False)
        try:
            self._stage_run_packets(bled112)
            bled112.run()
            # Test connect
            address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
            self._stage_connect_packets(bled112, address)
            bled112.connect(bytearray(address))
        finally:
            # Make sure to stop the receiver thread
            bled112.stop()

    def test_BLED112_Backend_disconnect_when_connected(self):
        # Create bled112
        bled112 = BLED112Backend(serial_port='dummy', logfile=self.null_file,
                                 run=False)
        try:
            self._stage_run_packets(bled112)
            bled112.run()
            address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
            self._stage_connect_packets(bled112, address)
            bled112.connect(bytearray(address))
            # Test disconnect (connected, not fail)
            self._stage_disconnect_packets(bled112, True, False)
            bled112.disconnect()
        finally:
            # Make sure to stop the receiver thread
            bled112.stop()

    # TODO
    def test_BLED112_Backend_char_read(self):
        pass

    # TODO
    def test_BLED112_Backend_char_write(self):
        pass

    # TODO
    def test_BLED112_Backend_encrypt(self):
        pass

    # TODO
    def test_BLED112_Backend_bond(self):
        pass

    # TODO
    def test_BLED112_Backend_get_rssi(self):
        pass

    # TODO
    def test_BLED112_Backend_get_handle(self):
        pass

    # TODO
    def test_BLED112_Backend_scan(self):
        pass

    # TODO
    def test_BLED112_Backend_get_devices_discovered(self):
        pass

    # TODO
    def test_BLED112_Backend_subscribe(self):
        pass

    # TODO
    def test_BLED112_Backend_wait_for_response(self):
        pass

    # TODO
    def test_BLED112_Backend_delete_stored_bonds(self):
        pass
