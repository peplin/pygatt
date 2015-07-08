from __future__ import print_function

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
        if self._active_packet is None:
            try:
                self._active_packet = self._output_queue.get_nowait()
            except Queue.Empty:
                # When no bytes to read, serial.read() returns empty byte string
                return b''
        read_byte = self._active_packet[0]
        if len(self._active_packet) == 1:  # we read the last byte
            self._active_packet = None
        else:
            self._active_packet = self._active_packet[1:]
        return read_byte

    def stage_output(self, next_output):
        self._output_queue.put(next_output)


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
    def _get_connection_status_flags_byte(self, flags):
        flags_byte = 0x00
        if 'connected' in flags:
            flags_byte |= 0x01
        if 'encrypted' in flags:
            flags_byte |= 0x02
        if 'completed' in flags:
            flags_byte |= 0x04
        if 'parameters_change' in flags:
            flags_byte |= 0x08
        return flags_byte

    # ------------------------ Packet Building ---------------------------------
    @nottest
    def _ble_rsp_attclient_attribute_write(self):
        pass

    @nottest
    def _ble_rsp_attclient_find_information(self):
        pass

    @nottest
    def _ble_rsp_attclient_read_by_handle(self):
        pass

    @nottest
    def _ble_rsp_connection_disconnect(self, fail=False,
                                       connection_handle=0x00):
        if fail:
            ret_code = 0x0186  # not connected
        else:
            ret_code = 0x0000  # success
        return pack('<4BBH', 0x00, 0x03, 0x03, 0x00, connection_handle,
                    ret_code)

    @nottest
    def _ble_rsp_connection_get_rssi(self, connection_handle=0x00, rssi=-80):
        return pack('<4BBb', 0x00, 0x02, 0x03, 0x01, connection_handle, rssi)

    @nottest
    def _ble_rsp_gap_connect_direct(self, fail=False, connection_handle=0x00):
        if fail:
            raise NotImplementedError()
        else:
            ret_code = 0x0000  # success
        return pack('<4BHB', 0x00, 0x03, 0x06, 0x03, ret_code,
                    connection_handle)

    @nottest
    def _ble_rsp_gap_discover(self):
        pass

    @nottest
    def _ble_rsp_gap_end_procedure(self, fail=False):
        if fail:
            ret_code = 0x0181  # device in wrong state
        else:
            ret_code = 0x0000  # success
        return pack('<4BH', 0x00, 0x02, 0x06, 0x04, ret_code)

    @nottest
    def _ble_rsp_gap_set_mode(self, fail=False):
        if fail:
            ret_code = 0x0181  # device in wrong state
        else:
            ret_code = 0x0000  # success
        return pack('<4BH', 0x00, 0x02, 0x06, 0x01, ret_code)

    @nottest
    def _ble_rsp_gap_set_scan_parameters(self):
        pass

    @nottest
    def _ble_rsp_sm_delete_bonding(self):
        pass

    @nottest
    def _ble_rsp_sm_encrypt_start(self, fail=False, connection_handle=0x00):
        if fail:
            raise NotImplementedError()
        else:
            ret_code = 0x0000  # success
        return pack('<4BBH', 0x00, 0x03, 0x05, 0x00, connection_handle,
                    ret_code)

    @nottest
    def _ble_rsp_sm_get_bonds(self):
        pass

    @nottest
    def _ble_rsp_sm_set_bondable_mode(self):
        return pack('<4B', 0x00, 0x00, 0x05, 0x01)

    @nottest
    def _ble_evt_attclient_attribute_value(self):
        pass

    @nottest
    def _ble_evt_attclient_find_information_found(self):
        pass

    @nottest
    def _ble_evt_attclient_procedure_completed(self):
        pass

    @nottest
    def _ble_evt_connection_status(
        self, addr, flags, connection_handle=0x00, address_type=0x00,
        connection_interval=0x0006, timeout=0x0014, latency=0x0000,
        bonding=0xFF
    ):
        return pack(
            '<4B2B6BB3HB', 0x80, 0x10, 0x03, 0x00, connection_handle, flags,
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], address_type,
            connection_interval, timeout, latency, bonding)

    @nottest
    def _ble_evt_connection_disconnected(self, connection_handle=0x00,
                                         terminator='local_user'):
        if terminator == 'local_user':
            ret_code = 0x0000
        else:
            raise NotImplementedError(terminator)
        return pack('<4BBH', 0x80, 0x03, 0x03, 0x04, connection_handle,
                    ret_code)

    @nottest
    def _ble_evt_gap_scan_response(self):
        pass

    @nottest
    def _ble_evt_sm_bond_status(self):
        pass

    @nottest
    def _ble_evt_sm_bonding_fail(self):
        pass

    # ------------------------ Packet Staging ----------------------------------
    @nottest
    def _stage_disconnect_packets(self, bled112, connected, fail,
                                  connection_handle=0x00):
        if connected:
            if fail:
                raise NotImplementedError()
            else:
                # Stage ble_rsp_connection_disconnect (success)
                bled112._ser.stage_output(self._ble_rsp_connection_disconnect())
                # Stage ble_evt_connection_disconnected (success by local user)
                bled112._ser.stage_output(
                    self._ble_evt_connection_disconnected())
        else:  # not connected always fails
            # Stage ble_rsp_connection_disconnect (fail)
            bled112._ser.stage_output(
                self._ble_rsp_connection_disconnect(fail=True))

    @nottest
    def _stage_run_packets(self, bled112):
        # Stage ble_rsp_connection_disconnect (not connected, fail)
        self._stage_disconnect_packets(bled112, False, True)
        # Stage ble_rsp_gap_set_mode (success)
        bled112._ser.stage_output(self._ble_rsp_gap_set_mode())
        # Stage ble_rsp_gap_end_procedure (fail device in wrong state)
        bled112._ser.stage_output(self._ble_rsp_gap_end_procedure(fail=True))
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        bled112._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())

    @nottest
    def _stage_connect_packets(self, bled112, addr, flags,
                               connection_handle=0x00):
        # Stage ble_rsp_gap_connect_direct (success)
        bled112._ser.stage_output(self._ble_rsp_gap_connect_direct(
            connection_handle=connection_handle))
        # Stage ble_evt_connection_status (flags = connected, completed)
        flags_byte = self._get_connection_status_flags_byte(flags)
        bled112._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle))

    @nottest
    def _stage_get_rssi_packets(self, bled112, connection_handle=0x00,
                                rssi=-80):
        # Stage ble_rsp_connection_get_rssi
        bled112._ser.stage_output(
            self._ble_rsp_connection_get_rssi(connection_handle, rssi))

    @nottest
    def _stage_encrypt_packets(self, bled112, addr, flags,
                               connection_handle=0x00):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        bled112._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        bled112._ser.stage_output(self._ble_rsp_sm_encrypt_start())
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        bled112._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle))

    # --------------------------- Tests ----------------------------------------
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
            self._stage_connect_packets(
                bled112, address, ['connected', 'completed'])
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
            self._stage_connect_packets(
                bled112, address, ['connected', 'completed'])
            bled112.connect(bytearray(address))
            # Test disconnect (connected, not fail)
            self._stage_disconnect_packets(bled112, True, False)
            bled112.disconnect()
        finally:
            # Make sure to stop the receiver thread
            bled112.stop()

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_char_read(self):
        pass

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_char_write(self):
        pass

    def test_BLED112_Backend_encrypt(self):
        # Create bled112
        bled112 = BLED112Backend(serial_port='dummy', logfile=self.null_file,
                                 run=False)
        try:
            self._stage_run_packets(bled112)
            bled112.run()
            address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
            self._stage_connect_packets(
                bled112, address, ['connected', 'completed'])
            bled112.connect(bytearray(address))
            # Test encrypt
            self._stage_encrypt_packets(
                bled112, address, ['connected', 'encrypted'])
            bled112.encrypt()
        finally:
            # Make sure to stop the receiver thread
            bled112.stop()

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_bond(self):
        pass

    def test_BLED112_Backend_get_rssi(self):
        # Create bled112
        bled112 = BLED112Backend(serial_port='dummy', logfile=self.null_file,
                                 run=False)
        try:
            self._stage_run_packets(bled112)
            bled112.run()
            address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
            self._stage_connect_packets(
                bled112, address, ['connected', 'completed'])
            bled112.connect(bytearray(address))
            # Test get_rssi
            self._stage_get_rssi_packets(bled112)
            assert(bled112.get_rssi() == -80)
        finally:
            # Make sure to stop the receiver thread
            bled112.stop()

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_get_handle(self):
        pass

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_scan(self):
        pass

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_get_devices_discovered(self):
        pass

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_subscribe(self):
        pass

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_wait_for_response(self):
        pass

    # TODO
    @unittest.skip("not implemented")
    def test_BLED112_Backend_delete_stored_bonds(self):
        pass
