from __future__ import print_function

from binascii import unhexlify
from mock import patch
from nose.tools import nottest, eq_, assert_in
import platform
import Queue
import unittest
from struct import pack
import threading
import time

from pygatt.backends import BGAPIBackend


class SerialMock(object):
    """
    Spoof a serial.Serial object.
    """
    def __init__(self, port, timeout):
        self._isOpen = True
        self._port = port
        self._timeout = timeout
        self._output_queue = Queue.Queue()
        self._active_packet = None
        self._expected_input_queue = Queue.Queue()

    def open(self):
        self._isOpen = True

    def close(self):
        self._isOpen = False

    def write(self, input_data):
        pass

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


class BGAPIBackendTests(unittest.TestCase):
    """
    Test the functionality of the BGAPIBackend class.
    """
    def setUp(self):
        self.patchers = []
        patcher = patch('serial.Serial', return_value=SerialMock('dummy', 0.25))
        patcher.start()
        self.patchers.append(patcher)
        # Where to write BGAPIBackend logfiles
        system = platform.system()
        self.null_file = '/dev/null'
        if system.lower() == 'windows':
            self.null_file = 'nul'

        self.backend = BGAPIBackend(serial_port='dummy',
                                    logfile=self.null_file,
                                    run=False)

    def tearDown(self):
        self.backend.stop()

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

    @nottest
    def _uuid_str_to_bytearray(self, uuid_str):
        """Convert a UUID string to a bytearray."""
        return unhexlify(uuid_str.replace('-', ''))

    # ------------------------ Packet Building ---------------------------------
    @nottest
    def _ble_rsp_attclient_attribute_write(
            self, connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x04, 0x05, connection_handle,
                    return_code)

    @nottest
    def _ble_rsp_attclient_find_information(
            self, connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x04, 0x03, connection_handle,
                    return_code)

    @nottest
    def _ble_rsp_attclient_read_by_handle(self, connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x04, 0x04, connection_handle,
                    return_code)

    @nottest
    def _ble_rsp_connection_disconnect(self, connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x03, 0x00, connection_handle,
                    return_code)

    @nottest
    def _ble_rsp_connection_get_rssi(self, connection_handle, rssi_value):
        return pack('<4BBb', 0x00, 0x02, 0x03, 0x01, connection_handle,
                    rssi_value)

    @nottest
    def _ble_rsp_gap_connect_direct(self, connection_handle, return_code):
        return pack('<4BHB', 0x00, 0x03, 0x06, 0x03, return_code,
                    connection_handle)

    @nottest
    def _ble_rsp_gap_discover(self, return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x02, return_code)

    @nottest
    def _ble_rsp_gap_end_procedure(self, return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x04, return_code)

    @nottest
    def _ble_rsp_gap_set_mode(self, return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x01, return_code)

    @nottest
    def _ble_rsp_gap_set_scan_parameters(self, return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x07, return_code)

    @nottest
    def _ble_rsp_sm_delete_bonding(self, return_code):
        return pack('<4BH', 0x00, 0x02, 0x05, 0x02, return_code)

    @nottest
    def _ble_rsp_sm_encrypt_start(self, connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x05, 0x00, connection_handle,
                    return_code)

    @nottest
    def _ble_rsp_sm_get_bonds(self, num_bonds):
        assert((num_bonds >= 0) and (num_bonds <= 8))  # hardware constraint
        return pack('<4BB', 0x00, 0x01, 0x05, 0x05, num_bonds)

    @nottest
    def _ble_rsp_sm_set_bondable_mode(self):
        return pack('<4B', 0x00, 0x00, 0x05, 0x01)

    @nottest
    def _ble_evt_attclient_attribute_value(
            self, connection_handle, att_handle, att_type, value):
        # the first byte of value must be the length of value
        assert((len(value) > 0) and (value[0] == len(value)))
        return pack('<4BBHB' + str(len(value)) + 's', 0x80, 4 + len(value),
                    0x04, 0x05, connection_handle, att_handle, att_type,
                    b''.join(chr(i) for i in value))

    @nottest
    def _ble_evt_attclient_find_information_found(
            self, connection_handle, chr_handle, uuid):
        # the first byte of uuid must be the length of uuid
        assert((len(uuid) > 0) and (uuid[0] == len(uuid)))
        return pack('<4BBH' + str(len(uuid)) + 's', 0x80, 3 + len(uuid), 0x04,
                    0x04, connection_handle, chr_handle,
                    b''.join(chr(i) for i in uuid))

    @nottest
    def _ble_evt_attclient_procedure_completed(
            self, connection_handle, return_code, chr_handle):
        return pack('<4BB2H', 0x80, 0x05, 0x04, 0x01, connection_handle,
                    return_code, chr_handle)

    @nottest
    def _ble_evt_connection_status(
            self, addr, flags, connection_handle, address_type,
            connection_interval, timeout, latency, bonding):
        return pack(
            '<4B2B6BB3HB', 0x80, 0x10, 0x03, 0x00, connection_handle, flags,
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], address_type,
            connection_interval, timeout, latency, bonding)

    @nottest
    def _ble_evt_connection_disconnected(self, connection_handle, return_code):
        return pack('<4BBH', 0x80, 0x03, 0x03, 0x04, connection_handle,
                    return_code)

    @nottest
    def _ble_evt_gap_scan_response(
            self, rssi, packet_type, bd_addr, addr_type, bond, data):
        # the first byte of data must be the length of data
        assert((len(data) > 0) and (data[0] == len(data)))
        return pack('<4Bb9B' + str(len(data)) + 's', 0x80, 10 + len(data),
                    0x06, 0x00, rssi, packet_type, bd_addr[5], bd_addr[4],
                    bd_addr[3], bd_addr[2], bd_addr[1], bd_addr[0], addr_type,
                    bond, b''.join(chr(i) for i in data))

    @nottest
    def _ble_evt_sm_bond_status(self, bond_handle, keysize, mitm, keys):
        return pack('<4B4B', 0x80, 0x04, 0x05, 0x04, bond_handle, keysize, mitm,
                    keys)

    @nottest
    def _ble_evt_sm_bonding_fail(self, connection_handle, return_code):
        return pack('<4BBH', 0x80, 0x03, 0x05, 0x01, connection_handle,
                    return_code)

    # ------------------------ Packet Staging ----------------------------------
    @nottest
    def _stage_ble_evt_connection_disconnected_by_remote_user(
            self, backend, connection_handle=0x00):
        # Stage ble_evt_connection_disconnected (terminated by remote user)
        backend._ser.stage_output(self._ble_evt_connection_disconnected(
            connection_handle, 0x0213))

    @nottest
    def _stage_disconnect_packets(
            self, backend, connected, fail, connection_handle=0x00):
        """Stage the packets for backend.disconnect()."""
        if connected:
            if fail:
                raise NotImplementedError()
            else:
                # Stage ble_rsp_connection_disconnect (success)
                backend._ser.stage_output(self._ble_rsp_connection_disconnect(
                    connection_handle, 0x0000))
                # Stage ble_evt_connection_disconnected (success by local user)
                backend._ser.stage_output(
                    self._ble_evt_connection_disconnected(
                        connection_handle, 0x0000))
        else:  # not connected always fails
            # Stage ble_rsp_connection_disconnect (fail, not connected)
            backend._ser.stage_output(
                self._ble_rsp_connection_disconnect(
                    connection_handle, 0x0186))

    @nottest
    def _stage_run_packets(self, backend, connection_handle=0x00):
        # Stage ble_rsp_connection_disconnect (not connected, fail)
        self._stage_disconnect_packets(backend, False, True)
        # Stage ble_rsp_gap_set_mode (success)
        backend._ser.stage_output(self._ble_rsp_gap_set_mode(0x0000))
        # Stage ble_rsp_gap_end_procedure (fail, device in wrong state)
        backend._ser.stage_output(self._ble_rsp_gap_end_procedure(0x0181))
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        backend._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())

    @nottest
    def _stage_connect_packets(self, backend, addr, flags,
                               connection_handle=0x00):
        # Stage ble_rsp_gap_connect_direct (success)
        backend._ser.stage_output(self._ble_rsp_gap_connect_direct(
            connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        backend._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    @nottest
    def _stage_get_rssi_packets(self, backend, connection_handle=0x00,
                                rssi=-80):
        # Stage ble_rsp_connection_get_rssi
        backend._ser.stage_output(
            self._ble_rsp_connection_get_rssi(connection_handle, rssi))

    @nottest
    def _stage_encrypt_packets(self, backend, addr, flags,
                               connection_handle=0x00):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        backend._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        backend._ser.stage_output(self._ble_rsp_sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        backend._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    @nottest
    def _stage_bond_packets(self, backend, addr, flags,
                            connection_handle=0x00, bond_handle=0x01):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        backend._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        backend._ser.stage_output(self._ble_rsp_sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_sm_bond_status
        backend._ser.stage_output(self._ble_evt_sm_bond_status(
            bond_handle, 0x00, 0x00, 0x00))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        backend._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    @nottest
    def _stage_delete_stored_bonds_packets(
            self, backend, bonds, disconnects=False):
        """bonds -- list of 8-bit integer bond handles"""
        if disconnects:
            self._stage_ble_evt_connection_disconnected_by_remote_user(backend)
        # Stage ble_rsp_get_bonds
        backend._ser.stage_output(self._ble_rsp_sm_get_bonds(len(bonds)))
        # Stage ble_evt_sm_bond_status (bond handle)
        for b in bonds:
            if disconnects:
                self._stage_ble_evt_connection_disconnected_by_remote_user(
                    backend)
            backend._ser.stage_output(self._ble_evt_sm_bond_status(
                b, 0x00, 0x00, 0x00))
        # Stage ble_rsp_sm_delete_bonding (success)
        for b in bonds:
            if disconnects:
                self._stage_ble_evt_connection_disconnected_by_remote_user(
                    backend)
            backend._ser.stage_output(self._ble_rsp_sm_delete_bonding(0x0000))

    @nottest
    def _stage_scan_packets(self, backend, scan_responses=[]):
        # Stage ble_rsp_gap_set_scan_parameters (success)
        backend._ser.stage_output(self._ble_rsp_gap_set_scan_parameters(0x0000))
        # Stage ble_rsp_gap_discover (success)
        backend._ser.stage_output(self._ble_rsp_gap_discover(0x0000))
        for srp in scan_responses:
            # Stage ble_evt_gap_scan_response
            backend._ser.stage_output(self._ble_evt_gap_scan_response(
                srp['rssi'], srp['packet_type'], srp['bd_addr'],
                srp['addr_type'], srp['bond'],
                [len(srp['data'])+1]+srp['data']))
        # Stage ble_rsp_gap_end_procedure (success)
        backend._ser.stage_output(self._ble_rsp_gap_end_procedure(0x0000))

    @nottest
    def _stage_get_handle_packets(
            self, backend, uuid_handle_list, connection_handle=0x00):
        # Stage ble_rsp_attclient_find_information (success)
        backend._ser.stage_output(self._ble_rsp_attclient_find_information(
            connection_handle, 0x0000))
        for i in range(0, len(uuid_handle_list)/2):
            uuid = self._uuid_str_to_bytearray(uuid_handle_list[2*i])
            handle = uuid_handle_list[2*i + 1]
            # Stage ble_evt_attclient_find_information_found
            u = [len(uuid) + 1]
            backend._ser.stage_output(
                self._ble_evt_attclient_find_information_found(
                    connection_handle, handle,
                    (u+list(reversed([ord(b) for b in uuid])))))
        # Stage ble_evt_attclient_procedure_completed (success)
        backend._ser.stage_output(self._ble_evt_attclient_procedure_completed(
            connection_handle, 0x0000, 0xFFFF))

    @nottest
    def _stage_char_read_packets(
            self, backend, att_handle, att_type, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_read_by_handle (success)
        backend._ser.stage_output(self._ble_rsp_attclient_read_by_handle(
            connection_handle, 0x0000))
        # Stage ble_evt_attclient_attribute_value
        backend._ser.stage_output(self._ble_evt_attclient_attribute_value(
            connection_handle, att_handle, att_type, [len(value)+1]+value))

    @nottest
    def _stage_char_write_packets(
            self, backend, handle, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_attribute_write (success)
        backend._ser.stage_output(self._ble_rsp_attclient_attribute_write(
            connection_handle, 0x0000))
        # Stage ble_evt_attclient_procedure_completed
        backend._ser.stage_output(self._ble_evt_attclient_procedure_completed(
            connection_handle, 0x0000, handle))

    @nottest
    def _stage_subscribe_packets(self, backend, uuid_char, handle_char,
                                 indications=False, connection_handle=0x00):
        # Stage get_handle packets
        uuid_desc = '2902'
        handle_desc = 0x5678
        self._stage_get_handle_packets(backend, [
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = backend.get_handle(self._uuid_str_to_bytearray(uuid_char),
                                    self._uuid_str_to_bytearray(uuid_desc))
        # Stage char_write packets
        if indications:
            value = [0x02, 0x00]
        else:
            value = [0x01, 0x00]
        self._stage_char_write_packets(backend, handle, value,
                                       connection_handle=connection_handle)

    @nottest
    def _stage_indication_packets(
            self, backend, handle, packet_values, connection_handle=0x00):
        # Stage ble_evt_attclient_attribute_value
        for value in packet_values:
            val = list(value)
            backend._ser.stage_output(self._ble_evt_attclient_attribute_value(
                connection_handle, handle, 0x00,
                value=[len(val)+1]+val))

    def test_run_backend(self):
        """run general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()

    def test_connect(self):
        """connect general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        # Test connect
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))

    def test_disconnect_when_connected(self):
        """disconnect general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # test disconnect (connected, not fail)
        self._stage_disconnect_packets(self.backend, True, False)
        self.backend.disconnect()

    def test_char_read(self):
        """read general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self._stage_get_handle_packets(self.backend, [
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(
            self._uuid_str_to_bytearray(uuid_char))
        # Test char_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self._stage_char_read_packets(
            self.backend, handle, 0x00, expected_value)
        value = self.backend.char_read(handle)
        assert(value == bytearray(expected_value))

    def test_char_write(self):
        """char_write general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self._stage_get_handle_packets(self.backend, [
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(
            self._uuid_str_to_bytearray(uuid_char))
        # Test char_write
        value = [0xF0, 0x0F, 0x00]
        self._stage_char_write_packets(self.backend, handle, value)
        self.backend.char_write(handle, bytearray(value))

    def test_encrypt(self):
        """encrypt general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test encrypt
        self._stage_encrypt_packets(
            self.backend, address, ['connected', 'encrypted'])
        self.backend.encrypt()

    def test_bond(self):
        """bond general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        self._stage_bond_packets(self.backend, address,
                                 ['connected', 'encrypted',
                                  'parameters_change'])
        self.backend.bond()

    def test_get_rssi(self):
        """get_rssi general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test get_rssi
        self._stage_get_rssi_packets(self.backend)
        assert(self.backend.get_rssi() == -80)

    def test_get_handle(self):
        """get_handle general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test get_handle
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self._stage_get_handle_packets(self.backend, [
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(
            self._uuid_str_to_bytearray(uuid_char))
        assert(handle == handle_char)
        handle = self.backend.get_handle(
            self._uuid_str_to_bytearray(uuid_char),
            self._uuid_str_to_bytearray(uuid_desc))
        assert(handle == handle_desc)

    def test_scan_and_get_devices_discovered(self):
        """scan/get_devices_discovered general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        # Test scan
        scan_responses = []
        addr_0 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        addr_0_str = ':'.join('%02x' % b for b in addr_0)
        scan_responses.append({
            'rssi': -80,
            'packet_type': 0,
            'bd_addr': addr_0,
            'addr_type': 0x00,
            'bond': 0xFF,
            'data': [0x07, 0x09, ord('H'), ord('e'), ord('l'),
                     ord('l'), ord('o'), ord('!')]
        })
        self._stage_scan_packets(self.backend,
                                 scan_responses=scan_responses)
        self.backend.scan()
        devs = self.backend.get_devices_discovered()
        assert_in(addr_0_str, devs)
        eq_('Hello!', devs[addr_0_str].name)
        eq_(-80, devs[addr_0_str].rssi)

    def test_subscribe_with_notify(self):
        """subscribe with notify general functionality."""

        class NotificationHandler(object):
            def __init__(self, expected_value_bytearray):
                self.expected_value_bytearray = expected_value_bytearray
                self.received_value_bytearray = None
                self.called = threading.Event()

            def handle(self, received_value_bytearray):
                self.received_value_bytearray = received_value_bytearray
                self.called.set()

        self._stage_run_packets(self.backend)
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            self.backend, address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test subscribe with indications
        packet_values = [bytearray([0xF0, 0x0D, 0xBE, 0xEF])]
        my_handler = NotificationHandler(packet_values[0])
        handle = 0x1234
        uuid = '01234567-0123-0123-0123-0123456789AB'
        self._stage_subscribe_packets(self.backend, uuid, handle)
        self.backend.subscribe(self._uuid_str_to_bytearray(uuid),
                               callback=my_handler.handle, indicate=True)
        start_time = time.time()
        self._stage_indication_packets(self.backend, handle, packet_values)
        while not my_handler.called.is_set():
            elapsed_time = start_time - time.time()
            if elapsed_time >= 5:
                raise Exception("Callback wasn't called after {0} seconds."
                                .format(elapsed_time))
        print([b for b in my_handler.expected_value_bytearray])
        print([b for b in my_handler.received_value_bytearray])
        assert(my_handler.expected_value_bytearray ==
               my_handler.received_value_bytearray)

    def test_delete_stored_bonds(self):
        """delete_stored_bonds general functionality."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        # Test delete stored bonds
        self._stage_delete_stored_bonds_packets(
            self.backend, [0x00, 0x01, 0x02, 0x03, 0x04])
        self.backend.delete_stored_bonds()

    def test_delete_stored_bonds_disconnect(self):
        """delete_stored_bonds shouldn't abort if disconnected."""
        self._stage_run_packets(self.backend)
        self.backend.run()
        # Test delete stored bonds
        self._stage_delete_stored_bonds_packets(
            self.backend, [0x00, 0x01, 0x02, 0x03, 0x04], disconnects=True)
        self.backend.delete_stored_bonds()
