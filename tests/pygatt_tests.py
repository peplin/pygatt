from __future__ import print_function

from binascii import hexlify, unhexlify
from mock import patch
from nose.tools import nottest
import platform
import Queue
import unittest
from struct import pack

from pygatt.bled112_backend import BLED112Backend


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
        # Note: if we want to check the incoming packets, uncomment this
        # try:
        #    expected_packet = self._expected_input_queue.get_nowait()
        #    assert(input_data == expected_packet)
        # except Queue.Empty:
        #    raise Exception("MockSerial._expected_input_queue was empty")

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

    # Note: if we want to check the incoming packets, uncomment this
    # def expect_input(self, next_input):
    #    self._expected_input_queue.put(next_input)


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
                    0x06, 0x00, rssi, packet_type, bd_addr[0], bd_addr[1],
                    bd_addr[2], bd_addr[3], bd_addr[4], bd_addr[5], addr_type,
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
    def _stage_disconnect_packets(
            self, bled112, connected, fail, connection_handle=0x00):
        """Stage the packets for bled112.disconnect()."""
        if connected:
            if fail:
                raise NotImplementedError()
            else:
                # Stage ble_rsp_connection_disconnect (success)
                bled112._ser.stage_output(self._ble_rsp_connection_disconnect(
                    connection_handle, 0x0000))
                # Stage ble_evt_connection_disconnected (success by local user)
                bled112._ser.stage_output(
                    self._ble_evt_connection_disconnected(
                        connection_handle, 0x0000))
        else:  # not connected always fails
            # Stage ble_rsp_connection_disconnect (fail, not connected)
            bled112._ser.stage_output(
                self._ble_rsp_connection_disconnect(
                    connection_handle, 0x0186))

    @nottest
    def _stage_run_packets(self, bled112, connection_handle=0x00):
        # Stage ble_rsp_connection_disconnect (not connected, fail)
        self._stage_disconnect_packets(bled112, False, True)
        # Stage ble_rsp_gap_set_mode (success)
        bled112._ser.stage_output(self._ble_rsp_gap_set_mode(0x0000))
        # Stage ble_rsp_gap_end_procedure (fail, device in wrong state)
        bled112._ser.stage_output(self._ble_rsp_gap_end_procedure(0x0181))
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        bled112._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())

    @nottest
    def _stage_connect_packets(self, bled112, addr, flags,
                               connection_handle=0x00):
        # Stage ble_rsp_gap_connect_direct (success)
        bled112._ser.stage_output(self._ble_rsp_gap_connect_direct(
            connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        bled112._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

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
        bled112._ser.stage_output(self._ble_rsp_sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        bled112._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    @nottest
    def _stage_bond_packets(self, bled112, addr, flags,
                            connection_handle=0x00, bond_handle=0x01):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        bled112._ser.stage_output(self._ble_rsp_sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        bled112._ser.stage_output(self._ble_rsp_sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_sm_bond_status
        bled112._ser.stage_output(self._ble_evt_sm_bond_status(
            bond_handle, 0x00, 0x00, 0x00))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        bled112._ser.stage_output(self._ble_evt_connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    @nottest
    def _stage_delete_stored_bonds_packets(self, bled112, bonds):
        """bonds -- list of 8-bit integer bond handles"""
        # Stage ble_rsp_get_bonds
        bled112._ser.stage_output(self._ble_rsp_sm_get_bonds(len(bonds)))
        # Stage ble_evt_sm_bond_status (bond handle)
        for b in bonds:
            bled112._ser.stage_output(self._ble_evt_sm_bond_status(
                b, 0x00, 0x00, 0x00))
        # Stage ble_rsp_sm_delete_bonding (success)
        for b in bonds:
            bled112._ser.stage_output(self._ble_rsp_sm_delete_bonding(0x0000))

    @nottest
    def _stage_scan_packets(self, bled112, scan_responses=[]):
        # Stage ble_rsp_gap_set_scan_parameters (success)
        bled112._ser.stage_output(self._ble_rsp_gap_set_scan_parameters(0x0000))
        # Stage ble_rsp_gap_discover (success)
        bled112._ser.stage_output(self._ble_rsp_gap_discover(0x0000))
        for srp in scan_responses:
            # Stage ble_evt_gap_scan_response
            bled112._ser.stage_output(self._ble_evt_gap_scan_response(
                srp['rssi'], srp['packet_type'], srp['bd_addr'],
                srp['addr_type'], srp['bond'],
                [len(srp['data'])+1]+srp['data']))
        # Stage ble_rsp_gap_end_procedure (success)
        bled112._ser.stage_output(self._ble_rsp_gap_end_procedure(0x0000))

    @nottest
    def _stage_get_handle_packets(
            self, bled112, uuid_handle_list, connection_handle=0x00):
        # Stage ble_rsp_attclient_find_information (success)
        bled112._ser.stage_output(self._ble_rsp_attclient_find_information(
            connection_handle, 0x0000))
        for i in range(0, len(uuid_handle_list)/2):
            uuid = uuid_handle_list[2*i]
            handle = uuid_handle_list[2*i + 1]
            # Stage ble_evt_attclient_find_information_found
            u = [len(unhexlify(uuid)) + 1]
            bled112._ser.stage_output(
                self._ble_evt_attclient_find_information_found(
                    connection_handle, int(handle, 16),
                    (u+list(reversed([ord(b) for b in unhexlify(uuid)])))))
        # Stage ble_evt_attclient_procedure_completed (success)
        bled112._ser.stage_output(self._ble_evt_attclient_procedure_completed(
            connection_handle, 0x0000, 0xFFFF))

    @nottest
    def _stage_char_read_packets(
            self, bled112, att_handle, att_type, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_read_by_handle (success)
        bled112._ser.stage_output(self._ble_rsp_attclient_read_by_handle(
            connection_handle, 0x0000))
        # Stage ble_evt_attclient_attribute_value
        bled112._ser.stage_output(self._ble_evt_attclient_attribute_value(
            connection_handle, att_handle, att_type, [len(value)+1]+value))

    @nottest
    def _stage_char_write_packets(
            self, bled112, handle, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_attribute_write (success)
        bled112._ser.stage_output(self._ble_rsp_attclient_attribute_write(
            connection_handle, 0x0000))
        # Stage ble_evt_attclient_procedure_completed
        bled112._ser.stage_output(self._ble_evt_attclient_procedure_completed(
            connection_handle, 0x0000, handle))

    @nottest
    def _stage_subscribe_packets(self, bled112, uuid0_bytearray, handle0,
                                 indications=False, connection_handle=0x00):
        # Stage get_handle packets
        uuid1_bytearray = bytearray([0x29, 0x02])
        handle1 = [0x56, 0x78]
        self._stage_get_handle_packets(bled112, [
            hexlify(uuid0_bytearray), hexlify(bytearray(handle0)),
            hexlify(uuid1_bytearray), hexlify(bytearray(handle1))
            ])
        handle = bled112.get_handle(uuid0_bytearray)
        assert(handle == int(hexlify(bytearray(handle0)), 16))
        # Stage char_write packets
        if indications:
            value = [0x02, 0x00]
        else:
            value = [0x01, 0x00]
        self._stage_char_write_packets(bled112, handle, value,
                                       connection_handle=connection_handle)

    @nottest
    def _stage_wait_for_response_packets(
            self, bled112, handle, packet_values, connection_handle=0x00):
        # Stage ble_evt_attclient_attribute_value
        for value in packet_values:
            val = list(value)
            bled112._ser.stage_output(self._ble_evt_attclient_attribute_value(
                connection_handle, int(hexlify(bytearray(handle)), 16), 0x00,
                value=[len(val)+1]+val))

    # --------------------------- Tests ----------------------------------------
    def test_create_BLED112_Backend(self):
        """__init__ general functionality."""
        bled112 = None
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        assert(bled112 is not None)

    def test_BLED112_Backend_run(self):
        """run general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        # Test run
        self._stage_run_packets(bled112)
        bled112.run()

    def test_BLED112_Backend_connect(self):
        """connect general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        # Test connect
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))

    def test_BLED112_Backend_disconnect_when_connected(self):
        """disconnect general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        # Test disconnect (connected, not fail)
        self._stage_disconnect_packets(bled112, True, False)
        bled112.disconnect()

    def test_BLED112_Backend_char_read(self):
        """read general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        uuid0 = '01234567-0123-0123-0123-0123456789AB'
        uuid0_bytearray = unhexlify(uuid0.replace('-', ''))
        handle0 = [0x12, 0x34]
        uuid1_bytearray = bytearray([0x29, 0x02])
        handle1 = [0x56, 0x78]
        self._stage_get_handle_packets(bled112, [
            hexlify(uuid0_bytearray), hexlify(bytearray(handle0)),
            hexlify(uuid1_bytearray), hexlify(bytearray(handle1))
            ])
        handle = bled112.get_handle(uuid0_bytearray)
        assert(handle == int(hexlify(bytearray(handle0)), 16))
        # Test char_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self._stage_char_read_packets(bled112, handle, 0x00, expected_value)
        value = bled112.char_read(handle)
        assert(value == bytearray(expected_value))

    def test_BLED112_Backend_char_write(self):
        """char_write general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        uuid0 = '01234567-0123-0123-0123-0123456789AB'
        uuid0_bytearray = unhexlify(uuid0.replace('-', ''))
        handle0 = [0x12, 0x34]
        uuid1_bytearray = bytearray([0x29, 0x02])
        handle1 = [0x56, 0x78]
        self._stage_get_handle_packets(bled112, [
            hexlify(uuid0_bytearray), hexlify(bytearray(handle0)),
            hexlify(uuid1_bytearray), hexlify(bytearray(handle1))
            ])
        handle = bled112.get_handle(uuid0_bytearray)
        assert(handle == int(hexlify(bytearray(handle0)), 16))
        # Test char_write
        value = [0xF0, 0x0F, 0x00]
        self._stage_char_write_packets(bled112, handle, value)
        bled112.char_write(handle, bytearray(value))

    def test_BLED112_Backend_encrypt(self):
        """encrypt general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
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

    def test_BLED112_Backend_bond(self):
        """bond general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        # Test encrypt
        self._stage_bond_packets(
            bled112, address, ['connected', 'encrypted',
                               'parameters_change'])
        bled112.bond()

    def test_BLED112_Backend_get_rssi(self):
        """get_rssi general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        # Test get_rssi
        self._stage_get_rssi_packets(bled112)
        assert(bled112.get_rssi() == -80)

    def test_BLED112_Backend_get_handle(self):
        """get_handle general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        # Test get_handle
        uuid0 = '01234567-0123-0123-0123-0123456789AB'
        uuid0_bytearray = unhexlify(uuid0.replace('-', ''))
        handle0 = [0x12, 0x34]
        uuid1_bytearray = bytearray([0x29, 0x02])
        handle1 = [0x56, 0x78]
        self._stage_get_handle_packets(bled112, [
            hexlify(uuid0_bytearray), hexlify(bytearray(handle0)),
            hexlify(uuid1_bytearray), hexlify(bytearray(handle1))
            ])
        handle = bled112.get_handle(uuid0_bytearray)
        assert(handle == int(hexlify(bytearray(handle0)), 16))
        handle = bled112.get_handle(uuid0_bytearray, uuid1_bytearray)
        assert(handle == int(hexlify(bytearray(handle1)), 16))

    def test_BLED112_Backend_scan_and_get_devices_discovered(self):
        """scan/get_devices_discovered general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        # Test scan
        scan_responses = []
        addr_0 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        addr_0_str = ":".join([hex(b)[2:] for b in addr_0])
        scan_responses.append({
            'rssi': -80,
            'packet_type': 0,
            'bd_addr': addr_0,
            'addr_type': 0x00,
            'bond': 0xFF,
            'data': [0x07, 0x09, ord('H'), ord('e'), ord('l'),
                     ord('l'), ord('o'), ord('!')]
        })
        self._stage_scan_packets(bled112, scan_responses=scan_responses)
        bled112.scan()
        devs = bled112.get_devices_discovered()
        assert(addr_0_str in devs)
        assert(devs[addr_0_str].name == 'Hello!')

    def test_BLED112_Backend_subscribe_and_wait_for_response(self):
        """subscribe/wait_for_response general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self._stage_connect_packets(
            bled112, address, ['connected', 'completed'])
        bled112.connect(bytearray(address))
        # Test subscribe
        handle0 = [0x12, 0x34]
        uuid0 = '01234567-0123-0123-0123-0123456789AB'
        uuid0_bytearray = unhexlify(uuid0.replace('-', ''))
        self._stage_subscribe_packets(bled112, uuid0_bytearray, handle0)
        bled112.subscribe(uuid0_bytearray)
        # Test wait for response
        value0 = [0xF0, 0x0D, 0xBE, 0xEF]
        packet_values = []
        packet_values.append(bytearray(value0))
        self._stage_wait_for_response_packets(
            bled112, handle0, packet_values)
        packet_values_received = bled112.wait_for_response(
            int(hexlify(bytearray(handle0)), 16), len(packet_values), 5)
        assert(packet_values_received == packet_values)

    def test_BLED112_Backend_delete_stored_bonds(self):
        """delete_stored_bonds general functionality."""
        bled112 = BLED112Backend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self._stage_run_packets(bled112)
        bled112.run()
        # Test delete stored bonds
        self._stage_delete_stored_bonds_packets(
            bled112, [0x00, 0x01, 0x02, 0x03, 0x04])
        bled112.delete_stored_bonds()
