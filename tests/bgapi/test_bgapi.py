from __future__ import print_function

from mock import patch
from nose.tools import eq_, assert_in
import platform
import unittest
import threading
import time

from pygatt.backends import BGAPIBackend

from tests.serial_mock import SerialMock
from .spy import BGAPIBackendSpy
from .util import uuid_to_bytearray


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

        self.backend = BGAPIBackend(
            serial_port='dummy', logfile=self.null_file, run=False)
        self.spy = BGAPIBackendSpy(self.backend)

    def tearDown(self):
        self.backend.stop()

        for patcher in self.patchers:
            try:
                patcher.stop()
            except RuntimeError:
                pass

    def test_run_backend(self):
        """run general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()

    def test_connect(self):
        """connect general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        # Test connect
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))

    def test_disconnect_when_connected(self):
        """disconnect general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # test disconnect (connected, not fail)
        self.spy.stage_disconnect_packets(True, False)
        self.backend.disconnect()

    def test_char_read(self):
        """read general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.spy.stage_get_handle_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char))
        # Test char_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.spy.stage_char_read_packets(
            handle, 0x00, expected_value)
        value = self.backend.char_read(handle)
        assert(value == bytearray(expected_value))

    def test_char_write(self):
        """char_write general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.spy.stage_get_handle_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char))
        # Test char_write
        value = [0xF0, 0x0F, 0x00]
        self.spy.stage_char_write_packets(handle, value)
        self.backend.char_write(handle, bytearray(value))

    def test_encrypt(self):
        """encrypt general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test encrypt
        self.spy.stage_encrypt_packets(
            address, ['connected', 'encrypted'])
        self.backend.encrypt()

    def test_bond(self):
        """bond general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        self.spy.stage_bond_packets(address,
                                    ['connected', 'encrypted',
                                     'parameters_change'])
        self.backend.bond()

    def test_get_rssi(self):
        """get_rssi general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test get_rssi
        self.spy.stage_get_rssi_packets()
        assert(self.backend.get_rssi() == -80)

    def test_get_handle(self):
        """get_handle general functionality."""
        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(
            address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test get_handle
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.spy.stage_get_handle_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char))
        assert(handle == handle_char)
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char),
                                         uuid_to_bytearray(uuid_desc))
        assert(handle == handle_desc)

    def test_scan_and_get_devices_discovered(self):
        """scan/get_devices_discovered general functionality."""
        self.spy.stage_run_packets()
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
        self.spy.stage_scan_packets(scan_responses=scan_responses)
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

        self.spy.stage_run_packets()
        self.backend.run()
        address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.spy.stage_connect_packets(address, ['connected', 'completed'])
        self.backend.connect(bytearray(address))
        # Test subscribe with indications
        packet_values = [bytearray([0xF0, 0x0D, 0xBE, 0xEF])]
        my_handler = NotificationHandler(packet_values[0])
        handle = 0x1234
        uuid = '01234567-0123-0123-0123-0123456789AB'
        self.spy.stage_subscribe_packets(uuid, handle)
        self.backend.subscribe(uuid_to_bytearray(uuid),
                               callback=my_handler.handle, indicate=True)
        start_time = time.time()
        self.spy.stage_indication_packets(handle, packet_values)
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
        self.spy.stage_run_packets()
        self.backend.run()
        # Test delete stored bonds
        self.spy.stage_delete_stored_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04])
        self.backend.delete_stored_bonds()

    def test_delete_stored_bonds_disconnect(self):
        """delete_stored_bonds shouldn't abort if disconnected."""
        self.spy.stage_run_packets()
        self.backend.run()
        # Test delete stored bonds
        self.spy.stage_delete_stored_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04], disconnects=True)
        self.backend.delete_stored_bonds()
