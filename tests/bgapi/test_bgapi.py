from __future__ import print_function

from nose.tools import eq_, assert_in
import unittest
import threading
import time

from pygatt.backends import BGAPIBackend

from .mocker import MockBGAPISerialDevice
from .util import uuid_to_bytearray


class BGAPIBackendTests(unittest.TestCase):
    """
    Test the functionality of the BGAPIBackend class.
    """
    def setUp(self):
        self.mock_device = MockBGAPISerialDevice()
        self.backend = BGAPIBackend(
            serial_port=self.mock_device.serial_port_name, run=False)

        self.address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.address_string = ":".join("%02x" % b for b in self.address)

    def tearDown(self):
        self.mock_device.stop()
        # TODO if we call stop without staging another disconnect packet, the
        # bglib explodes because of a packet == None and you get a runaway
        # process. what we can do about that?
        self.mock_device.stage_disconnect_packets(True, False)
        self.backend.stop()

    def _connect(self):
        self.mock_device.stage_connect_packets(
            self.address, ['connected', 'completed'])
        self.backend.connect(self.address_string)

    def test_run_backend(self):
        self.mock_device.stage_run_packets()
        self.backend.run()

    def test_connect(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()

    def test_disconnect_when_connected(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        # test disconnect (connected, not fail)
        self.mock_device.stage_disconnect_packets(True, False)
        self.backend.disconnect()

    def test_char_read(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_get_handle_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char))
        # Test char_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.mock_device.stage_char_read_packets(
            handle, 0x00, expected_value)
        value = self.backend._char_read(handle)
        assert(value == bytearray(expected_value))

    def test_char_write(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_get_handle_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char))
        # Test char_write
        value = [0xF0, 0x0F, 0x00]
        self.mock_device.stage_char_write_packets(handle, value)
        self.backend.char_write(handle, bytearray(value))

    def test_encrypt(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        # Test encrypt
        self.mock_device.stage_encrypt_packets(
            self.address, ['connected', 'encrypted'])
        self.backend.encrypt()

    def test_bond(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        self.mock_device.stage_bond_packets(
            self.address, ['connected', 'encrypted', 'parameters_change'])
        self.backend.bond()

    def test_get_rssi(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        # Test get_rssi
        self.mock_device.stage_get_rssi_packets()
        assert(self.backend.get_rssi() == -80)

    def test_get_handle(self):
        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        # Test get_handle
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_get_handle_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char))
        assert(handle == handle_char)
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char),
                                         uuid_to_bytearray(uuid_desc))
        assert(handle == handle_desc)

    def test_scan_and_get_devices_discovered(self):
        self.mock_device.stage_run_packets()
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
        self.mock_device.stage_scan_packets(scan_responses=scan_responses)
        self.backend.scan()
        devs = self.backend.get_devices_discovered()
        assert_in(addr_0_str, devs)
        eq_('Hello!', devs[addr_0_str].name)
        eq_(-80, devs[addr_0_str].rssi)

    def stage_subscribe_packets(self, uuid_char, handle_char,
                                indications=False, connection_handle=0x00):
        # TODO this is a candidate to move to the BGAPIBackendSpy, but why does
        # it need to call get_handle on the backend? otherwise it would just
        # generate its own fake ouput for the serial device.

        # Stage get_handle packets
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_get_handle_packets([
            uuid_char, handle_char, uuid_desc, handle_desc])
        handle = self.backend.get_handle(uuid_to_bytearray(uuid_char),
                                         uuid_to_bytearray(uuid_desc))
        # Stage char_write packets
        if indications:
            value = [0x02, 0x00]
        else:
            value = [0x01, 0x00]
        self.mock_device.stage_char_write_packets(
            handle, value, connection_handle=connection_handle)

    def test_subscribe_with_notify(self):
        class NotificationHandler(object):
            def __init__(self, expected_value_bytearray):
                self.expected_value_bytearray = expected_value_bytearray
                self.received_value_bytearray = None
                self.called = threading.Event()

            def handle(self, received_value_bytearray):
                self.received_value_bytearray = received_value_bytearray
                self.called.set()

        self.mock_device.stage_run_packets()
        self.backend.run()
        self._connect()
        # Test subscribe with indications
        packet_values = [bytearray([0xF0, 0x0D, 0xBE, 0xEF])]
        my_handler = NotificationHandler(packet_values[0])
        handle = 0x1234
        uuid = '01234567-0123-0123-0123-0123456789AB'
        self.stage_subscribe_packets(uuid, handle)
        self.backend.subscribe(uuid, callback=my_handler.handle, indicate=True)
        start_time = time.time()
        self.mock_device.stage_indication_packets(handle, packet_values)
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
        self.mock_device.stage_run_packets()
        self.backend.run()
        # Test delete stored bonds
        self.mock_device.stage_delete_stored_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04])
        self.backend.delete_stored_bonds()

    def test_delete_stored_bonds_disconnect(self):
        """delete_stored_bonds shouldn't abort if disconnected."""
        self.mock_device.stage_run_packets()
        self.backend.run()
        # Test delete stored bonds
        self.mock_device.stage_delete_stored_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04], disconnects=True)
        self.backend.delete_stored_bonds()
