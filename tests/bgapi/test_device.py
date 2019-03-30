from __future__ import print_function

from nose.tools import eq_, raises
import mock
import unittest
from uuid import UUID

from pygatt.util import uuid16_to_uuid
from pygatt.backends import BGAPIBackend
from pygatt.backends.bgapi.exceptions import ExpectedResponseTimeout

from .mocker import MockBGAPISerialDevice


class BGAPIDeviceTests(unittest.TestCase):
    def setUp(self):
        self.mock_device = MockBGAPISerialDevice()
        self.backend = BGAPIBackend(
            serial_port=self.mock_device.serial_port_name)

        self.address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.address_string = ":".join("%02x" % b for b in self.address)

        self.mock_device.stage_run_packets()

        self.time_patcher = mock.patch('pygatt.backends.bgapi.bgapi.time')
        self.time_patcher.start()

        self.timeout_patcher = mock.patch(
            'pygatt.backends.bgapi.bgapi._timed_out')
        timed_out = self.timeout_patcher.start()
        timed_out.return_value = True

        self.backend.start()

    def tearDown(self):
        self.time_patcher.stop()
        self.timeout_patcher.stop()
        self.mock_device.stop()
        # TODO if we call stop without staging another disconnect packet, the
        # bglib explodes because of a packet == None and you get a runaway
        # process. what we can do about that?
        self.mock_device.stage_disconnect_packets(True, False)
        self.backend.stop()

    def _connect(self):
        self.mock_device.stage_connect_packets(
            self.address, ['connected', 'completed'])
        device = self.backend.connect(self.address_string)
        self.assertNotEqual(None, device)
        return device

    def test_disconnect_when_connected(self):
        device = self._connect()
        # test disconnect (connected, not fail)
        self.mock_device.stage_disconnect_packets(True, False)
        device.disconnect()

    def test_char_read(self):
        device = self._connect()
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_discover_characteristics_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        # Test char_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.mock_device.stage_char_read_packets(
            handle_char, 0x00, expected_value)
        value = device.char_read(UUID(uuid_char))
        eq_(bytearray(expected_value), value)

        # Test ignore of packet with wrong handle
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.mock_device.stage_char_read_packets(
            0, 0x00, expected_value)
        self.mock_device.stage_char_read_packets(
            handle_char, 0x00, expected_value)
        value = device.char_read(UUID(uuid_char))
        eq_(bytearray(expected_value), value)

    def test_read_nonstandard_4byte_char(self):
        device = self._connect()
        uuid_char = 0x03ea
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_discover_characteristics_packets([
            "03ea", handle_char,
            uuid_desc, handle_desc])

        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.mock_device.stage_char_read_packets(
            handle_char, 0x00, expected_value)
        value = device.char_read(UUID(str(uuid16_to_uuid(uuid_char))))
        eq_(bytearray(expected_value), value)

    @raises(ExpectedResponseTimeout)
    def test_read_timeout_wrong_handle(self):
        device = self._connect()
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_discover_characteristics_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        # Test char_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.mock_device.stage_char_read_packets(
            0, 0x00, expected_value)
        device.char_read(UUID(uuid_char))

    def test_char_write(self):
        device = self._connect()
        uuid_char = '01234567-0123-0123-0123-0123456789AB'
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.mock_device.stage_discover_characteristics_packets([
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        # Test char_write request
        value = [0xF0, 0x0F, 0x00]
        self.mock_device.stage_char_write_packets(0, value)
        device.char_write(UUID(uuid_char), bytearray(value), True)

        # Test char_write command
        value = [0xF0, 0x0F, 0x00]
        self.mock_device.stage_char_write_command_packets(0, value)
        device.char_write(UUID(uuid_char), bytearray(value), False)

    def test_bond(self):
        device = self._connect()
        self.mock_device.stage_bond_packets(
            self.address, ['connected', 'encrypted', 'parameters_change'])
        device.bond()

    def test_get_rssi(self):
        device = self._connect()
        # Test get_rssi
        self.mock_device.stage_get_rssi_packets()
        eq_(-80, device.get_rssi())

    def test_discover_characteristics(self):
        device = self._connect()

        uuid_char = UUID('01234567-0123-0123-0123-0123456789AB')
        handle_char = 0x1234
        uuid_desc = '2902'
        handle_desc = 0x5678

        self.mock_device.stage_discover_characteristics_packets([
            str(uuid_char), handle_char,
            uuid_desc, handle_desc])
        characteristics = device.discover_characteristics()
        eq_(characteristics[uuid_char].handle, handle_char)
        eq_(characteristics[uuid_char].descriptors[uuid16_to_uuid(0x2902)],
            handle_desc)
