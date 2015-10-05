import unittest
import uuid
from mock import MagicMock, patch
from nose.tools import ok_, eq_, raises

from pygatt.exceptions import NotConnectedError
from pygatt.backends import Characteristic
from pygatt.backends.gatttool.device import GATTToolBLEDevice


class GATTToolBLEDeviceTests(unittest.TestCase):
    def setUp(self):
        super(GATTToolBLEDeviceTests, self).setUp()
        self.address = "11:22:33:44:55:66"
        self.backend = MagicMock()
        self.device = GATTToolBLEDevice(self.address, self.backend)

        self.expected_handle = 99
        self.char_uuid = uuid.uuid4()
        self.backend.discover_characteristics.return_value = {
            self.char_uuid: Characteristic(self.char_uuid, self.expected_handle)
        }

    def test_bond(self):
        self.device.bond()
        ok_(self.backend.bond.called)
        eq_(self.device, self.backend.bond.call_args[0][0])

    def test_char_read(self):
        expected_value = bytearray(range(4))
        self.backend.char_read.return_value = expected_value
        with patch.object(self.backend, 'get_handle', return_value=24
                          ) as get_handle:
            char_uuid = uuid.uuid4()
            value = self.device.char_read(char_uuid)
            ok_(not get_handle.called)
            ok_(self.backend.char_read.called)
            eq_(self.device, self.backend.char_read.call_args[0][0])
            eq_(char_uuid, self.backend.char_read.call_args[0][1])
            eq_(expected_value, value)

    def test_char_write(self):
        with patch.object(self.device, 'get_handle', return_value=24
                          ) as get_handle:
            char_uuid = uuid.uuid4()
            value = bytearray(range(4))
            self.device.char_write(char_uuid, value)
            ok_(get_handle.called)
            eq_(char_uuid, get_handle.call_args[0][0])
            ok_(self.backend.char_write_handle.called)
            eq_(self.device, self.backend.char_write_handle.call_args[0][0])
            eq_(24, self.backend.char_write_handle.call_args[0][1])
            eq_(value, self.backend.char_write_handle.call_args[0][2])

    def test_disconnect(self):
        self.device.disconnect()
        ok_(self.backend.disconnect.called)
        eq_(self.device, self.backend.disconnect.call_args[0][0])

    @raises(NotConnectedError)
    def test_write_after_disconnect(self):
        self.device.disconnect()
        self.device.char_read(uuid.uuid4())

    def test_get_handle(self):
        handle = self.device.get_handle(self.char_uuid)
        ok_(self.backend.discover_characteristics.called)
        eq_(self.device, self.backend.discover_characteristics.call_args[0][0])
        eq_(self.expected_handle, handle)

    def test_get_cached_handle(self):
        handle = self.device.get_handle(self.char_uuid)
        with patch.object(self.backend, 'discover_characteristics') as discover:
            next_handle = self.device.get_handle(self.char_uuid)
            eq_(handle, next_handle)
            ok_(not discover.called)
