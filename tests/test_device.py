import unittest
import uuid
from mock import MagicMock, patch
from nose.tools import ok_, eq_, raises

from pygatt.classes import BLEDevice
from pygatt.exceptions import NotConnectedError
from pygatt.backends import Characteristic


class BLEDeviceTest(unittest.TestCase):
    def setUp(self):
        super(BLEDeviceTest, self).setUp()
        self.address = "11:22:33:44:55:66"
        self.handle = 42
        self.backend = MagicMock()
        self.device = BLEDevice(self.address, self.handle, self.backend)

        self.expected_handle = 99
        self.char_uuid = uuid.uuid4()
        self.backend.discover_characteristics.return_value = {
            self.char_uuid: Characteristic(self.char_uuid, self.expected_handle)
        }

    def test_bond(self):
        self.device.bond()
        ok_(self.backend.bond.called)
        eq_(self.handle, self.backend.bond.call_args[0][0])

    def test_get_rssi(self):
        self.backend.get_rssi.return_value = 49
        rssi = self.device.get_rssi()
        ok_(self.backend.get_rssi.called)
        eq_(self.handle, self.backend.get_rssi.call_args[0][0])
        eq_(49, rssi)

    def test_char_read(self):
        expected_value = bytearray(range(4))
        self.backend.char_read.return_value = expected_value
        with patch.object(self.device, 'get_handle', return_value=24
                          ) as get_handle:
            char_uuid = uuid.uuid4()
            value = self.device.char_read(char_uuid)
            ok_(get_handle.called)
            eq_(char_uuid, get_handle.call_args[0][0])
            ok_(self.backend.char_read.called)
            eq_(self.handle, self.backend.char_read.call_args[0][0])
            eq_(24, self.backend.char_read.call_args[0][1])
            eq_(expected_value, value)

    def test_char_write(self):
        with patch.object(self.device, 'get_handle', return_value=24
                          ) as get_handle:
            char_uuid = uuid.uuid4()
            value = bytearray(range(4))
            self.device.char_write(char_uuid, value)
            ok_(get_handle.called)
            eq_(char_uuid, get_handle.call_args[0][0])
            ok_(self.backend.char_write.called)
            eq_(self.handle, self.backend.char_write.call_args[0][0])
            eq_(24, self.backend.char_write.call_args[0][1])
            eq_(value, self.backend.char_write.call_args[0][2])

    def _subscribe(self):
        callback = MagicMock()
        with patch.object(self.device, 'char_write') as char_write:
            self.device.subscribe(self.char_uuid, callback=callback)
            ok_(char_write.called)
            eq_(self.expected_handle + 1, char_write.call_args[0][0])
            eq_(bytearray([1, 0]), char_write.call_args[0][1])
        return callback

    def test_subscribe(self):
        self._subscribe()

    def test_subscribe_another_callback(self):
        self._subscribe()
        another_callback = MagicMock()
        with patch.object(self.device, 'char_write') as char_write:
            self.device.subscribe(self.char_uuid, callback=another_callback)
            ok_(not char_write.called)

    def test_receive_notification(self):
        callback = self._subscribe()
        value = bytearray([24])
        self.device.receive_notification(self.expected_handle, value)
        ok_(callback.called)
        eq_(self.expected_handle, callback.call_args[0][0])
        eq_(value, callback.call_args[0][1])

    def test_ignore_notification_for_another_handle(self):
        callback = self._subscribe()
        value = bytearray([24])
        self.device.receive_notification(self.expected_handle + 1, value)
        ok_(not callback.called)

    def test_disconnect(self):
        self.device.disconnect()
        ok_(self.backend.disconnect.called)
        eq_(self.handle, self.backend.disconnect.call_args[0][0])

    @raises(NotConnectedError)
    def test_write_after_disconnect(self):
        self.device.disconnect()
        self.device.char_read(uuid.uuid4())

    def test_get_handle(self):
        handle = self.device.get_handle(self.char_uuid)
        ok_(self.backend.discover_characteristics.called)
        eq_(self.handle, self.backend.discover_characteristics.call_args[0][0])
        eq_(self.expected_handle, handle)

    def test_get_cached_handle(self):
        handle = self.device.get_handle(self.char_uuid)
        with patch.object(self.backend, 'discover_characteristics') as discover:
            next_handle = self.device.get_handle(self.char_uuid)
            eq_(handle, next_handle)
            ok_(not discover.called)
