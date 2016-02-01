import unittest
import uuid
from mock import MagicMock, patch
from nose.tools import ok_, eq_

from pygatt import BLEDevice
from pygatt.backends import Characteristic


class TestBLEDevice(BLEDevice):
    CHAR_UUID = uuid.uuid4()
    EXPECTED_HANDLE = 99

    def discover_characteristics(self):
        return {
            self.CHAR_UUID: Characteristic(self.CHAR_UUID, self.EXPECTED_HANDLE)
        }


class BLEDeviceTest(unittest.TestCase):
    def setUp(self):
        super(BLEDeviceTest, self).setUp()
        self.address = "11:22:33:44:55:66"
        self.backend = MagicMock()
        self.device = TestBLEDevice(self.address)

    def _subscribe(self):
        callback = MagicMock()
        with patch.object(self.device, 'char_write_handle') as char_write:
            self.device.subscribe(self.device.CHAR_UUID, callback=callback)
            ok_(char_write.called)
            eq_(self.device.EXPECTED_HANDLE + 1, char_write.call_args[0][0])
            eq_(bytearray([1, 0]), char_write.call_args[0][1])
        return callback

    def _unsubscribe(self):
        callback = MagicMock()
        with patch.object(self.device, 'char_write_handle') as char_write:
            self.device.unsubscribe(self.device.CHAR_UUID)
            eq_(self.device.EXPECTED_HANDLE + 1, char_write.call_args[0][0])
            eq_(bytearray([0, 0]), char_write.call_args[0][1])
        return callback

    def test_subscribe(self):
        self._subscribe()

    def test_unsubscribe(self):
        self._subscribe()
        self._unsubscribe()

    def test_subscribe_another_callback(self):
        self._subscribe()
        another_callback = MagicMock()
        with patch.object(self.device, 'char_write_handle') as char_write:
            self.device.subscribe(self.device.CHAR_UUID,
                                  callback=another_callback)
            ok_(not char_write.called)

    def test_receive_notification(self):
        callback = self._subscribe()
        value = bytearray([24])
        self.device.receive_notification(TestBLEDevice.EXPECTED_HANDLE, value)
        ok_(callback.called)
        eq_(TestBLEDevice.EXPECTED_HANDLE, callback.call_args[0][0])
        eq_(value, callback.call_args[0][1])

    def test_ignore_notification_for_another_handle(self):
        callback = self._subscribe()
        value = bytearray([24])
        self.device.receive_notification(
            TestBLEDevice.EXPECTED_HANDLE + 1, value)
        ok_(not callback.called)

    def test_unicode_get_handle(self):
        for chars in self.device.discover_characteristics().values():
            self.device.get_handle(unicode(chars.uuid))
