import unittest
import uuid
from mock import MagicMock, patch

from pygatt import BLEDevice
from pygatt.backends import Characteristic


class MockBLEDevice(BLEDevice):
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
        self.device = MockBLEDevice(self.address)

    def _subscribe(self):
        callback = MagicMock()
        with patch.object(self.device, 'char_write_handle') as char_write:
            self.device.subscribe(self.device.CHAR_UUID, callback=callback)
            assert char_write.called
            assert self.device.EXPECTED_HANDLE + 1 == char_write.call_args[0][0]
            assert bytearray([1, 0]) == char_write.call_args[0][1]
        return callback

    def _unsubscribe(self):
        callback = MagicMock()
        with patch.object(self.device, 'char_write_handle') as char_write:
            self.device.unsubscribe(self.device.CHAR_UUID)
            assert self.device.EXPECTED_HANDLE + 1 == char_write.call_args[0][0]
            assert bytearray([0, 0]) == char_write.call_args[0][1]
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
            assert not char_write.called

    def test_receive_notification(self):
        callback = self._subscribe()
        value = bytearray([24])
        self.device.receive_notification(MockBLEDevice.EXPECTED_HANDLE, value)
        assert callback.called
        assert MockBLEDevice.EXPECTED_HANDLE == callback.call_args[0][0]
        assert value == callback.call_args[0][1]

    def test_ignore_notification_for_another_handle(self):
        callback = self._subscribe()
        value = bytearray([24])
        self.device.receive_notification(
            MockBLEDevice.EXPECTED_HANDLE + 1, value)
        assert not callback.called

    def test_unicode_get_handle(self):
        try:
            string_type = unicode
        except NameError:
            string_type = str

        for chars in self.device.discover_characteristics().values():
            self.device.get_handle(string_type(chars.uuid))
