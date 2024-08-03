import pytest
import unittest
import uuid
from mock import MagicMock, patch

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
        assert self.backend.bond.called
        assert self.device == self.backend.bond.call_args[0][0]

    def test_char_read(self):
        expected_value = bytearray(range(4))
        self.backend.char_read.return_value = expected_value
        with patch.object(self.backend, 'get_handle', return_value=24
                          ) as get_handle:
            char_uuid = uuid.uuid4()
            value = self.device.char_read(char_uuid)
            assert not get_handle.called
            assert self.backend.char_read.called
            assert self.device == self.backend.char_read.call_args[0][0]
            assert char_uuid == self.backend.char_read.call_args[0][1]
            assert expected_value == value

    def test_char_write(self):
        with patch.object(self.device, 'get_handle', return_value=24
                          ) as get_handle:
            char_uuid = uuid.uuid4()
            value = bytearray(range(4))
            self.device.char_write(char_uuid, value)
            assert get_handle.called
            assert char_uuid == get_handle.call_args[0][0]
            assert self.backend.char_write_handle.called
            assert self.device == self.backend.char_write_handle.call_args[0][0]
            assert 24 == self.backend.char_write_handle.call_args[0][1]
            assert value == self.backend.char_write_handle.call_args[0][2]

    def test_disconnect(self):
        self.device.disconnect()
        assert self.backend.disconnect.called
        assert self.device == self.backend.disconnect.call_args[0][0]

    def test_additional_disconnect_callback(self):
        mock_callback = MagicMock()
        self.device.register_disconnect_callback(mock_callback)
        self.backend._receiver.register_callback.assert_called_with(
            "disconnected", mock_callback)
        self.device.remove_disconnect_callback(mock_callback)
        self.backend._receiver.remove_callback.assert_called_with(
            "disconnected", mock_callback)

    def test_write_after_disconnect(self):
        with pytest.raises(NotConnectedError):
            self.device.disconnect()
            self.device.char_read(uuid.uuid4())

    def test_get_handle(self):
        handle = self.device.get_handle(self.char_uuid)
        assert self.backend.discover_characteristics.called
        assert (
            self.device == self.backend.discover_characteristics.call_args[0][0]
        )
        assert self.expected_handle == handle

    def test_get_cached_handle(self):
        handle = self.device.get_handle(self.char_uuid)
        with patch.object(self.backend, 'discover_characteristics') as discover:
            next_handle = self.device.get_handle(self.char_uuid)
            assert handle == next_handle
            assert not discover.called
