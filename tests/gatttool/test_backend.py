from __future__ import print_function

from mock import patch, MagicMock

import pexpect
import time
import unittest

from pygatt.backends import GATTToolBackend


class GATTToolBackendTests(unittest.TestCase):
    def setUp(self):
        self.patchers = []
        self.patchers.append(
            patch('pygatt.backends.gatttool.gatttool.pexpect.spawn'))
        self.spawn = self.patchers[0].start()
        self.spawn.return_value.isalive.return_value = False
        self.spawn.return_value.read_nonblocking.side_effect = (
            pexpect.EOF(value=None))
        self.patchers.append(
            patch('pygatt.backends.gatttool.gatttool.subprocess'))
        self.patchers[1].start()

        # Just keep saying we got the "Connected" response
        def rate_limited_expect(*args, **kwargs):
            # Sleep a little bit to stop the receive thread from spinning and
            # eating 100% CPU during the tests
            time.sleep(0.001)
            # This is hacky, but we sort the event list in the GATTTool receiver
            # and hard code where we expect the "Connected" event to be.
            return 4

        self.spawn.return_value.expect.side_effect = rate_limited_expect

        self.backend = GATTToolBackend()
        self.backend.start()

    def tearDown(self):
        self.backend.stop()
        for patcher in self.patchers:
            patcher.stop()

    def test_scan(self):
        # TODO mock a successful scan
        devices = self.backend.scan()
        assert devices is not None
        assert 0 == len(devices)

    def test_connect(self):
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        assert device is not None

    def test_disconnect_callback(self):
        # Just keep saying we got the "Disconnected" response
        def rate_limited_expect_d(*args, **kwargs):
                time.sleep(0.001)
                # hard code the "Disconnected" event
                return 1

        mock_callback = MagicMock()
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.register_disconnect_callback(mock_callback)
        assert (mock_callback in device._backend._receiver._event_vector[
            "disconnected"]["callback"])

        self.spawn.return_value.expect.side_effect = rate_limited_expect_d
        time.sleep(0.1)
        assert mock_callback.called

        device.remove_disconnect_callback(mock_callback)
        assert (mock_callback not in device._backend._receiver._event_vector[
            "disconnected"]["callback"])
        assert (len(device._backend._receiver._event_vector[
            "disconnected"]["callback"]) > 0)

    def test_auto_reconnect_call(self):
        # Just keep saying we got the "Disconnected" response
        def rate_limited_expect_d(*args, **kwargs):
            time.sleep(0.001)
            # hard code the "Disconnected" event
            return 1

        address = "11:22:33:44:55:66"
        device = self.backend.connect(address, auto_reconnect=True)
        device._backend.reconnect = MagicMock()
        self.spawn.return_value.expect.side_effect = rate_limited_expect_d
        time.sleep(0.1)
        assert device._backend.reconnect.called

    def test_no_reconnect_default(self):
        # Just keep saying we got the "Disconnected" response
        def rate_limited_expect_d(*args, **kwargs):
            time.sleep(0.001)
            # hard code the "Disconnected" event
            return 1

        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device._backend.reconnect = MagicMock()
        self.spawn.return_value.expect.side_effect = rate_limited_expect_d
        time.sleep(0.1)
        assert not device._backend.reconnect.called

    def test_no_reconnect_disconnect(self):
        # Just keep saying we got the "Disconnected" response
        def rate_limited_expect_d(*args, **kwargs):
            time.sleep(0.001)
            # hard code the "Disconnected" event
            return 1

        address = "11:22:33:44:55:66"
        device = self.backend.connect(address, auto_reconnect=True)
        device._backend.reconnect = MagicMock()
        device.disconnect()
        self.spawn.return_value.expect.side_effect = rate_limited_expect_d
        time.sleep(0.1)
        assert not device._backend.reconnect.called

    def test_auto_reconnect(self):
        # Just keep saying we got the "Disconnected" response
        def rate_limited_expect_d(*args, **kwargs):
            time.sleep(0.001)
            # hard code the "Disconnected" event
            return 1

        # Just keep saying we got the "Connected" response
        def rate_limited_expect_c(*args, **kwargs):
            time.sleep(0.001)
            # hard code the "Connected" event
            return 4

        address = "11:22:33:44:55:66"
        device = self.backend.connect(address, auto_reconnect=True)
        self.spawn.return_value.expect.side_effect = rate_limited_expect_d
        time.sleep(0.1)
        device.resubscribe_all = MagicMock()
        self.spawn.return_value.expect.side_effect = rate_limited_expect_c
        time.sleep(0.1)
        assert device.resubscribe_all.called

    def test_single_byte_notification(self):
        event = {
            'after': "Notification handle = 0x0024 value: 64".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        assert device.receive_notification.called
        assert 0x24 == device.receive_notification.call_args[0][0]
        assert bytearray([0x64]) == device.receive_notification.call_args[0][1]

    def test_multi_byte_notification(self):
        event = {
            'after': (
                "Notification handle = 0x0024 value: 64 46 72".encode("utf8"))
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        assert device.receive_notification.called
        assert 0x24 == device.receive_notification.call_args[0][0]
        assert bytearray([0x64, 0x46, 0x72]) == \
            device.receive_notification.call_args[0][1]

    def test_empty_notification(self):
        event = {
            'after': "Notification handle = 0x0024 value: ".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        assert device.receive_notification.called

    def test_malformed_notification(self):
        event = {
            'after': "Notification handle = 0x0024vlue: ".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        assert not device.receive_notification.called

    def test_indication(self):
        event = {
            'after': "Indication   handle = 0x0024 value: 64".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        assert device.receive_notification.called
        assert 0x24 == device.receive_notification.call_args[0][0]
        assert bytearray([0x64]) == device.receive_notification.call_args[0][1]
