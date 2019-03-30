from __future__ import print_function

from nose.tools import eq_, ok_
from mock import patch, MagicMock
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
            return 3

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
        ok_(devices is not None)
        eq_(0, len(devices))

    def test_connect(self):
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        ok_(device is not None)

    def test_single_byte_notification(self):
        event = {
            'after': "Notification handle = 0x0024 value: 64".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        ok_(device.receive_notification.called)
        eq_(0x24, device.receive_notification.call_args[0][0])
        eq_(bytearray([0x64]), device.receive_notification.call_args[0][1])

    def test_multi_byte_notification(self):
        event = {
            'after': (
                "Notification handle = 0x0024 value: 64 46 72".encode("utf8"))
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        ok_(device.receive_notification.called)
        eq_(0x24, device.receive_notification.call_args[0][0])
        eq_(bytearray([0x64, 0x46, 0x72]),
            device.receive_notification.call_args[0][1])

    def test_empty_notification(self):
        event = {
            'after': "Notification handle = 0x0024 value: ".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        ok_(device.receive_notification.called)

    def test_malformed_notification(self):
        event = {
            'after': "Notification handle = 0x0024vlue: ".encode("utf8")
        }
        address = "11:22:33:44:55:66"
        device = self.backend.connect(address)
        device.receive_notification = MagicMock()
        device._backend._handle_notification_string(event)
        ok_(not device.receive_notification.called)
