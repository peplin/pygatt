from __future__ import print_function

from nose.tools import eq_, ok_
import mock
import unittest

import serial

from pygatt.backends import BGAPIBackend
from pygatt.backends.bgapi.bgapi import bgapi_address_to_hex
from pygatt.backends.bgapi.util import extract_vid_pid
from pygatt.backends.bgapi.error_codes import get_return_message
from pygatt.backends.bgapi import bglib
from pygatt.exceptions import NotConnectedError

from .mocker import MockBGAPISerialDevice


class BGAPIBackendTests(unittest.TestCase):
    def setUp(self):
        self.mock_device = MockBGAPISerialDevice()
        self.backend = BGAPIBackend(
            serial_port=self.mock_device.serial_port_name,
            receive_queue_timeout=0.001)

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
        return self.backend.connect(self.address_string)

    def test_connect(self):
        self._connect()

    def test_connect_already_connected(self):
        device = self._connect()
        another_device = self.backend.connect(self.address_string)
        eq_(device, another_device)

    def test_serial_port_connection_failure(self):
        self.mock_device.mocked_serial.read = mock.MagicMock()
        self.mock_device.mocked_serial.read.side_effect = (
            serial.serialutil.SerialException)
        with self.assertRaises(NotConnectedError):
            self.backend.start()

    def test_scan_and_get_devices_discovered(self):
        # Test scan
        scan_responses = []
        addr_0 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
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
        devs = self.backend.scan(timeout=.5)
        eq_('Hello!', devs[0]['name'])
        eq_(-80, devs[0]['rssi'])

    def test_clear_bonds(self):
        # Test delete stored bonds
        self.mock_device.stage_clear_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04])
        self.backend.clear_bond()

    def test_clear_bonds_disconnect(self):
        """clear_bonds shouldn't abort if disconnected."""
        # Test delete stored bonds
        self.mock_device.stage_clear_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04], disconnects=True)
        self.backend.clear_bond()


class UsbInfoStringParsingTests(unittest.TestCase):

    def test_weird_platform(self):
        vid, pid = extract_vid_pid("USB VID_2458 PID_0001")
        eq_(0x2458, vid)
        eq_(1, pid)

    def test_linux(self):
        vid, pid = extract_vid_pid("USB VID:PID=2458:0001 SNR=1")
        eq_(0x2458, vid)
        eq_(1, pid)

    def test_mac(self):
        vid, pid = extract_vid_pid("USB VID:PID=2458:1 SNR=1")
        eq_(0x2458, vid)
        eq_(1, pid)

    def test_invalid(self):
        eq_(None, extract_vid_pid("2458:1"))


class ReturnCodeTests(unittest.TestCase):

    def test_unrecognized_return_code(self):
        ok_(get_return_message(123123123123123) is not None)


class BGAPIAddressToHexTests(unittest.TestCase):

    def test_convert(self):
        bgapi_address = bytearray([21, 19, 11, 210, 2, 97])
        eq_("61:02:D2:0B:13:15", bgapi_address_to_hex(bgapi_address))


class DecodePacketTests(unittest.TestCase):

    def setUp(self):
        self.lib = bglib.BGLib()

    def test_decode_scan_packet(self):
        data = [128, 34, 6, 0, 166, 0, 21, 19, 11, 210, 2, 97, 1, 255, 23, 2, 1,
                6, 19, 255, 76, 0, 12, 14, 0, 100, 39, 38, 61, 167, 226, 128,
                135, 0, 76, 200, 60, 78]

        packet_type, packet = self.lib.decode_packet(data)
        eq_(bglib.EventPacketType.gap_scan_response, packet_type)
        eq_(bytearray([21, 19, 11, 210, 2, 97]), packet['sender'])
