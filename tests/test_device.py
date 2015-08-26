from nose.tools import ok_, eq_
from mock import Mock, patch
import unittest

from bluetooth_adapter import BleDevice
from bluetooth_adapter import gatt


class BleDeviceTest(unittest.TestCase):

    mock_backend = Mock()

    def make_patch(self, *args, **kwargs):
        p = patch(*args, **kwargs)
        p.start()
        self.patchers.append(p)

    def setUp(self):
        self.patchers = []

    def tearDown(self):
        for p in self.patchers:
            p.stop()

    def test_init(self):
        ok_(BleDevice(self.mock_backend, '01:23:45:67:89:AB',
            name='Hello, World!', scan_response_rssi=-80))

    def test_get_name(self):
        expected_name = 'Hello, World!'
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB',
                        name=expected_name, scan_response_rssi=-80)
        name = dev.get_name()
        eq_(name, expected_name)

    def test_get_mac_address(self):
        expected_mac = '01:23:45:67:89:AB'
        dev = BleDevice(self.mock_backend, expected_mac, name='Foobar',
                        scan_response_rssi=-80)
        mac = dev.get_mac_address()
        eq_(mac, expected_mac)

    def test_get_rssi_from_scan_response(self):
        expected_rssi = -74
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=expected_rssi)
        rssi = dev.get_rssi(from_connection=False)
        eq_(rssi, expected_rssi)

    def test_get_rssi_from_connection(self):
        expected_rssi = -74
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()
        self.mock_backend.get_rssi.return_value = expected_rssi
        rssi = dev.get_rssi(from_connection=True)
        eq_(rssi, expected_rssi)

    def test_connect(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()
        ok_(self.mock_backend.connect.called)

    def test_disconnect(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()
        dev.disconnect()
        ok_(self.mock_backend.disconnect.called)

    def test_list_services(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()

        services = []
        serv = gatt.Service(0x01)
        char = gatt.Characteristic(
            0x02, uuid=gatt.Uuid('01234567-0123-0123-0123-0123456789AB'))
        desc = gatt.Descriptor(
            0x03, descriptor_type=gatt.DescriptorType
            .client_characteristic_configuration)
        char.descriptors.append(desc)
        serv.characteristics.append(char)
        services.append(serv)

        self.mock_backend.discover_attributes.return_value = services
        service_list = dev.list_services()
        eq_(service_list, services)

    def test_encrypt(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()
        dev.encrypt()
        ok_(self.mock_backend.encrypt.called)

    def test_bond(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()
        dev.bond()
        ok_(self.mock_backend.bond.called)

    def test_char_read(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()

        expected_value_bytearray = bytearray([0x00, 0x01, 0x02, 0x03, 0x04])
        char = gatt.Characteristic(
            0x02, uuid=gatt.Uuid('01234567-0123-0123-0123-0123456789AB'))
        self.mock_backend.attribute_read.return_value = expected_value_bytearray
        value = dev.char_read(char)
        eq_(value, expected_value_bytearray)

    def test_char_write(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()

        value = bytearray([0x00, 0x01, 0x02, 0x03, 0x04])
        char = gatt.Characteristic(
            0x02, uuid=gatt.Uuid('01234567-0123-0123-0123-0123456789AB'))
        dev.char_write(char, value)
        self.mock_backend.attribute_write.assert_called_once_with(char, value)

    def test_subscribe(self):
        dev = BleDevice(self.mock_backend, '01:23:45:67:89:AB', name='Foobar',
                        scan_response_rssi=-72)
        dev.connect()

        char = gatt.Characteristic(
            0x02, uuid=gatt.Uuid('01234567-0123-0123-0123-0123456789AB'))
        dev.subscribe(char, notifications=True, indications=False,
                      callback=None)
        self.mock_backend.subscribe.assert_called_once_with(
            char, notifications=True, indications=False, callback=None)
