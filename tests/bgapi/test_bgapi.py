from __future__ import print_function

from nose.tools import eq_, assert_in
import unittest
import threading
import time

from bluetooth_adapter.backends import BGAPIBackend
from bluetooth_adapter.backends.bgapi.constants import ConnectionStatusFlag
from bluetooth_adapter import gatt

from .mocker import MockBGAPISerialDevice


class BGAPIBackendTests(unittest.TestCase):
    """
    Test the functionality of the BGAPIBackend class.
    """
    def setUp(self):
        self.mock_device = MockBGAPISerialDevice()
        self.backend = BGAPIBackend(
            serial_port=self.mock_device.serial_port_name)

        self.address = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        self.address_string = ":".join("%02x" % b for b in self.address)

    def tearDown(self):
        self.mock_device.stop()
        self.backend.stop()

    def _connect(self):
        self.mock_device.stage_connect_packets(
            # TODO: update to use enum not just enum name
            self.address, [ConnectionStatusFlag.connected.name,
                           ConnectionStatusFlag.completed.name])
        self.backend.connect(bytearray(self.address))

    def test_start_backend(self):
        """start general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()

    def test_connect(self):
        """connect general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()

    def test_disconnect_when_connected(self):
        """disconnect general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()
        # test disconnect (connected, not fail)
        self.mock_device.stage_disconnect_packets(True, False)
        self.backend.disconnect()

    def test_attribute_read(self):
        """read general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()

        char = gatt.GattCharacteristic(
            0x02, custom_128_bit_uuid=gatt.Uuid(
                '01234567-0123-0123-0123-0123456789AB'))

        # Test attribute_read
        expected_value = [0xBE, 0xEF, 0x15, 0xF0, 0x0D]
        self.mock_device.stage_attribute_read_packets(
            char.handle, 0x00, expected_value)
        value = self.backend.attribute_read(char)
        eq_(value, bytearray(expected_value))

    def test_attribute_write(self):
        """attribute_write general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()

        char = gatt.GattCharacteristic(
            0x02, custom_128_bit_uuid=gatt.Uuid(
                '01234567-0123-0123-0123-0123456789AB'))

        # Test attribute_write
        value = [0xF0, 0x0F, 0x00]
        self.mock_device.stage_attribute_write_packets(char.handle, value)
        self.backend.attribute_write(char, bytearray(value))

    @unittest.skip("FIXME")
    def test_encrypt(self):
        """encrypt general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()
        # Test encrypt
        self.mock_device.stage_encrypt_packets(
            self.address, ['connected', 'encrypted'])
        self.backend.encrypt()

    @unittest.skip("FIXME")
    def test_bond(self):
        """bond general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()
        self.mock_device.stage_bond_packets(
            self.address, ['connected', 'encrypted', 'parameters_change'])
        self.backend.bond()

    @unittest.skip("FIXME")
    def test_get_rssi(self):
        """get_rssi general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()
        # Test get_rssi
        self.mock_device.stage_get_rssi_packets()
        assert(self.backend.get_rssi() == -80)

    def test_discover_attributes(self):
        """discover_attributes general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()

        services = []
        serv = gatt.GattService(0x01, gatt.GattAttributeType.primary_service)
        char = gatt.GattCharacteristic(
            0x02, custom_128_bit_uuid=gatt.Uuid(
                '01234567-0123-0123-0123-0123456789AB'))
        desc = gatt.GattDescriptor(0x03, gatt.GattCharacteristicDescriptor.
                                   client_characteristic_configuration)
        char.descriptors.append(desc)
        serv.characteristics.append(char)
        services.append(serv)

        self.mock_device.stage_discover_attributes_packets(services)
        discovered_services = self.backend.discover_attributes()
        eq_(len(services), len(discovered_services))
        # TODO: this can be condensed to one line if each object has a __cmp__
        #       method defined
        for i in range(len(services)):
            serv = services[i]
            serv_d = discovered_services[i]
            eq_(serv.handle, serv_d.handle)
            eq_(serv.service_type, serv_d.service_type)
            eq_(len(serv.characteristics),
                len(serv_d.characteristics))
            for j in range(len(serv.characteristics)):
                char = serv.characteristics[j]
                char_d = serv_d.characteristics[j]
                eq_(char.handle, char_d.handle)
                eq_(char.characteristic_type, char_d.characteristic_type)
                eq_(char.custom_128_bit_uuid, char_d.custom_128_bit_uuid)
                eq_(len(char.descriptors),
                    len(char_d.descriptors))
                for k in range(len(char.descriptors)):
                    desc = char.descriptors[k]
                    desc_d = char.descriptors[k]
                    eq_(desc.handle, desc_d.handle)
                    eq_(desc.descriptor_type, desc_d.descriptor_type)

    def test_scan(self):
        """scan general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        # Test scan
        scan_responses = []
        addr_0 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB]
        addr_0_str = ':'.join('%02x' % b for b in addr_0)
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
        devs = self.backend.scan()
        assert_in(addr_0_str, devs)
        eq_('Hello!', devs[addr_0_str].name)
        eq_(-80, devs[addr_0_str].rssi)

    def test_subscribe_with_notify(self):
        """subscribe with notify general functionality."""

        class NotificationHandler(object):
            def __init__(self, expected_value_bytearray):
                self.expected_value_bytearray = expected_value_bytearray
                self.received_value_bytearray = None
                self.called = threading.Event()

            def handle(self, received_value_bytearray):
                self.received_value_bytearray = received_value_bytearray
                self.called.set()

        self.mock_device.stage_start_packets()
        self.backend.start()
        self._connect()
        # Test subscribe with notifications
        packet_values = [bytearray([0xF0, 0x0D, 0xBE, 0xEF])]
        my_handler = NotificationHandler(packet_values[0])
        char = gatt.GattCharacteristic(
            0x02, custom_128_bit_uuid=gatt.Uuid(
                '01234567-0123-0123-0123-0123456789AB'))
        desc = gatt.GattDescriptor(0x03, gatt.GattCharacteristicDescriptor.
                                   client_characteristic_configuration)
        char.descriptors.append(desc)
        self.mock_device.stage_attribute_write_packets(
            desc.handle, [0x01, 0x00])
        self.backend.subscribe(char, callback=my_handler.handle)

        start_time = time.time()
        self.mock_device.stage_notification_packets(char.handle, packet_values)
        while not my_handler.called.is_set():
            elapsed_time = start_time - time.time()
            if elapsed_time >= 5:
                raise Exception("Callback wasn't called after {0} seconds."
                                .format(elapsed_time))
        print([b for b in my_handler.expected_value_bytearray])
        print([b for b in my_handler.received_value_bytearray])
        assert(my_handler.expected_value_bytearray ==
               my_handler.received_value_bytearray)

    @unittest.skip("FIXME")
    def test_clear_all_bonds(self):
        """clear_all_bonds general functionality."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        # Test delete stored bonds
        self.mock_device.stage_delete_stored_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04])
        self.backend.delete_stored_bonds()

    @unittest.skip("FIXME")
    def test_delete_stored_bonds_disconnect(self):
        """delete_stored_bonds shouldn't abort if disconnected."""
        self.mock_device.stage_start_packets()
        self.backend.start()
        # Test delete stored bonds
        self.mock_device.stage_delete_stored_bonds_packets(
            [0x00, 0x01, 0x02, 0x03, 0x04], disconnects=True)
        self.backend.delete_stored_bonds()
