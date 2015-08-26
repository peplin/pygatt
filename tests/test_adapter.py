from nose.tools import ok_, eq_
from mock import Mock, patch
import unittest

from bluetooth_adapter import BluetoothAdapter
from bluetooth_adapter.backends import BackendEnum


class BluetoothAdapterTest(unittest.TestCase):

    EXAMPLE_BONDS = [0x00, 0x01, 0x02, 0x03, 0x04]
    EXAMPLE_SCAN_DICT = {
        '01:23:45:67:89:AB': {
            'name': 'Device_1',
            'address': '01:23:45:67:89:AB',
            'rssi': -65,
        },
        'BE:EF:15:F0:0D:11': {
            'name': 'Device_2',
            'address': 'BE:EF:15:F0:0D:11',
            'rssi': -75,
        },
        'FF:FF:FF:FF:FF:FF': {
            'name': 'Device_3',
            'address': 'FF:FF:FF:FF:FF:FF',
            'rssi': -100,
        },
    }

    mock_bgapi_backend = Mock()

    def make_patch(self, *args, **kwargs):
        p = patch(*args, **kwargs)
        p.start()
        self.patchers.append(p)

    def setUp(self):
        self.patchers = []
        self.make_patch('bluetooth_adapter.adapter.BGAPIBackend',
                        return_value=self.mock_bgapi_backend)

    def tearDown(self):
        for p in self.patchers:
            p.stop()

    def test_init(self):
        ok_(BluetoothAdapter(BackendEnum.bgapi))

    def test_enable_disable(self):
        adapter = BluetoothAdapter(BackendEnum.bgapi)
        adapter.enable()
        adapter.disable()

    def test_list_bonds(self):
        self.mock_bgapi_backend.list_bonds.return_value = self.EXAMPLE_BONDS
        adapter = BluetoothAdapter(BackendEnum.bgapi)
        adapter.enable()
        bonds = adapter.list_bonds()
        eq_(bonds, self.EXAMPLE_BONDS)
        adapter.disable()

    def test_clear_bond(self):
        self.mock_bgapi_backend.clear_bond.return_value = Mock()
        adapter = BluetoothAdapter(BackendEnum.bgapi)
        adapter.enable()
        bond = 0xEF
        adapter.clear_bond(bond)
        self.mock_bgapi_backend.clear_bond.assert_called_once_with(bond)
        adapter.disable()

    def test_clear_all_bonds(self):
        self.mock_bgapi_backend.clear_all_bonds.return_value = Mock()
        adapter = BluetoothAdapter(BackendEnum.bgapi)
        adapter.enable()
        adapter.clear_all_bonds()
        ok_(self.mock_bgapi_backend.clear_all_bonds.called)
        adapter.disable()

    def test_scan(self):
        self.mock_bgapi_backend.scan.return_value = self.EXAMPLE_SCAN_DICT
        adapter = BluetoothAdapter(BackendEnum.bgapi)
        adapter.enable()
        devices = adapter.scan()
        for d in devices:
            address = d.get_mac_address()
            ok_(address in self.EXAMPLE_SCAN_DICT)
            dev_dict = self.EXAMPLE_SCAN_DICT[address]
            eq_(d.get_name(), dev_dict['name'])
            eq_(d.get_rssi(from_connection=False), dev_dict['rssi'])
        adapter.disable()
