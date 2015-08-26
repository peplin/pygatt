from nose.tools import ok_, eq_
from mock import Mock, patch
import unittest

from bluetooth_adapter import BluetoothAdapter
from bluetooth_adapter.backends import BackendEnum


class BluetoothAdapterTest(unittest.TestCase):

    EXAMPLE_BONDS = [0x00, 0x01, 0x02, 0x03, 0x04]
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
