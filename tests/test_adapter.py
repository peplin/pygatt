from nose.tools import ok_
from mock import patch
import unittest

from bluetooth_adapter import BluetoothAdapter
from bluetooth_adapter.backends import BackendEnum


class BluetoothAdapterTest(unittest.TestCase):

    def patch(self, *args, **kwargs):
        p = patch(*args, **kwargs)
        p.start()
        self.patchers.append(p)

    def setUp(self):
        self.patchers = []
        self.patch('bluetooth_adapter.adapter.BGAPIBackend')

    def tearDown(self):
        for p in self.patchers:
            p.stop()

    def test_init(self):
        ok_(BluetoothAdapter(BackendEnum.bgapi))

    def test_enable_disable(self):
        adapter = BluetoothAdapter(BackendEnum.bgapi)
        adapter.enable()
        adapter.disable()
