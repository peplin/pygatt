from __future__ import print_function

from nose.tools import eq_, ok_
from nose import SkipTest
from mock import patch
import unittest

from pygatt.backends import GATTToolBackend


class GATTToolBackendTests(unittest.TestCase):
    def setUp(self):
        raise SkipTest()
        self.patchers = []
        self.patchers.append(
            patch('pygatt.backends.gatttool.gatttool.pexpect.spawn'))
        self.spawn = self.patchers[0].start()
        self.spawn.return_value.isalive.return_value = False
        self.patchers.append(
            patch('pygatt.backends.gatttool.gatttool.subprocess'))
        self.patchers[1].start()
        self.backend = GATTToolBackend()
        self.mock_expect = patch.object(self.backend, '_expect').start()
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
