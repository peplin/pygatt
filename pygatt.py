#!/usr/bin/env python
from __future__ import print_function
import pexpect
import sys
import threading


class BluetoothLeDevice(object):
    connection_lock = threading.Lock()

    def __init__(self, bluetooth_adr):
        print("Preparing to connect.")
        lescan = pexpect.spawn('sudo hcitool lescan')
        lescan.expect(bluetooth_adr.upper(), timeout=5)
        self.con = pexpect.spawn('gatttool -b ' + bluetooth_adr + ' --interactive')
        self.con.expect('\[LE\]>', timeout=1)
        self.con.sendline('connect')
        # test for success of connect
        self.con.expect('Connection successful.*\[LE\]>')
        print("Connected to %s." % bluetooth_adr)

    def char_write_cmd(self, handle, value):
        with self.connection_lock:
            # The 0%x for value is VERY naughty!  Fix this!
            cmd = 'char-write-cmd 0x%02x 0%x' % (handle, value)
            print(cmd)
            self.con.sendline(cmd)

    def char_read_uuid(self, uuid):
        with self.connection_lock:
            self.con.sendline('char-read-uuid %s' % uuid)
            self.con.expect('value: .*? \r')
            after = self.con.after
            rval = after.split()[1:]
            return bytearray([int(x, 16) for x in rval])

    def char_read_hnd(self, handle):
        with self.connection_lock:
            self.con.sendline('char-read-hnd 0x%02x' % handle)
            self.con.expect('descriptor: .*? \r')
            after = self.con.after
            rval = after.split()[1:]
            return [int(n, 16) for n in rval]

    # Notification handle = 0x0025 value: 9b ff 54 07
    def run(self):
        while True:
            with self.connection_lock:
                try:
                    # TODO is pexpect thread safe, e.g. could we be blocked on this
                     # expect in one thread and do a sendline in another thread?
                    pnum = self.con.expect('Notification handle = .*? \r', timeout=.5)

                    if pnum == 0:
                        after = self.con.after
                        hxstr = after.split()[3:]
                        handle = int(hxstr[0], 16)
                except pexpect.TIMEOUT:
                    pass


    def register_cb(self, handle, fn):
        self.cb[handle]=fn

def run(bluetooth_address):
    print("starting..")

    device = BluetoothLeDevice(bluetooth_address)
    print("Version is %s" %
            str(device.char_read_uuid("f1000101-cb53-4c71-9c5f-69887f0ccb74")))
    device.run()

if __name__ == "__main__":
    run(sys.argv[1])
