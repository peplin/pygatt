#!/usr/bin/env python
from __future__ import print_function
import pexpect
import sys
import subprocess
import threading
import re

def reset_device():
    print("Re-initializing Bluetooth controller")
    subprocess.Popen(["sudo", "hciconfig", "hci0", "down"]).wait()
    subprocess.Popen(["sudo", "hciconfig", "hci0", "up"]).wait()

def lescan():
    reset_device()
    scan = pexpect.spawn("sudo hcitool lescan")
    # TODO don't want to expect anything, just want to take advantage of
    # pexpect's timeout feature
    try:
        scan.expect("nothing", timeout=5)
    except pexpect.TIMEOUT:
        addresses = set(re.findall("([\w][\w]\:.{14})", scan.before))
    print("Discovered devices:")
    print("\n".join(addresses))

class BluetoothLeDevice(object):
    connection_lock = threading.Lock()

    def __init__(self, mac_address):
        print("Preparing to connect to %s" + mac_address)
        reset_device()
        self.con = pexpect.spawn('gatttool -b ' + mac_address + ' --interactive')
        self.con.expect('\[LE\]>', timeout=1)
        self.con.sendline('connect')
        # test for success of connect
        self.con.expect('Connection successful.*\[LE\]>', timeout=5)
        print("Connected to %s." % mac_address)

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

def run(mac_address):
    print("starting..")

    lescan()
    device = BluetoothLeDevice(mac_address)
    print("Version is %s" %
            str(device.char_read_uuid("f1000101-cb53-4c71-9c5f-69887f0ccb74")))
    device.run()

if __name__ == "__main__":
    run(sys.argv[1])
