#!/usr/bin/env python
from __future__ import print_function
import pexpect
import sys

def floatfromhex(h):
    t = float.fromhex(h)
    if t > float.fromhex('7FFF'):
        t = -(float.fromhex('FFFF') - t)
    return t

class BluetoothLeDevice(object):

    def __init__(self, bluetooth_adr):
        print("Preparing to connect.")
        lescan = pexpect.spawn('sudo hcitool lescan')
        lescan.expect(bluetooth_adr.upper(), timeout=5)
        self.con = pexpect.spawn('gatttool -b ' + bluetooth_adr + ' --interactive')
        self.con.expect('\[LE\]>', timeout=1)
        self.con.sendline('connect')
        # test for success of connect
	self.con.expect('Connection successful.*\[LE\]>')
        # Earlier versions of gatttool returned a different message.  Use this pattern -
        #self.con.expect('\[CON\].*>')
        self.cb = {}
        return

    def char_write_cmd(self, handle, value):
        # The 0%x for value is VERY naughty!  Fix this!
        cmd = 'char-write-cmd 0x%02x 0%x' % (handle, value)
        print(cmd)
        self.con.sendline(cmd)
        return

    def char_read_uuid(self, uuid):
        self.con.sendline('char-read-uuid %s' % uuid)
        self.con.expect('descriptor: .*? \r')
        after = self.con.after
        rval = after.split()[1:]
        return [long(float.fromhex(n)) for n in rval]

    def char_read_hnd(self, handle):
        self.con.sendline('char-read-hnd 0x%02x' % handle)
        self.con.expect('descriptor: .*? \r')
        after = self.con.after
        rval = after.split()[1:]
        return [long(float.fromhex(n)) for n in rval]

    # Notification handle = 0x0025 value: 9b ff 54 07
    def notification_loop(self):
        while True:
	    try:
              pnum = self.con.expect('Notification handle = .*? \r', timeout=4)
            except pexpect.TIMEOUT:
              print("Timed out waiting for a notification")
              break
	    if pnum==0:
                after = self.con.after
	        hxstr = after.split()[3:]
            	handle = long(float.fromhex(hxstr[0]))
            	#try:
	        if True:
                  self.cb[handle]([long(float.fromhex(n)) for n in hxstr[2:]])

    def register_cb(self, handle, fn):
        self.cb[handle]=fn
        return

def run(bluetooth_address):
    print("starting..")

    device = BluetoothLeDevice(bluetooth_adr)

    device.notification_loop()

if __name__ == "__main__":
    run(sys.argv[1])
