#!/usr/bin/env python
from __future__ import print_function
import pexpect
import subprocess
import threading
import re

def reset_bluetooth_controller():
    print("Re-initializing Bluetooth controller")
    subprocess.Popen(["sudo", "hciconfig", "hci0", "down"]).wait()
    subprocess.Popen(["sudo", "hciconfig", "hci0", "up"]).wait()

def lescan(timeout=5):
    scan = pexpect.spawn("sudo hcitool lescan")
    # TODO don't want to expect anything, just want to take advantage of
    # pexpect's timeout feature
    try:
        scan.expect("nothing", timeout=timeout)
    except pexpect.TIMEOUT:
        devices = []
        for line in scan.before.split("\r\n"):
            match = re.match("(([0-9A-Fa-f][0-9A-Fa-f]:?){6}) (\(?[\w]+\)?)", line)
            if match is not None:
                devices.append({
                    'address': match.group(1),
                    'name': match.group(3)
                })
    return [device for device in devices]

class BluetoothLeError(Exception): pass

class BluetoothLeDevice(object):
    DEFAULT_TIMEOUT_S = 1
    connection_lock = threading.Lock()
    handles = {}

    def __init__(self, mac_address):
        self.con = pexpect.spawn('gatttool -b ' + mac_address + ' --interactive')
        self.con.expect('\[LE\]>', timeout=1)
        self.con.sendline('connect')
        self.con.expect('Connection successful.*\[LE\]>', timeout=5)

    def get_handle(self, uuid):
        """Look up and return the handle for an attribute by its UUID.

        uuid - the UUID of the characteristic.

        Returns None if the UUID was not found.
        """
        if uuid not in self.handles:
            with self.connection_lock:
                self.con.sendline('characteristics')
                try:
                    self.con.expect(uuid, timeout=5)
                except pexpect.TIMEOUT:
                    raise BluetoothLeError(self.con.before)
                else:
                    handle_start = self.con.before.rfind("handle: ")
                    self.handles[uuid] = int(re.match("handle: 0x([a-fA-F0-9]{4})",
                            self.con.before[handle_start:]).group(1), 16)
        return self.handles.get(uuid)

    def char_write_cmd(self, handle, value):
        with self.connection_lock:
            # The 0%x for value is VERY naughty!  Fix this!
            cmd = 'char-write-cmd 0x%02x 0%x' % (handle, value)
            self.con.sendline(cmd)

    def char_write_req(self, handle, value):
        with self.connection_lock:
            hexstring = ''.join('%02x' % ord(byte) for byte in value)
            cmd = 'char-write-req 0x%02x %s' % (handle, hexstring)
            self.con.sendline(cmd)

    def char_read_uuid(self, uuid):
        with self.connection_lock:
            self.con.sendline('char-read-uuid %s' % uuid)
            self.con.expect('value: .*? \r', timeout=self.DEFAULT_TIMEOUT_S)
            after = self.con.after
            rval = after.split()[1:]
            return bytearray([int(x, 16) for x in rval])

    def char_read_hnd(self, handle):
        with self.connection_lock:
            self.con.sendline('char-read-hnd 0x%02x' % handle)
            self.con.expect('descriptor: .*? \r', timeout=self.DEFAULT_TIMEOUT_S)
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
