#!/usr/bin/env python
from __future__ import print_function
import pexpect
import subprocess
import threading
import re
import string

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
    connection_lock = threading.RLock()
    handles = {}

    def __init__(self, mac_address):
        self.con = pexpect.spawn('gatttool -b ' + mac_address + ' --interactive')
        self.con.expect('\[LE\]>', timeout=1)
        self.con.sendline('connect')
        try:
            self.con.expect('Connection successful.*\[LE\]>', timeout=5)
        except pexpect.TIMEOUT:
            raise BluetoothLeError("Unable to connect to device")

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
                    # TODO ugh this is sketchy, but then again so is this whole
                    # "library". The last line of the output will be the one
                    # matching our uuid (because it was the filter for the call
                    # to 'expect' above. Take that and pull out the leftmost
                    # handle value.
                    #TODO just split on ':'!
                    matching_line = self.con.before.splitlines(True)[-1]
                    self.handles[uuid] = int(re.match("\x1b\[Khandle: 0x([a-fA-F0-9]{4})",
                            matching_line).group(1), 16)
        return self.handles.get(uuid)

    def _expect(self, expected, timeout=DEFAULT_TIMEOUT_S):
        """We may (and often do) get an indication/notification before a
        write completes, and so it can be lost if we "expect()"'d something
        that came after it in the output, e.g.:

        > char-write-req 0x1 0x2
        Notificaiton    handle: xxx
        Write completed successfully.
        >

        Anytime we expect something we have to expect noti/indication first for
        a short time.
        """

        with self.connection_lock:
            try:
                # TODO is pexpect thread safe, e.g. could we be blocked on this
                # expect in one thread and do a sendline in another thread?
                pnum = self.con.expect('Notification handle = .*? \r', timeout=.5)
                if pnum == 0:
                    self._handle_notification(self.con.after)
            except pexpect.TIMEOUT:
                pass

            # TODO DRY
            try:
                pnum = self.con.expect('Indication   handle = .*? \r', timeout=.5)
                if pnum == 0:
                    self._handle_notification(self.con.after)
            except pexpect.TIMEOUT:
                pass

            self.con.expect(expected, timeout)


    def char_write_cmd(self, handle, value):
        with self.connection_lock:
            # The 0%x for value is VERY naughty!  Fix this!
            cmd = 'char-write-cmd 0x%02x 0%x' % (handle, value)
            self.con.sendline(cmd)

    def char_write_req(self, handle, value):
        with self.connection_lock:
            hexstring = ''.join('%02x' % byte for byte in value)
            cmd = 'char-write-req 0x%02x %s' % (handle, hexstring)
            self.con.sendline(cmd)
            self._expect('Characteristic value was written successfully')

    def char_read_uuid(self, uuid):
        with self.connection_lock:
            self.con.sendline('char-read-uuid %s' % uuid)
            self.con.expect('value: .*? \r', timeout=self.DEFAULT_TIMEOUT_S)
            rval = self.con.after.split()[1:]
            return bytearray([int(x, 16) for x in rval])

    def char_read_hnd(self, handle):
        with self.connection_lock:
            self.con.sendline('char-read-hnd 0x%02x' % handle)
            self.con.expect('descriptor: .*? \r', timeout=self.DEFAULT_TIMEOUT_S)
            rval = self.con.after.split()[1:]
            return [int(n, 16) for n in rval]

    def subscribe(self, uuid, callback=None):
        handle = self.get_handle(uuid)
        # TODO how do we explicitly associate the value and CCC handles?
        handle += 2
        # TODO just turning on notifications and indications for now to keep
        # it simple
        self.char_write_req(handle, bytearray([0x02, 0x00]))

    def _handle_notification(self, msg):
        handle, _, value = string.split(self.con.after.strip(), maxsplit=5)[3:]
        handle = int(handle, 16)
        value = bytearray.fromhex(value)
        print("Received indication on handle 0x%x " % handle)

    def run(self):
        while True:
            with self.connection_lock:
                try:
                    # TODO is pexpect thread safe, e.g. could we be blocked on this
                    # expect in one thread and do a sendline in another thread?
                    pnum = self.con.expect('Notification handle = .*? \r', timeout=.5)
                    if pnum == 0:
                        self._handle_notification(self.con.after)
                except pexpect.TIMEOUT:
                    pass

                # TODO DRY
                try:
                    pnum = self.con.expect('Indication   handle = .*? \r', timeout=.5)
                    if pnum == 0:
                        self._handle_notification(self.con.after)
                except pexpect.TIMEOUT:
                    pass
