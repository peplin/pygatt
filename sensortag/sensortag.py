#!/usr/bin/env python
# Michael Saunby. April 2013   
# 
# Notes.
# pexpect uses regular expression so characters that have special meaning
# in regular expressions, e.g. [ and ] must be escaped with a backslash.
#

import pexpect
import sys
import time
from sensor_calcs import *

def floatfromhex(h):
    t = float.fromhex(h)
    if t > float.fromhex('7FFF'):
        t = -(float.fromhex('FFFF') - t)
        pass
    return t

class sensorTag: 

    def __init__( self, bluetooth_adr ):
        self.con = pexpect.spawn('gatttool -b ' + bluetooth_adr + ' --interactive')
        self.con.expect('\[LE\]>')
        print "Preparing to connect. You might need to press the side button..."
        self.con.sendline('connect')
        # test for success of connect
        self.con.expect('\[CON\].*>')
        return
    
    def char_write_cmd( self, handle, value ):
        self.con.sendline('char-write-cmd 0x%02x %02x' % (handle, value))
        return
    
    def char_read_hnd( self, handle ):
        self.con.sendline('char-read-hnd 0x%02x' % handle)
        self.con.expect('descriptor: .* \r')
        after = self.con.after
        rval = after.split()[1:]
        return [long(float.fromhex(n)) for n in rval]


def main():
    bluetooth_adr = sys.argv[1]
    tag = sensorTag(bluetooth_adr)
    # enable TMP006 sensor
    tag.char_write_cmd(0x29,0x01)
    while True:
        time.sleep(1)
        v = tag.char_read_hnd(0x25)
        objT = (v[1]<<8)+v[0]
        ambT = (v[3]<<8)+v[2]
        t = calcTmpTarget(objT, ambT)
        print v, t
    

if __name__ == "__main__":
    main()


