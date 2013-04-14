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
import json

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
        self.cb = {}
        return
    
    def char_write_cmd( self, handle, value ):
        # The 0%x for value is VERY naughty!  Fix this!
        cmd = 'char-write-cmd 0x%02x 0%x' % (handle, value)
        print cmd
        self.con.sendline( cmd )
        return
    
    def char_read_hnd( self, handle ):
        self.con.sendline('char-read-hnd 0x%02x' % handle)
        self.con.expect('descriptor: .* \r')
        after = self.con.after
        rval = after.split()[1:]
        return [long(float.fromhex(n)) for n in rval]

    # Notification handle = 0x0025 value: 9b ff 54 07
    def notification_loop( self ):
        while True:
            self.con.expect('Notification handle = .* \r')
            hxstr = self.con.after.split()[3:]
            #print hxstr[0],  [long(float.fromhex(n)) for n in hxstr[2:]]
            handle = long(float.fromhex(hxstr[0]))
            try:
                self.cb[handle]([long(float.fromhex(n)) for n in hxstr[2:]])
            except: 
                print "Error in callback for %x" % handle
                print sys.argv[1]
            pass
        pass
    
    def register_cb( self, handle, fn ):
        self.cb[handle]=fn;
        return


data = {}
datalog = sys.stdout

def tmp006(v):
    objT = (v[1]<<8)+v[0]
    ambT = (v[3]<<8)+v[2]
    targetT = calcTmpTarget(objT, ambT)
    data['t006'] = targetT
    print "T006 %.1f" % targetT

def accel(v):
    (xyz,mag) = calcAccel(v[0],v[1],v[2])
    data['accl'] = xyz
    print "ACCL", xyz
    datalog.write(json.dumps(data) + "\n")
    datalog.flush()

def magnet(v):
    print "MAGN", v

def gyro(v):
    print "GYRO", v

def main():
    global datalog

    bluetooth_adr = sys.argv[1]
    if len(sys.argv) > 2:
        datalog = open(sys.argv[2], 'w')


    tag = sensorTag(bluetooth_adr)

    # enable TMP006 sensor
    tag.register_cb(0x25,tmp006)
    tag.char_write_cmd(0x29,0x01)
    tag.char_write_cmd(0x26,0x0100)

    # enable accelerometer
    tag.register_cb(0x2d,accel)
    tag.char_write_cmd(0x31,0x01)
    tag.char_write_cmd(0x2e,0x0100)

    # enable magnetometer
    #tag.register_cb(0x40,magnet)
    #tag.char_write_cmd(0x44,0x01)
    #tag.char_write_cmd(0x41,0x0100)

    # enable gyroscope
    #tag.register_cb(0x57,gyro)
    #tag.char_write_cmd(0x5B,0x07)
    #tag.char_write_cmd(0x58,0x0100)

    tag.notification_loop()


if __name__ == "__main__":
    main()


