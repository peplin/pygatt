#!/usr/bin/env python
# Michael Saunby. April 2013
#
# Notes.
# pexpect uses regular expression so characters that have special meaning
# in regular expressions, e.g. [ and ] must be escaped with a backslash.
#
#   Copyright 2013 Michael Saunby
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import pexpect
import sys
import time
from sensor_calcs import *
import json
import select

def floatfromhex(h):
    t = float.fromhex(h)
    if t > float.fromhex('7FFF'):
        t = -(float.fromhex('FFFF') - t)
        pass
    return t

class SensorTag:

    def __init__( self, bluetooth_adr ):
        self.con = pexpect.spawn('gatttool -b ' + bluetooth_adr + ' --interactive')
        self.con.expect('\[LE\]>', timeout=600)
        print "Preparing to connect. You might need to press the side button..."
        self.con.sendline('connect')
        # test for success of connect
	self.con.expect('Connection successful.*\[LE\]>')
        # Earlier versions of gatttool returned a different message.  Use this pattern -
        #self.con.expect('\[CON\].*>')
        self.cb = {}
        return

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
        self.con.expect('descriptor: .*? \r')
        after = self.con.after
        rval = after.split()[1:]
        return [long(float.fromhex(n)) for n in rval]

    # Notification handle = 0x0025 value: 9b ff 54 07
    def notification_loop( self ):
        while True:
	    try:
              pnum = self.con.expect('Notification handle = .*? \r', timeout=4)
            except pexpect.TIMEOUT:
              print "TIMEOUT exception!"
              break
	    if pnum==0:
                after = self.con.after
	        hxstr = after.split()[3:]
            	handle = long(float.fromhex(hxstr[0]))
            	#try:
	        if True:
                  self.cb[handle]([long(float.fromhex(n)) for n in hxstr[2:]])
            	#except:
                #  print "Error in callback for %x" % handle
                #  print sys.argv[1]
                pass
            else:
              print "TIMEOUT!!"
        pass

    def register_cb( self, handle, fn ):
        self.cb[handle]=fn;
        return

barometer = None
datalog = sys.stdout

class SensorCallbacks:

    data = {}

    def __init__(self,addr):
        self.data['addr'] = addr

    def tmp006(self,v):
        objT = (v[1]<<8)+v[0]
        ambT = (v[3]<<8)+v[2]
        targetT = calcTmpTarget(objT, ambT)
        self.data['t006'] = targetT
        print "T006 %.1f" % targetT

    def accel(self,v):
        (xyz,mag) = calcAccel(v[0],v[1],v[2])
        self.data['accl'] = xyz
        print "ACCL", xyz

    def humidity(self, v):
        rawT = (v[1]<<8)+v[0]
        rawH = (v[3]<<8)+v[2]
        (t, rh) = calcHum(rawT, rawH)
        self.data['humd'] = [t, rh]
        print "HUMD %.1f" % rh

    def baro(self,v):
        global barometer
        global datalog
        rawT = (v[1]<<8)+v[0]
        rawP = (v[3]<<8)+v[2]
        (temp, pres) =  self.data['baro'] = barometer.calc(rawT, rawP)
        print "BARO", temp, pres
        self.data['time'] = long(time.time() * 1000);
        # The socket or output file might not be writeable
        # check with select so we don't block.
        (re,wr,ex) = select.select([],[datalog],[],0)
        if len(wr) > 0:
            datalog.write(json.dumps(self.data) + "\n")
            datalog.flush()
            pass

    def magnet(self,v):
        x = (v[1]<<8)+v[0]
        y = (v[3]<<8)+v[2]
        z = (v[5]<<8)+v[4]
        xyz = calcMagn(x, y, z)
        self.data['magn'] = xyz
        print "MAGN", xyz

    def gyro(self,v):
        print "GYRO", v

def main():
    global datalog
    global barometer

    bluetooth_adr = sys.argv[1]
    #data['addr'] = bluetooth_adr
    if len(sys.argv) > 2:
        datalog = open(sys.argv[2], 'w+')

    while True:
     try:   
      print "[re]starting.."

      tag = SensorTag(bluetooth_adr)
      cbs = SensorCallbacks(bluetooth_adr)

      # enable TMP006 sensor
      tag.register_cb(0x25,cbs.tmp006)
      tag.char_write_cmd(0x29,0x01)
      tag.char_write_cmd(0x26,0x0100)

      # enable accelerometer
      tag.register_cb(0x2d,cbs.accel)
      tag.char_write_cmd(0x31,0x01)
      tag.char_write_cmd(0x2e,0x0100)

      # enable humidity
      tag.register_cb(0x38, cbs.humidity)
      tag.char_write_cmd(0x3c,0x01)
      tag.char_write_cmd(0x39,0x0100)

      # enable magnetometer
      tag.register_cb(0x40,cbs.magnet)
      tag.char_write_cmd(0x44,0x01)
      tag.char_write_cmd(0x41,0x0100)

      # enable gyroscope
      tag.register_cb(0x57,cbs.gyro)
      tag.char_write_cmd(0x5b,0x07)
      tag.char_write_cmd(0x58,0x0100)

      # fetch barometer calibration
      tag.char_write_cmd(0x4f,0x02)
      rawcal = tag.char_read_hnd(0x52)
      barometer = Barometer( rawcal )
      # enable barometer
      tag.register_cb(0x4b,cbs.baro)
      tag.char_write_cmd(0x4f,0x01)
      tag.char_write_cmd(0x4c,0x0100)

      tag.notification_loop()
     except:
      pass

if __name__ == "__main__":
    main()

