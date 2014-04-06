#!/usr/bin/env python
# Michael Saunby. April 2014
#
#   Copyright 2014 Michael Saunby
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

import xively
import datetime
import time
import os

def xively_init():
   print os.getenv('XIVELY_API_KEY')
   api = xively.XivelyAPIClient(os.getenv('XIVELY_API_KEY'))
   return api.feeds.get(os.getenv('XIVELY_FEED_ID'))


t006 = []
accl_x = []
accl_y = []
accl_z = []
humd_t = []
humd_rh = []
baro_t = []
baro_p = []
magn_x = []
magn_y = []
magn_z = []
gyro_x = []
gyro_y = []
gyro_z = []


def xively_write(feed, data):
  global t006, accl_x, accl_y, accl_z, humd_t, humd_rh, baro_t, baro_p, magn_x, magn_y, magn_z, gyro_x, gyro_y, gyro_z
  t006.append(xively.Datapoint(datetime.datetime.utcnow(), data['t006']))
  accl_x.append(xively.Datapoint(datetime.datetime.utcnow(), data['accl'][0]))
  accl_y.append(xively.Datapoint(datetime.datetime.utcnow(), data['accl'][1]))
  accl_z.append(xively.Datapoint(datetime.datetime.utcnow(), data['accl'][2]))
  humd_t.append(xively.Datapoint(datetime.datetime.utcnow(), data['humd'][0]))
  humd_rh.append(xively.Datapoint(datetime.datetime.utcnow(), data['humd'][1]))
  baro_t.append(xively.Datapoint(datetime.datetime.utcnow(), data['baro'][0]))
  baro_p.append(xively.Datapoint(datetime.datetime.utcnow(), data['baro'][1]))
  magn_x.append(xively.Datapoint(datetime.datetime.utcnow(), data['magn'][0]))
  magn_y.append(xively.Datapoint(datetime.datetime.utcnow(), data['magn'][1]))
  magn_z.append(xively.Datapoint(datetime.datetime.utcnow(), data['magn'][2]))
  #gyro_x.append(xively.Datapoint(datetime.datetime.utcnow(), data['gyro'][0]))
  #gyro_y.append(xively.Datapoint(datetime.datetime.utcnow(), data['gyro'][1]))
  #gyro_z.append(xively.Datapoint(datetime.datetime.utcnow(), data['gyro'][2]))

  if len(t006) < 10:
    return
  else:
    feed.datastreams = [
      xively.Datastream(id=  't006', datapoints=t006),
      xively.Datastream(id=  'accl_x', datapoints=accl_x),
      xively.Datastream(id=  'accl_y', datapoints=accl_y),
      xively.Datastream(id=  'accl_z', datapoints=accl_z),
      xively.Datastream(id=  'humd_t', datapoints=humd_t),
      xively.Datastream(id=  'humd_rh', datapoints=humd_rh),
      xively.Datastream(id=  'baro_t', datapoints=baro_t),
      xively.Datastream(id=  'baro_p', datapoints=baro_p),
      xively.Datastream(id=  'magn_x', datapoints=magn_x),
      xively.Datastream(id=  'magn_y', datapoints=magn_y),
      xively.Datastream(id=  'magn_z', datapoints=magn_z),
      #xively.Datastream(id=  'gyro_x', datapoints=gyro_x),
      #xively.Datastream(id=  'gyro_x', datapoints=gyro_y),
      #xively.Datastream(id=  'gyro_x', datapoints=gyro_z),
     # when dealing with single data values can do this instead -
     # xively.Datastream(id=  't006', current_value=data['t006'],  at=now),
    ]
    t006 = []
    accl_x = []
    accl_y = []
    accl_z = []
    humd_t = []
    humd_rh = []
    baro_t = []
    baro_p = []
    magn_x = []
    magn_y = []
    magn_z = []
    gyro_x = []
    gyro_y = []
    gyro_z = []
    feed.update()


