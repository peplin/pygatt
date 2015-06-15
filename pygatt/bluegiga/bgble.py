from __future__ import print_function

from binascii import hexlify
import logging
import serial
import threading

import bglib
from error import get_return_message
from constants import(
    ble_address_type, bondable, bonding, connection_status_flag,
    gap_discover_mode, gap_discoverable_mode, gap_connectable_mode,
    gatt_attribute_type_uuid, gatt_characteristic_descriptor_uuid,
    gatt_characteristic_type_uuid, gatt_service_uuid
)


class Characteristic(object):
    """
    GATT characteristic. For internal use within BluetoothLEDevice.
    """
    def __init__(self, name, handle):
        """
        Sets the characteritic name and handle.
        """
        self.handle = handle  # bytearray
        self.descriptors = {
            # uuid_string: handle
        }

    def add_descriptor(self, uuid, handle):
        """
        Add a characteristic descriptor to the dictionary of descriptors.
        """
        self.descriptors[uuid] = handle


class BLED112Backend(object):
    """
    Pygatt BLE device backend using the Bluegiga BLED112.
    Only supports 1 device connection at a time.
    This object is NOT threadsafe.
    """
    def __init__(self, serial_port):
        """
        Initialize the BLED112 to be ready for use with a BLE device, i.e.,
        stop ongoing procedures, disconnect any connections, optionally start
        the receiver thread, and optionally delete any stored bonds.

        serial_port -- The name of the serial port that the BLED112 is connected
                       to.

        Locking total order:
        1) self._cond
        2) self._loglock
        """
        # Initialization
        self._lib = bglib.BGLib()
        self._ser = serial.Serial(serial_port, timeout=0.25)
        # Note: _ser is not protected by _main_thread_cond

        # Logging
        # FIXME/TODO: remove config/set log level
        self._loglock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        logging.basicConfig(filename='example.log', level=logging.DEBUG)

        # Main thread (the one calling commands) waits on this. This also
        # provides mutual exclustion for BLED112Backend's state (except for the
        # log)
        self._main_thread_cond = threading.Condition()

        # Packet receiving
        self._recvr_thread = None  # background thread to receive packets
        self._recvr_stop = True  # tell recvr thread not to run

        # Flags to tell the main thread what to do when woken up from waiting
        self._attribute_value_received = False  # attribute_value event occurred
        self._bond_removed = False  # stored bond has been deleted
        self._bonded = False  # device is bonded
        self._bonding_fail = False  # failed to bond with device
        self._connect_timeout = False  # connection procedure timed-out
        self._connected = False  # device is connected
        self._encrypted = False  # connection is encrypted
        self._event_return = 0  # event return code
        self._procedure_completed = False  # procecure_completed event occurred
        self._response_received = False  # command response received
        self._response_return = 0  # command response return code

        # BLED112_backend's state
        self._attribute_value = None  # attribute_value event value
        self._expected_attribute_handle = None  # expected handle after a read
        self._bond_handle = 0xFF  # handle for the device bond
        self._connection_handle = 0x00  # handle for the device connection
        self._characteristics = {  # the device characteristics discovered
            # uuid_string: Characteristic()
        }
        self._characteristics_cached = False  # characteristics already found
        self._current_characteristic = None  # used in char/descriptor discovery
        self._num_bonds = 0  # number of bonds stored on the BLED112
        self.notifications = {  # stores notification packet contents
            # handle: [value_bytearray0, ...]
        }
        self._stored_bonds = []  # bond handles stored on the BLED112

        # Register response handlers. Note: the packets of any response not
        # registered here will go undetected.
        self._lib.ble_rsp_attclient_attribute_write +=\
            self._ble_rsp_attclient_attribute_write
        self._lib.ble_rsp_attclient_find_information +=\
            self._ble_rsp_attclient_find_information
        self._lib.ble_rsp_attclient_read_by_handle +=\
            self._ble_rsp_attclient_read_by_handle
        self._lib.ble_rsp_connection_disconnect +=\
            self._ble_rsp_connection_disconnect
        self._lib.ble_rsp_connection_get_rssi +=\
            self._ble_rsp_connection_get_rssi
        self._lib.ble_rsp_gap_connect_direct +=\
            self._ble_rsp_gap_connect_direct
        # FIXME: gap_discover needed?
        # self._lib.ble_rsp_gap_discover +=\
        #    self._ble_rsp_gap_discover
        self._lib.ble_rsp_gap_end_procedure +=\
            self._ble_rsp_gap_end_procedure
        self._lib.ble_rsp_gap_set_mode +=\
            self._ble_rsp_gap_set_mode
        self._lib.ble_rsp_gap_set_scan_parameters +=\
            self._ble_rsp_gap_set_scan_parameters
        self._lib.ble_rsp_sm_delete_bonding +=\
            self._ble_rsp_sm_delete_bonding
        self._lib.ble_rsp_sm_encrypt_start +=\
            self._ble_rsp_sm_encrypt_start
        self._lib.ble_rsp_sm_get_bonds +=\
            self._ble_rsp_sm_get_bonds
        self._lib.ble_rsp_sm_set_bondable_mode +=\
            self._ble_rsp_sm_set_bondable_mode

        # Register event handlers. Note: the packets of any event not registered
        # here will go undetected.
        self._lib.ble_evt_attclient_attribute_value +=\
            self._ble_evt_attclient_attribute_value
        self._lib.ble_evt_attclient_find_information_found +=\
            self._ble_evt_attclient_find_information_found
        self._lib.ble_evt_attclient_procedure_completed +=\
            self._ble_evt_attclient_procedure_completed
        self._lib.ble_evt_connection_status +=\
            self._ble_evt_connection_status
        self._lib.ble_evt_connection_disconnected +=\
            self._ble_evt_connection_disconnected
        # FIXME: next 3 events needed?
        # self._lib.ble_evt_connection_feature_ind += self._generic_handler
        # self._lib.ble_evt_connection_version_ind += self._generic_handler
        # self._lib.ble_evt_gap_scan_response +=\
        #    self._ble_evt_gap_scan_response
        self._lib.ble_evt_sm_bond_status +=\
            self._ble_evt_sm_bond_status
        self._lib.ble_evt_sm_bonding_fail +=\
            self._ble_evt_sm_bonding_fail

        # Start logging
        self._loglock.acquire()
        self._logger.info("---LOG START---")
        self._logger.info("BLED112Backend on %s", serial_port)
        self._loglock.release()

    def bond(self):
        """
        Create a bond and encrypted connection with the device.

        This requires that a connection is already extablished with the device.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there is a connection
        if not self._connected:
            self._logger.warn("Not connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Set to bondable mode
        self._logger.info("set_bondable_mode")
        cmd = self._lib.ble_cmd_sm_set_bondable_mode(bondable['yes'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        self._loglock.acquire()
        if self._response_return != 0:
            self._logger.warn("set_bondable_mode failed: %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Begin encryption and bonding
        self._bonding_fail = False
        self._logger.info("encrypt_start")
        cmd = self._lib.ble_cmd_sm_encrypt_start(self._connection_handle,
                                                 bonding['create_bonding'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        self._loglock.acquire()
        if self._response_return != 0:
            self._logger.warn("encrypt_start failed: %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Wait for event
        while not (self._bonded or self._bonding_fail) and self._connected:
            self._main_thread_cond.wait()
        if not self._connected:
            self._logger.warn("encrypt_start failed: disconnected")
            self._loglock.release()
            self._main_thread_cond.release()
            return
        if self._bonded:
            self._logger.info("Bonding successful")
        if self._bonding_fail:
            self._logger.info("Bonding failed")
            self._bonding_fail = False

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def char_write(self, handle, value):
        """
        Write a value to a characteristic on the device.

        This requires that a connection is already extablished with the device.

        handle -- the characteristic/descriptor handle to write to.
        value -- a bytearray holding the value to write.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there is a connection
        if not self._connected:
            self._logger.warn("Not connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Write to characteristic
        value_list = [b for b in value]
        self._logger.info("attribute_write")
        cmd = self._lib.ble_cmd_attclient_attribute_write(
            self._connection_handle, handle, value_list)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        self._loglock.acquire()
        if self._response_return != 0:
            self._logger.warn("attribute_write failed: %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Wait for event
        self._loglock.release()  # don't hold loglock while waiting
        while (not self._procedure_completed) and self._connected:
            self._main_thread_cond.wait()
        self._procedure_completed = False
        self._loglock.acquire()
        if not self._connected:
            self._logger.warn("attribute_write failed: disconnected")
            self._loglock.release()
            self._main_thread_cond.release()
            return
        if self._event_return != 0:
            self._logger.warn("attribute_write failed: %s",
                              get_return_message(self._event_return))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def char_read(self, handle):
        """
        Read a value from a characteristic on the device.

        This requires that a connection is already established with the device.

        handle -- the characteristic handle to read from.

        Returns a bytearray containing the value read, on success.
        Returns None, on failure.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there is a connection
        if not self._connected:
            self._logger.warn("Not connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return None

        # Read from characteristic
        self._logger.info("read_by_handle")
        self._expected_attribute_handle = handle
        cmd = self._lib.ble_cmd_attclient_read_by_handle(
            self._connection_handle, handle)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        self._loglock.acquire()
        if self._response_return != 0:
            self._logger.warn("read_by_handle failed: %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return None

        # Wait for event
        self._loglock.release()  # don't hold loglock while waiting
        while (not (self._attribute_value_received or
                    self._procedure_completed)) and self._connected:
            self._main_thread_cond.wait()
        value = None  # return value
        self._loglock.acquire()
        if not self._connected:
            self._logger.warn("read_by_handle failed: disconnected")
            self._loglock.release()
            self._main_thread_cond.release()
            return
        if self._attribute_value_received:
            self._attribute_value_received = False  # reset the flag
            value = self._attribute_value
        elif self._procedure_completed:
            self._procedure_completed = False  # reset the flag
            if self._event_return != 0:
                self._logger.warn("read_by_handle failed: %s",
                                  get_return_message(self._event_return))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

        # Return characteristic value
        if value is not None:
            return bytearray(value)
        else:
            return value

    def connect(self, address, timeout=5,
                addr_type=ble_address_type['gap_address_type_public']):
        """
        Connnect directly to a device given the ble address then discovers and
        stores the characteristic and characteristic descriptor handles.

        Requires that the BLED112 is not connected to a device already.

        address -- a bytearray containing the device mac address.
        timeout -- number of seconds to wait before returning if not connected.
        addr_type -- one of the ble_address_type constants.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there isn't a connection
        if self._connected:
            self._logger.warn("Already connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Setup connection timeout timer
        self._connect_timeout = False
        timer = threading.Timer(timeout, self._timer_func)

        # Connect to the device
        bd_addr = [b for b in address]
        interval_min = 6  # 6/1.25 ms
        interval_max = 30  # 30/1.25 ms
        timeout = 20  # 20/10 ms
        latency = 0  # intervals that can be skipped
        self._logger.info("gap_connect_direct")
        self._logger.info("address = %s", '0x'+hexlify(address))
        self._logger.debug("interval_min = %f ms", interval_min/1.25)
        self._logger.debug("interval_max = %f ms", interval_max/1.25)
        self._logger.debug("timeout = %d ms", timeout/10)
        self._logger.debug("latency = %d intervals", latency)
        cmd = self._lib.ble_cmd_gap_connect_direct(bd_addr, addr_type,
                                                   interval_min, interval_max,
                                                   timeout, latency)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        if self._response_return != 0:
            self._loglock.acquire()
            self._logger.warn("connect_direct failed: %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Start timeout timer
        timer.start()

        # Wait for event
        while not (self._connected or self._connect_timeout):
            self._main_thread_cond.wait()
        self._loglock.acquire()
        if self._connect_timeout:
            self._connect_timeout = False
            if not self._connected:
                self._logger.warn("Connect timeout")

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def disconnect(self):
        """
        Disconnect from the device if connected.

        delete_bond -- Delete the bond? (True/False)
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Disconnect connection
        self._logger.info("connection_disconnect")
        cmd = self._lib.ble_cmd_connection_disconnect(self._connection_handle)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        if self._response_return != 0:
            self._loglock.acquire()
            self._logger.warn("connection_disconnect failed: %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Wait for event
        while self._connected:
            self._main_thread_cond.wait()
        msg = "Disconnected by local user"
        if self._event_return != 0:
            msg = get_return_message(self._event_return)
        self._loglock.acquire()
        self._logger.info("Connection disconnected: %s", msg)

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def encrypt(self):
        """
        Begin encryption on the connection with the device.

        This requires that a connection is already established with the device.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there is a connection
        if not self._connected:
            self._logger.warn("Not connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Set to non-bondable mode
        self._logger.info("set_bondable_mode")
        cmd = self._lib.ble_cmd_sm_set_bondable_mode(bondable['no'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag

        # Start encryption
        self._logger.info("encrypt_start")
        cmd = self._lib.ble_cmd_sm_encrypt_start(
            self._connection_handle, bonding['do_not_create_bonding'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        if self._response_return != 0:
            self._loglock.acquire()
            self._logger.warn("encrypt_start failed %s",
                              get_return_message(self._response_return))
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Wait for event
        while (not self._encrypted) and self._connected:
            self._main_thread_cond.wait()
        self._loglock.acquire()
        if not self._connected:
            self._logger.warn("encrypt_start failed: disconnected")
        elif self._bonding_fail:
            # Device may try to bond and cause this, so catch if possible
            self._bonding_fail = False

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def get_handle(self, characteristic_uuid, descriptor_uuid=None):
        """
        Get the handle for a characteristic or descriptor.

        This requires that a connection is already established with the device.

        characteristic_uuid -- bytearray containing the characteristic UUID.
        descriptor_uuid -- optional bytearray containg the GATT descriptor UUID
                           for the given characteristic. Note: use the
                           gatt_characteristic_descriptor_uuid constant.

        Returns an integer containing the handle on success.
        Returns None on failure.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there is a connection
        if not self._connected:
            self._logger.warn("Not connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Discover characteristics if not cached
        if not self._characteristics_cached:
            att_handle_start = 0x0001  # first valid handle
            att_handle_end = 0xFFFF  # last valid handle
            cmd = self._lib.ble_cmd_attclient_find_information(
                self._connection_handle, att_handle_start, att_handle_end)
            self._logger.info("find_information")
            self._lib.send_command(self._ser, cmd)

            # Wait for response
            self._loglock.release()  # don't hold loglock while waiting
            while not self._response_received:
                self._main_thread_cond.wait()
            self._response_received = False  # reset the flag
            if self._response_return != 0:
                self._loglock.acquire()
                self._logger.warn("find_information failed %s",
                                  get_return_message(self._response_return))
                self._loglock.release()
                self._main_thread_cond.release()
                return

            # Wait for event
            while (not self._procedure_completed) and self._connected:
                self._main_thread_cond.wait()
            self._procedure_completed = False
            self._loglock.acquire()
            if not self._connected:
                self._logger.warn("find_information failed: disconnected")
                self._loglock.release()
                self._main_thread_cond.release()
                return
            elif self._event_return != 0:
                self._logger.warn("find_information failed: %s",
                                  get_return_message(self._event_return))
                self._loglock.release()
                self._main_thread_cond.release()
                return
            self._characteristics_cached = True

            # Log
            self._logger.debug("Characteristics:")
            for char_uuid_str, char_obj in self._characteristics.iteritems():
                self._logger.debug("char 0x%s --> %s", char_uuid_str,
                                   hex(char_obj.handle))
                for desc_uuid_str, desc_handle in (
                        char_obj.descriptors.iteritems()):
                    self._logger.debug("desc 0x%s --> %s", desc_uuid_str,
                                       hex(desc_handle))

        # Return the handle if it exists
        char = None
        char_uuid_str = hexlify(characteristic_uuid)
        if not (char_uuid_str in self._characteristics):
            self._logger.warn("No such characterisitic")
            self._loglock.release()
            self._main_thread_cond.release()
            return
        char = self._characteristics[char_uuid_str]
        if descriptor_uuid is None:
            self._loglock.release()
            self._main_thread_cond.release()
            return char.handle
        desc_uuid_str = hexlify(descriptor_uuid)
        if not (desc_uuid_str in char.descriptors):
            self._logger.warn("No such descriptor")
            self._loglock.release()
            self._main_thread_cond.release()
            return
        desc_handle = char.descriptors[desc_uuid_str]
        self._loglock.release()
        self._main_thread_cond.release()
        return desc_handle

    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        This requires that a connection is already established with the device.

        Returns the RSSI as in integer in dBm.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Make sure there is a connection
        if not self._connected:
            self._logger.warn("Not connected")
            self._loglock.release()
            self._main_thread_cond.release()
            return

        # Get RSSI value
        self._logger.info("get_rssi")
        cmd = self._lib.ble_cmd_connection_get_rssi(self._connection_handle)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False  # reset the flag
        rssi_value = self._response_return

        # Drop locks
        self._main_thread_cond.release()

        return rssi_value

    def run(self):
        """
        Start running the receiver thread in the background.

        Note: if this is not done before sending a command, NO PACKETS will be
        received and the program will hang.
        """
        # Setup and run recvr thread
        self._main_thread_cond.acquire()
        self._recvr_stop = False
        self._main_thread_cond.release()
        self._recvr_thread = threading.Thread(target=self._recvr)
        self._recvr_thread.start()

        # The following steps must be taken to ensure that the BLED112 is in an
        # idle state.

        # Disconnect any connections
        self.disconnect()

        # Stop advertising
        self._loglock.acquire()
        self._logger.info("gap_set_mode")
        self._loglock.release()
        cmd = self._lib.ble_cmd_gap_set_mode(
            gap_discoverable_mode['non_discoverable'],
            gap_connectable_mode['non_connectable'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._main_thread_cond.acquire()
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False
        self._loglock.acquire()
        if self._response_return != 0:
            self._logger.warn("gap_set_mode failed: %s",
                              get_return_message(self._response_return))

        # Stop any ongoing procedure
        self._logger.info("gap_end_procedure")
        cmd = self._lib.ble_cmd_gap_end_procedure()
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False
        self._loglock.acquire()
        if self._response_return != 0:
            self._logger.warn("gap_end_procedure failed: %s",
                              get_return_message(self._response_return))

        # Set not bondable
        self._logger.info("set_bondable_mode")
        cmd = self._lib.ble_cmd_sm_set_bondable_mode(bondable['no'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._loglock.release()  # don't hold loglock while waiting
        while not self._response_received:
            self._main_thread_cond.wait()
        self._response_received = False

        # Drop lock
        self._main_thread_cond.release()

        # Find bonds
        # with self._loglock:
        #    self._logger.info("Finding bonds")
        # cmd = self._lib.ble_cmd_sm_get_bonds()
        # self._lib.send_command(self._ser, cmd)
        # self._cond.acquire()
        # while (self._num_bonds == -1) or\
        #      (len(self._stored_bonds) < self._num_bonds):
        #    with self._loglock:
        #        self._logger.debug("Waiting on bond finding")
        #    self._cond.wait()
        # with self._loglock:
        #    self._logger.debug("Bonds")
        #    for b in self._stored_bonds:
        #        self._logger.debug(hex(b))
        # self._cond.release()

        # Delete bonds
        # if delete_existing_bonds:
        #    with self._loglock:
        #        self._logger.info("Deleting stored bonds")
        #    for b in reversed(self._stored_bonds):
        #        cmd = self._lib.ble_cmd_sm_delete_bonding(b)
        #        self._lib.send_command(self._ser, cmd)
        #        self._cond.acquire()
        #        self._bond_removed = False
        #        while not self._bond_removed:
        #            with self._loglock:
        #                self._logger.debug("Waiting on bond removal")
        #            self._cond.wait()
        #        self._cond.release()

    # TODO: finish this function if needed
    # NOTE: it doesn't make sense for a BluetoothLEDevice to "scan"...
    def scan(self, scan_interval=75, scan_window=50, active=True,
             scan_time=1000, discover_mode=gap_discover_mode['generic']):
        """
        Perform a scan to discover BLE devices.

        scan_interval -- the number of miliseconds until scanning is restarted.
        scan_window -- the number of miliseconds the scanner will listen on one
                     frequency for advertisement packets.
        active -- True --> ask sender for scan response data. False --> don't.
        scan_time -- the number of miliseconds this scan should last.
        discover_mode -- one of the gap_discover_mode constants.
        """
        raise NotImplementedError("scan")  # FIXME: remove
        # Set scan parameters
        # with self._loglock:
        #    self._logger.info("Set scan parameters")
        # if active:
        #    active = 0x01
        # else:
        #    active = 0x00
        # NOTE: the documentation seems to say that the times are in units of
        # 625us but the ranges it gives correspond to units of 1ms....
        # cmd = self._lib.ble_cmd_gap_set_scan_parameters(
        #    scan_interval, scan_window, active
        # )
        # self._lib.send_command(self._ser, cmd)
        # Begin scanning
        # with self._loglock:
        #    self._logger.info("Begin scanning")
        # cmd = self._lib.ble_cmd_gap_discover(discover_mode)
        # self._lib.send_command(self._ser, cmd)
        # Wait for scan_time
        # with self._loglock:
        #    self._logger.debug("Wait for %d ms", scan_time)
        # time.sleep(scan_time/1000)
        # Stop scanning
        # with self._loglock:
        #    self._logger.info("Stop scanning")
        # cmd = self._lib.ble_cmd_gap_end_procedure()
        # self._lib.send_command(self._ser, cmd)

    def stop(self):
        """
        Stop the receiver thread to allow for a graceful exit. This should be
        called when the BLED112Backend is done being used in the program.
        """
        self._main_thread_cond.acquire()
        self._logger.info("Set _recvr_stop True")
        self._recvr_stop = True
        self._main_thread_cond.release()

    def subscribe(self, characteristic_uuid, indicate=False):
        """
        Receive notifications from the characteritic.

        This requires that a connection is already established with the device.

        characteristic_uuid -- the uuid of the characteristic to subscribe to.
        indicate -- receive indications (requires application ACK) rather than
                    notifications (does not require application ACK).
        """
        # Get client_characteristic_configuration descriptor handle
        handle = self.get_handle(
            characteristic_uuid,
            gatt_characteristic_descriptor_uuid[
                'client_characteristic_configuration'
            ])
        if handle is None:
            return

        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

        # Subscribe to characteristic
        config_val = [0x01, 0x00]  # Enable notifications 0x0001
        if indicate:
            config_val = [0x02, 0x00]  # Enable indications 0x0002
        self.char_write(handle, config_val)

    def _connection_status_flag(self, flags, flag_to_find):
        """
        Is the given flag in the connection status flags?

        flags -- the 'flags' parameter returned by ble_evt_connection_status.
        flag_to_find -- the flag to look for in flags.

        Returns true if flag_to_find is in flags. Returns false otherwise.
        """
        return (flags & flag_to_find) == flag_to_find

    def _get_uuid_type(self, uuid):
        """
        Checks if the UUID is a custom 128-bit UUID or a GATT characteristic
        descriptor UUID.

        uuid -- the UUID as a bytearray.

        Returns -1 if the UUID is unrecognized.
        Returns 0 if the UUID is a 128-bit UUID.
        Returns 1 if the UUID is a GATT service UUID.
        Returns 2 if the UUID is a GATT attribute type UUID
        Returns 3 if the UUID is a GATT characteristic descriptor UUID.
        Returns 4 if the UUID is a GATT characteristic type UUID.
        """
        self._logger.debug("uuid = %s", "0x"+hexlify(uuid))
        self._logger.debug("len(uuid) = %d", len(uuid))
        if len(uuid) == 16:  # 128-bit --> 16 byte
            self._logger.debug("match custom")
            return 0
        for name, u in gatt_service_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 1
        for name, u in gatt_attribute_type_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 2
        for name, u in gatt_characteristic_descriptor_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 3
        for name, u in gatt_characteristic_type_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 4
        self._logger.debug("no match")
        return -1

    def _recvr(self):
        """
        Continuously receives packets from the serial port until the flag
        self._recvr_stop == True.

        This should be run in its own thread.

        ser -- the serial.Serial() object for the serial port
        """
        self._loglock.acquire()
        self._logger.info("Receiver thread started")
        self._loglock.release()
        while True:
            # Read, parse byte, possibly calling a response or event method
            x = self._ser.read()
            if len(x) > 0:
                self._lib.parse(ord(x))
            else:
                self._main_thread_cond.acquire()
                if self._recvr_stop:
                    self._loglock.acquire()
                    self._logger.info("Receiver thread stopped")
                    self._loglock.release()
                    self._main_thread_cond.release()
                    return
                self._main_thread_cond.release()

    def _timer_func(self):
        """
        Notify _main_thread_cond and set the _connect_timeout flag to True.

        For use in a threading.Timer object.
        """
        self._main_thread_cond.acquire()
        self._connect_timeout = True
        self._main_thread_cond.notify()
        self._main_thread_cond.release()

    # Generic event/response handler -------------------------------------------
    def _generic_handler(self, sender, args):
        """
        Generic event/response handler. Used for receiving packets from the
        BLED112 that don't need any specific action taken.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in  BGLib.
        args -- dictionary containing the parameters for the event/response
                given in the Bluegia Bluetooth Smart Software API.
        """
        self._loglock.acquire()
        self._logger.info("Generic packet handler")
        # for key in args:
        #    print(key, " = ", args[key])
        if 'result' in args:
            self._logger.info("Return code = %s",
                              get_return_message(args['result']))
        self._locklock.release()

    # Event handlers -----------------------------------------------------------
    # FIXME: asynchronous notifications trigger this. How to handle value and
    #       callback.
    def _ble_evt_attclient_attribute_value(self, sender, args):
        """
        Handles the BLED112 event for values of characteristics.

        Modifies _attribute_value_received, _attribute_value. Nofifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in  BGLib.
        args -- dictionary containing the connection handle ('connection'),
                attribute handle ('atthandle'), attribute type ('type'),
                and attribute value ('value')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Check if notification packet
        if self._expected_attribute_handle != args['atthandle']:
            self.notifications[args['atthandle']].append(
                bytearray(args['value']))
            print(args['value'])
        else:
            # Set flags, record info, and notify
            self._attribute_value_received = True
            self._attribute_value = args['value']
            self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_evt_attclient_attriute_value")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("attribute handle = %s", hex(args['atthandle']))
        self._logger.debug("attribute type = %s", hex(args['type']))
        self._logger.debug("attribute value = %s",
                           hexlify(bytearray(args['value'])))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_evt_attclient_find_information_found(self, sender, args):
        """
        Handles the event for characteritic discovery.

        Adds the characteristic to the dictionary of characteristics or adds
        the descriptor to the dictionary of descriptors in the current
        characteristic. These events will be occur in an order similar to the
        following:
        1) primary service uuid
        2) 0 or more descriptors
        3) characteristic uuid
        4) 0 or more descriptors
        5) repeat steps 3-4

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in  BGLib.
        args -- dictionary containing the connection handle ('connection'),
                characteristic handle ('chrhandle'), and characteristic UUID
                ('uuid')
        """
        uuid = bytearray(list(reversed(args['uuid'])))
        uuid_str = "0x"+hexlify(uuid)

        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Log
        self._logger.info("_ble_evt_attclient_find_information_found")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("characteristic handle = %s", hex(args['chrhandle']))
        self._logger.debug("characteristic UUID = %s", uuid_str)

        # Add uuid to characteristics as characteristic or descriptor
        uuid_type = self._get_uuid_type(uuid)
        # 3 == descriptor
        if (uuid_type == 3) and (self._current_characteristic is not None):
            self._logger.debug("GATT characteristic descriptor")
            self._current_characteristic.add_descriptor(hexlify(uuid),
                                                        args['chrhandle'])
        elif uuid_type == 0:  # 0 == custom 128-bit UUID
            self._logger.debug("found custom characteristic")
            new_char = Characteristic(uuid, args['chrhandle'])
            self._current_characteristic = new_char
            self._characteristics[hexlify(uuid)] = new_char
            self.notifications[new_char.handle] = []

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_evt_attclient_procedure_completed(self, sender, args):
        """
        Handles the event for completion of writes to remote device.

        Modifies _procedure_completed and _event_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in  BGLib.
        args -- dictionary containing the connection handle ('connection'),
                return code ('result'), characteristic handle ('chrhandle')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Log
        self._logger.info("_ble_evt_attclient_procedure_completed")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("characteristic handle = %s", hex(args['chrhandle']))
        self._logger.info("return code = %s",
                          get_return_message(args['result']))

        # Set flag, return value, and notify
        self._procedure_completed = True
        self._event_return = args['result']
        self._main_thread_cond.notify()

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_evt_connection_disconnected(self, sender, args):
        """
        Handles the event for the termination of a connection.

        Modifies the _connected, _bonded, _encrypted flags. Modifies
        _connection_handle, _bond_handle, and _event_return.
        Notifies _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in  BGLib.
        args -- dictionary containing the connection handle ('connection'),
                return code ('reason')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Determine disconnect reason
        msg = "disconnected by local user"
        if args['reason'] != 0:
            msg = get_return_message(args['reason'])

        # Log
        self._logger.info("_ble_evt_connection_disconnected")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("return code = %s", msg)

        # Set flags, return value, and notify
        self._connected = False
        self._encrypted = False
        self._bonded = False
        self._event_return = args['reason']
        self._main_thread_cond.notify()

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_evt_connection_status(self, sender, args):
        """
        Handles the event for the BLED112 reporting connection parameters.

        Modifies the _connected, _bonded, _encrypted flags. Modifies
        _connection_handle and _bond_handle. Notifies _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in  BGLib.
        args -- dictionary containing the connection handle ('connection'),
                connection status flags ('flags'), device address ('address'),
                device address type ('address_type'), connection interval
                ('conn_interval'), connection timeout (timeout'), device latency
                ('latency'), device bond handle ('bonding')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._main_thread_cond.notify()
        self._connection_handle = args['connection']
        self._bond_handle = args['bonding']
        flags = ""
        if self._connection_status_flag(
                args['flags'], connection_status_flag['connected']):
            self._connected = True
            flags += 'connected, '
        if self._connection_status_flag(
                args['flags'], connection_status_flag['encrypted']):
            self._encrypted = True
            flags += 'encrypted, '
        if self._connection_status_flag(
                args['flags'], connection_status_flag['completed']):
            flags += 'completed, '
        if self._connection_status_flag(
                args['flags'], connection_status_flag['parameters_change']):
            flags += 'parameters_change, '
        if self._bond_handle != 0xFF:
            self._bonded = True
        else:
            self._bonded = False

        # Log
        self._logger.info("_ble_evt_connection_status")
        self._logger.debug("connection = %s", hex(args['connection']))
        self._logger.info("flags = %s", flags)
        addr_str = "0x"+hexlify(bytearray(args['address']))
        self._logger.debug("address = %s", addr_str)
        if (args['address_type'] ==
                ble_address_type['gap_address_type_public']):
            address_type = "public"
        elif (args['address_type'] ==
                ble_address_type['gap_address_type_random']):
            address_type = "random"
        else:
            address_type = "Bad type"
        self._logger.debug("address type = %s", address_type)
        self._logger.debug("connection interval = %f ms",
                           args['conn_interval'] * 1.25)
        self._logger.debug("timeout = %d", args['timeout'] * 10)
        self._logger.debug("latency = %d intervals", args['latency'])
        self._logger.debug("bonding = %s", hex(args['bonding']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    # FIXME: Are we using this?
    def _ble_evt_gap_scan_response(self, sender, args):
        """
        Handles the event for reporting the contents of an advertising or scan
        response packet.
        This event will occur during device discovery but not direct connection.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the RSSI value ('rssi'), packet type
                ('packet_type'), address of packet sender ('sender'), address
                type ('address_type'), existing bond handle ('bond'), and
                scan resonse data array ('data')
        """
        self._loglock.acquire()
        self._logger.info("_ble_evt_gap_scan_response")
        # for key in args:
        #    print(key, " = ", args[key])
        self._loglock.release()

    def _ble_evt_sm_bond_status(self, sender, args):
        """
        Handles the event for reporting a stored bond.

        Adds the stored bond to the list of bond handles.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the bond handle ('bond'), encryption key
                size used in the long-term key ('keysize'), was man in the
                middle used ('mitm'), keys stored for bonding ('keys')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Add to list of stored bonds found
        self._stored_bonds.append(args['bond'])

        # Notify
        self._main_thread_cond.nofity()

        # Log
        self._logger.info("_ble_evt_sm_bond_status")
        self._logger.debug("bond handle = %s", hex(args['bond']))
        self._logger.debug("keysize = %d", args['keysize'])
        self._logger.debug("man in the middle = %d", args['mitm'])
        self._logger.debug("keys = %s", hex(args['keys']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_evt_sm_bonding_fail(self, sender, args):
        """
        Handles the event for the failure to establish a bond for a connection.

        Modifies _bonding_fail and _event_return. Notifies _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._bonding_fail = True
        self._event_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_evt_sm_bonding_fail")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    # Response handlers --------------------------------------------------------
    def _ble_rsp_attclient_attribute_write(self, sender, args):
        """
        Handles the response for writing values of characteristics.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_attclient_attriute_write")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_attclient_find_information(self, sender, args):
        """
        Handles the response for characteristic discovery. Note that this only
        indicates success or failure. The find_information_found event contains
        the characteristic/descriptor information.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_attclient_find_information")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_attclient_read_by_handle(self, sender, args):
        """
        Handles the response for characteristic reads. Note that this only
        indicates success or failure. The attribute_value event contains the
        characteristic value.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_attclient_read_by_handle")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_connection_disconnect(self, sender, args):
        """
        Handles the response for connection disconnection.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_connection_disconnect")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        msg = "Disconnected by local user"
        if args['result'] != 0:
            msg = get_return_message(args['result'])
        self._logger.info("Return code = %s", msg)

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_connection_get_rssi(self, sender, args):
        """
        Handles the response that contains the RSSI for the connection.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle ('connection'),
                receiver signal strength indicator ('rssi')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['rssi']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_connection_get_rssi")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("rssi = %d", args['rssi'])

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_gap_connect_direct(self, sender, args):
        """
        Handles the response for direct connection to a device. Note that this
        only indicates success or failure of the initiation of the command. The
        the connection will not have been established until an advertising
        packet from the device is received and the connection_status received.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle
                ('connection_handle'), return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_gap_connect_direct")
        self._logger.debug("connection handle = %s",
                           hex(args['connection_handle']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    # FIXME: is this being used?
    def _ble_rsp_gap_discover(self, sender, args):
        """
        Handles the response for the start of the GAP device discovery
        procedure.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_gap_discover")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_gap_end_procedure(self, sender, args):
        """
        Handles the response for the termination of a GAP procedure (device
        discovery and scanning).

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_gap_end_procedure")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_gap_set_mode(self, sender, args):
        """
        Handles the response for the change of gap_discovererable_mode and/or
        gap_connectable_mode.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_gap_set_mode")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_gap_set_scan_parameters(self, sender, args):
        """
        Handles the response for the change of the gap scan parameters.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_gap_set_scan_parameters")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    # FIXME: bond remove
    def _ble_rsp_sm_delete_bonding(self, sender, args):
        """
        Handles the response for the deletion of a stored bond.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Remove bond
        if args['result'] == 0:
            self._stored_bonds.pop()
        self._bond_removed = True

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_sm_delete_bonding")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_sm_encrypt_start(self, sender, args):
        """
        Handles the response for the start of an encrypted connection.

        Modifies _response_received and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the connection handle ('handle'),
                return code ('result')
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_sm_encrypt_start")
        self._logger.debug("connection handle = %s",
                           hex(args['handle']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_sm_get_bonds(self, sender, args):
        """
        Handles the response for the start of stored bond enumeration. Sets
        self._num_bonds to the number of stored bonds.

        Modifies _num_bonds, _response_received, and response_return. Notifies
        _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- dictionary containing the number of stored bonds ('bonds),
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._num_bonds = args['bonds']
        self._response_received = True
        self._response_return = args['result']
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_sm_get_bonds")
        self._logger.info("num bonds = %d", args['bonds'])

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()

    def _ble_rsp_sm_set_bondable_mode(self, sender, args):
        """
        Handles the response for the change of bondable mode.

        Modifies _response_received. Notifies _main_thread_cond.

        sender -- Who fired the event. Should be the BGLib object. This is a
                  product of the event system used in BGLib.
        args -- An empty dictionary.
        """
        # Get locks
        self._main_thread_cond.acquire()
        self._loglock.acquire()

        # Set flags, notify
        self._response_received = True
        self._main_thread_cond.notify()

        # Log
        self._logger.info("_ble_rsp_set_bondable_mode")

        # Drop locks
        self._loglock.release()
        self._main_thread_cond.release()