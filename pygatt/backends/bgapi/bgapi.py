from __future__ import print_function

import logging
import Queue
import serial
import time
import threading
from binascii import hexlify, unhexlify

from pygatt.constants import LOG_FORMAT, LOG_LEVEL
from pygatt.exceptions import BluetoothLEError, NotConnectedError
from pygatt.backends.backend import BLEBackend

from . import bglib
from . import constants
from .error_codes import get_return_message


class BGAPIError(BluetoothLEError):
    pass


class Characteristic(object):
    """
    GATT characteristic. For internal use within BGAPIBackend.
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


class AdvertisingAndScanInfo(object):
    """
    Holds the advertising and scan response packet data from a device at a given
    address.
    """
    def __init__(self):
        self.name = ""
        self.address = ""
        self.rssi = None
        self.packet_data = {
            # scan_response_packet_type[xxx]: data_dictionary,
        }


class BGAPIBackend(BLEBackend):
    """
    Pygatt BLE device backend using a Bluegiga BGAPI compatible dongle.

    Only supports 1 device connection at a time.

    This object is NOT threadsafe.
    """
    def __init__(self, serial_port, run=True, logfile=None):
        """
        Initialize the BGAPI device to be ready for use with a BLE device, i.e.,
        stop ongoing procedures, disconnect any connections, optionally start
        the receiver thread, and optionally delete any stored bonds.

        serial_port -- The name of the serial port that the dongle is connected
                       to.
        run -- begin reveiving packets immediately.
        logfile -- the file to log to.
        """
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(LOG_LEVEL)
        handler = (logging.FileHandler(logfile)
                   if logfile is not None
                   else logging.NullHandler())
        formatter = logging.Formatter(fmt=LOG_FORMAT)
        handler.setLevel(LOG_LEVEL)
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)

        # Initialization
        self._lib = bglib.BGLib(loghandler=handler, loglevel=LOG_LEVEL)
        self._ser = serial.Serial(serial_port, timeout=0.25)

        self._recvr_thread = threading.Thread(target=self._recv_packets)
        self._recvr_thread_stop = threading.Event()
        self._recvr_queue = Queue.Queue()  # buffer for packets received

        # State that is locked
        self._lock = threading.Lock()
        self._callbacks = {
            # atttribute handle: callback function
        }

        # State
        self._expected_attribute_handle = None  # expected handle after a read
        self._num_bonds = 0  # number of bonds stored on the dongle
        self._stored_bonds = []  # bond handles stored on the dongle
        self._connection_handle = 0x00  # handle for the device connection
        self._devices_discovered = {
            # 'address': AdvertisingAndScanInfo,
            # Note: address formatted like "01:23:45:67:89:AB"
        }
        self._attribute_value = None  # attribute_value event value
        self._characteristics = {  # the device characteristics discovered
            # uuid_string: Characteristic()
        }
        self._characteristics_cached = False  # characteristics already found
        self._current_characteristic = None  # used in char/descriptor discovery

        # Flags
        self._event_return = 0  # event return code
        self._response_return = 0  # command response return code
        self._bonded = False  # device is bonded
        self._connected = False  # device is connected
        self._encrypted = False  # connection is encrypted
        self._bond_expected = False  # tell bond_status handler to set _bonded
        self._attribute_value_received = False  # attribute_value event occurred
        self._procedure_completed = False  # procecure_completed event occurred
        self._bonding_fail = False  # bonding with device failed

        # Packet handlers
        self._packet_handlers = {
            # Formatted as follows:
            # BGLib.PacketType.<PACKET_NAME>, BGAPIBackend.handler_function
        }
        # Set default packet handler
        for i in range(self._lib.PacketType.before_first_value+1,
                       self._lib.PacketType.after_last_value):
            self._packet_handlers[i] = self._generic_handler
        # Register needed packet handlers
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_attclient_attribute_write] =\
            self._ble_rsp_attclient_attribute_write
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_attclient_find_information] =\
            self._ble_rsp_attclient_find_information
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_attclient_read_by_handle] =\
            self._ble_rsp_attclient_read_by_handle
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_connection_disconnect] =\
            self._ble_rsp_connection_disconnect
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_connection_get_rssi] =\
            self._ble_rsp_connection_get_rssi
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_gap_connect_direct] =\
            self._ble_rsp_gap_connect_direct
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_gap_discover] =\
            self._ble_rsp_gap_discover
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_gap_end_procedure] =\
            self._ble_rsp_gap_end_procedure
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_gap_set_mode] =\
            self._ble_rsp_gap_set_mode
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_gap_set_scan_parameters] =\
            self._ble_rsp_gap_set_scan_parameters
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_sm_delete_bonding] =\
            self._ble_rsp_sm_delete_bonding
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_sm_encrypt_start] =\
            self._ble_rsp_sm_encrypt_start
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_sm_get_bonds] =\
            self._ble_rsp_sm_get_bonds
        self._packet_handlers[
            self._lib.PacketType.ble_rsp_sm_set_bondable_mode] =\
            self._ble_rsp_sm_set_bondable_mode
        self._packet_handlers[
            self._lib.PacketType.ble_evt_attclient_attribute_value] =\
            self._ble_evt_attclient_attribute_value
        self._packet_handlers[
            self._lib.PacketType.ble_evt_attclient_find_information_found] =\
            self._ble_evt_attclient_find_information_found
        self._packet_handlers[
            self._lib.PacketType.ble_evt_attclient_procedure_completed] =\
            self._ble_evt_attclient_procedure_completed
        self._packet_handlers[
            self._lib.PacketType.ble_evt_connection_status] =\
            self._ble_evt_connection_status
        self._packet_handlers[
            self._lib.PacketType.ble_evt_connection_disconnected] =\
            self._ble_evt_connection_disconnected
        self._packet_handlers[
            self._lib.PacketType.ble_evt_gap_scan_response] =\
            self._ble_evt_gap_scan_response
        self._packet_handlers[
            self._lib.PacketType.ble_evt_sm_bond_status] =\
            self._ble_evt_sm_bond_status
        self._packet_handlers[
            self._lib.PacketType.ble_evt_sm_bonding_fail] =\
            self._ble_evt_sm_bonding_fail

        # Start logging
        self._logger.info("BGAPIBackend on %s", serial_port)

        # Run the receiver thread
        if run:
            self.run()

    def bond(self):
        """
        Create a bond and encrypted connection with the device.

        This requires that a connection is already extablished with the device.
        """
        # Make sure there is a connection
        self._check_connection()

        # Set to bondable mode
        self._bond_expected = True
        self._logger.info("set_bondable_mode")
        cmd = self._lib.ble_cmd_sm_set_bondable_mode(constants.bondable['yes'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_sm_set_bondable_mode,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()

        # Begin encryption and bonding
        self._bonding_fail = False
        self._logger.info("encrypt_start")
        cmd = self._lib.ble_cmd_sm_encrypt_start(
            self._connection_handle, constants.bonding['create_bonding'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_sm_encrypt_start,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if self._response_return != 0:
            warning = "encrypt_start failed: " +\
                      get_return_message(self._response_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

        # Wait for event
        while (not self._bonding_fail) and self._connected and\
              (not self._bonded) and (not self._encrypted):
            self._process_packets_until(
                [self._lib.PacketType.ble_evt_connection_status,
                 self._lib.PacketType.ble_evt_sm_bonding_fail,
                 self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if self._bonding_fail:
            warning = "encrypt_start failed: " +\
                      get_return_message(self._event_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

    def char_write(self, handle, value, wait_for_response=False):
        """
        Write a value to a characteristic on the device.

        This requires that a connection is already extablished with the device.

        handle -- the characteristic/descriptor handle (integer) to write to.
        value -- a bytearray holding the value to write.

        Raises BGAPIError on failure.
        """
        if wait_for_response:
            raise NotImplementedError("bgapi subscribe wait for response")

        # Make sure there is a connection
        self._check_connection()

        # Write to characteristic
        value_list = [b for b in value]
        self._logger.info("attribute_write")
        cmd = self._lib.ble_cmd_attclient_attribute_write(
            self._connection_handle, handle, value_list)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_attclient_attribute_write,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if self._response_return != 0:
            warning = "attribute_write failed: " +\
                      get_return_message(self._response_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

        # Wait for event
        self._process_packets_until(
            [self._lib.PacketType.ble_evt_attclient_procedure_completed,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._procedure_completed = False
        self._check_connection()
        if self._event_return != 0:
            warning = "attribute_write failed: " +\
                      get_return_message(self._event_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

    def char_read_uuid(self, uuid):
        handle = self.get_handle(uuid)
        return self._char_read(handle)

    def _char_read(self, handle):
        """
        Read a value from a characteristic on the device.

        This requires that a connection is already established with the device.

        handle -- the characteristic handle (integer) to read from.

        Returns a bytearray containing the value read, on success.
        Raised BGAPIError on failure.
        """
        # Make sure there is a connection
        self._check_connection()

        # Read from characteristic
        self._logger.info("read_by_handle")
        self._expected_attribute_handle = handle
        cmd = self._lib.ble_cmd_attclient_read_by_handle(
            self._connection_handle, handle)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_attclient_read_by_handle,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if self._response_return != 0:
            warning = "read_by_handle failed: " +\
                      get_return_message(self._response_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

        # Reset flags
        self._attribute_value_received = False  # reset the flag
        self._procedure_completed = False  # reset the flag

        # Wait for event
        self._process_packets_until(
            [self._lib.PacketType.ble_evt_attclient_attribute_value,
             self._lib.PacketType.ble_evt_attclient_procedure_completed,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if self._procedure_completed:
            self._procedure_completed = False  # reset the flag
            warning = "read_by_handle failed: " +\
                      get_return_message(self._event_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)
        if self._attribute_value_received:
            self._attribute_value_received = False  # reset the flag
            # Return characteristic value
            return bytearray(self._attribute_value)

    def connect(self, address, timeout=5,
                addr_type=constants.ble_address_type[
                    'gap_address_type_public']):
        """
        Connnect directly to a device given the ble address then discovers and
        stores the characteristic and characteristic descriptor handles.

        Requires that the dongle is not connected to a device already.

        address -- a bytearray containing the device mac address.
        timeout -- number of seconds to wait before returning if not connected.
        addr_type -- one of the ble_address_type constants.

        Raises BGAPIError or NotConnectedError on failure.
        """
        # Make sure there is NOT a connection
        self._check_connection(check_if_connected=False)

        # Connect to the device
        bd_addr = [b for b in address]
        interval_min = 6  # 6/1.25 ms
        interval_max = 30  # 30/1.25 ms
        supervision_timeout = 20  # 20/10 ms
        latency = 0  # intervals that can be skipped
        self._logger.info("gap_connect_direct")
        self._logger.info("address = 0x%s", hexlify(address))
        self._logger.debug("interval_min = %f ms", interval_min/1.25)
        self._logger.debug("interval_max = %f ms", interval_max/1.25)
        self._logger.debug("timeout = %d ms", timeout/10)
        self._logger.debug("latency = %d intervals", latency)
        cmd = self._lib.ble_cmd_gap_connect_direct(
            bd_addr, addr_type, interval_min, interval_max, supervision_timeout,
            latency)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_gap_connect_direct])
        if self._response_return != 0:
            self._logger.warn("connect_direct failed: %s",
                              get_return_message(self._response_return))
            raise BGAPIError("Connection command failed")

        # Wait for event
        self._process_packets_until(
            [self._lib.PacketType.ble_evt_connection_status], timeout=timeout,
            exception_type=NotConnectedError)

    def delete_stored_bonds(self):
        """
        Delete the bonds stored on the dongle.

        Note: this does not delete the corresponding bond stored on the remote
              device.
        """
        # Find bonds
        self._logger.info("get_bonds")
        self._stored_bonds = []
        cmd = self._lib.ble_cmd_sm_get_bonds()
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_sm_get_bonds])
        if self._num_bonds == 0:  # no bonds
            return

        # Wait for event
        while len(self._stored_bonds) < self._num_bonds:
            self._process_packets_until(
                [self._lib.PacketType.ble_evt_sm_bond_status])

        # Delete bonds
        for b in reversed(self._stored_bonds):
            self._logger.info("delete_bonding")
            cmd = self._lib.ble_cmd_sm_delete_bonding(b)
            self._lib.send_command(self._ser, cmd)

            # Wait for response
            self._process_packets_until(
                [self._lib.PacketType.ble_rsp_sm_delete_bonding])
            if self._response_return != 0:
                self._logger.warn("delete_bonding: %s",
                                  get_return_message(self._response_return))
                raise BGAPIError("Can't delete bonding")

    def disconnect(self, fail_quietly=False):
        """
        Disconnect from the device if connected.

        fail_quietly -- do not raise an exception on failure.
        """
        # Disconnect connection
        self._logger.info("connection_disconnect")
        cmd = self._lib.ble_cmd_connection_disconnect(self._connection_handle)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_connection_disconnect])
        if self._response_return != 0:
            self._logger.warn("connection_disconnect failed: %s",
                              get_return_message(self._response_return))
            if fail_quietly:
                return
            else:
                raise BGAPIError("disconnect failed")

        # Wait for event
        self._process_packets_until(
            [self._lib.PacketType.ble_evt_connection_disconnected])
        msg = "Disconnected by local user"
        if self._event_return != 0:
            msg = get_return_message(self._event_return)
        self._logger.info("Connection disconnected: %s", msg)

    def encrypt(self):
        """
        Begin encryption on the connection with the device.

        This requires that a connection is already established with the device.

        Raises BGAPIError on failure.
        """
        # Make sure there is a connection
        self._check_connection()

        # Set to non-bondable mode
        self._logger.info("set_bondable_mode")
        cmd = self._lib.ble_cmd_sm_set_bondable_mode(constants.bondable['no'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_sm_set_bondable_mode,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()

        # Start encryption
        self._logger.info("encrypt_start")
        cmd = self._lib.ble_cmd_sm_encrypt_start(
            self._connection_handle, constants.bonding['do_not_create_bonding'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_sm_encrypt_start,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if self._response_return != 0:
            warning = "encrypt_start failed " +\
                      get_return_message(self._response_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

        # Wait for event
        self._process_packets_until(
            [self._lib.PacketType.ble_evt_connection_status,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        if not self._encrypted:
            warning = "encrypt_start failed: " +\
                      get_return_message(self._response_return)
            self._logger.warn(warning)
            raise BGAPIError(warning)

    def get_devices_discovered(self):
        """
        Get self._devices_discovered.
        A scan() should be run prior to accessing this data.

        Returns the self._devices_discovered dictionary.
        """
        # Log
        self._logger.info("get_devices_discovered")

        return self._devices_discovered

    def get_handle(self, characteristic_uuid, descriptor_uuid=None):
        """
        Get the handle (integer) for a characteristic or descriptor.

        This requires that a connection is already established with the device.

        characteristic_uuid -- bytearray containing the characteristic UUID.
        descriptor_uuid -- optional bytearray containg the GATT descriptor UUID
                           for the given characteristic. Note: use the
                           gatt_characteristic_descriptor_uuid constant.

        Returns an integer containing the handle on success.
        Raises BGAPIError on failure.
        """
        # Make sure there is a connection
        self._check_connection()

        # Discover characteristics if not cached
        if not self._characteristics_cached:
            att_handle_start = 0x0001  # first valid handle
            att_handle_end = 0xFFFF  # last valid handle
            cmd = self._lib.ble_cmd_attclient_find_information(
                self._connection_handle, att_handle_start, att_handle_end)
            self._logger.info("find_information")
            self._lib.send_command(self._ser, cmd)

            # Wait for response
            self._process_packets_until(
                [self._lib.PacketType.ble_rsp_attclient_find_information,
                 self._lib.PacketType.ble_evt_connection_disconnected])
            self._check_connection()
            if self._response_return != 0:
                warning = "find_information failed " +\
                          get_return_message(self._response_return)
                self._logger.warn(warning)
                raise BGAPIError(warning)

            # Wait for event
            self._process_packets_until(
                [self._lib.PacketType.ble_evt_attclient_procedure_completed,
                 self._lib.PacketType.ble_evt_connection_disconnected])
            self._check_connection()
            self._procedure_completed = False
            if self._event_return != 0:
                warning = "find_information failed: " +\
                          get_return_message(self._event_return)
                self._logger.warn(warning)
                raise BGAPIError(warning)
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
            warning = "No such characteristic"
            self._logger.warn(warning)
            raise BGAPIError(warning)
        char = self._characteristics[char_uuid_str]
        if descriptor_uuid is None:
            return char.handle
        desc_uuid_str = hexlify(descriptor_uuid)
        if not (desc_uuid_str in char.descriptors):
            warning = "No such descriptor"
            self._logger.warn(warning)
            raise BGAPIError(warning)
        desc_handle = char.descriptors[desc_uuid_str]
        return desc_handle

    def get_rssi(self):
        # The BGAPI has some strange behavior where it will return 25 for
        # the RSSI value sometimes... Try a maximum of 3 times.
        for i in range(0, 3):
            rssi = self._get_rssi_once()
            if rssi != 25:
                return rssi
            time.sleep(0.1)
        raise BGAPIError("get rssi failed")

    def _get_rssi_once(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        This requires that a connection is already established with the device.

        Returns the RSSI as in integer in dBm.
        """
        # Make sure there is a connection
        self._check_connection()

        # Get RSSI value
        self._logger.info("get_rssi")
        cmd = self._lib.ble_cmd_connection_get_rssi(self._connection_handle)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_connection_get_rssi,
             self._lib.PacketType.ble_evt_connection_disconnected])
        self._check_connection()
        rssi_value = self._response_return

        return rssi_value

    def run(self):
        """
        Put the interface into a known state to start. And start the recvr
        thread.
        """
        self._recvr_thread_stop.clear()
        self._recvr_thread.start()

        # Disconnect any connections
        self.disconnect(fail_quietly=True)

        # Stop advertising
        self._logger.info("gap_set_mode")
        cmd = self._lib.ble_cmd_gap_set_mode(
            constants.gap_discoverable_mode['non_discoverable'],
            constants.gap_connectable_mode['non_connectable'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_gap_set_mode])
        if self._response_return != 0:
            self._logger.warn("gap_set_mode failed: %s",
                              get_return_message(self._response_return))

        # Stop any ongoing procedure
        self._logger.info("gap_end_procedure")
        cmd = self._lib.ble_cmd_gap_end_procedure()
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_gap_end_procedure])
        if self._response_return != 0:
            self._logger.warn("gap_end_procedure failed: %s",
                              get_return_message(self._response_return))

        # Set not bondable
        self._logger.info("set_bondable_mode")
        cmd = self._lib.ble_cmd_sm_set_bondable_mode(constants.bondable['no'])
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_sm_set_bondable_mode])

    def scan(self, scan_interval=75, scan_window=50, active=True,
             scan_time=1000,
             discover_mode=constants.gap_discover_mode['generic']):
        """
        Perform a scan to discover BLE devices.

        scan_interval -- the number of miliseconds until scanning is restarted.
        scan_window -- the number of miliseconds the scanner will listen on one
                     frequency for advertisement packets.
        active -- True --> ask sender for scan response data. False --> don't.
        scan_time -- the number of miliseconds this scan should last.
        discover_mode -- one of the gap_discover_mode constants.
        """
        # Set scan parameters
        self._logger.info("set_scan_parameters")
        if active:
            active = 0x01
        else:
            active = 0x00
        # NOTE: the documentation seems to say that the times are in units of
        # 625us but the ranges it gives correspond to units of 1ms....
        cmd = self._lib.ble_cmd_gap_set_scan_parameters(
            scan_interval, scan_window, active
        )
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_gap_set_scan_parameters])
        if self._response_return != 0:
            self._logger.warn("set_scan_parameters failed: %s",
                              get_return_message(self._response_return))
            raise BGAPIError("set scan parmeters failed")

        # Begin scanning
        self._logger.info("gap_discover")
        cmd = self._lib.ble_cmd_gap_discover(discover_mode)
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_gap_discover])
        if self._response_return != 0:
            self._logger.warn("gap_discover failed: %s",
                              get_return_message(self._response_return))
            raise BGAPIError("gap discover failed")

        # Wait for scan_time
        self._logger.debug("Wait for %d ms", scan_time)
        time.sleep(scan_time/1000)

        # Stop scanning
        self._logger.info("gap_end_procedure")
        cmd = self._lib.ble_cmd_gap_end_procedure()
        self._lib.send_command(self._ser, cmd)

        # Wait for response
        self._process_packets_until(
            [self._lib.PacketType.ble_rsp_gap_end_procedure])
        if self._response_return != 0:
            self._logger.warn("gap_end_procedure failed: %s",
                              get_return_message(self._response_return))
            raise BGAPIError("gap end procedure failed")

    def subscribe(self, uuid, callback=None, indicate=False):
        """
        Ask GATT server to receive notifications from the characteristic.

        This requires that a connection is already established with the device.

        uuid -- the uuid of the characteristic to subscribe to.
        callback -- funtion to call when notified/indicated.
        indicate -- receive indications (requires application ACK) rather than
                    notifications (does not require application ACK).

        Raises BGAPIError on failure.
        """

        uuid_bytes = self._uuid_bytearray(uuid)
        characteristic_handle = self.get_handle(uuid_bytes)
        characteristic_config_handle = self.get_handle(
            uuid_bytes,
            constants.gatt_characteristic_descriptor_uuid[
                'client_characteristic_configuration'
            ])

        # Subscribe to characteristic
        config_val = [0x01, 0x00]  # Enable notifications 0x0001
        if indicate:
            config_val = [0x02, 0x00]  # Enable indications 0x0002
        self.char_write(characteristic_config_handle, config_val)

        if callback is not None:
            self._lock.acquire()
            self._callbacks[characteristic_handle] = callback
            self._lock.release()

    def stop(self):
        self.disconnect(fail_quietly=True)
        self._recvr_thread_stop.set()

    def _check_connection(self, check_if_connected=True):
        """
        Checks if there is/isn't a connection already established with a device.

        check_if_connected -- If True, checks if connected, else checks if not
                              connected.

        Raises NotConnectedError on failure if check_if_connected == True.
        Raised BGAPIError on failure if check_if_connected == False.
        """
        if (not self._connected) and check_if_connected:
            warning = "Not connected"
            self._logger.warn(warning)
            raise NotConnectedError(warning)
        elif self._connected and (not check_if_connected):
            warning = "Already connected"
            self._logger.warn(warning)
            raise BGAPIError(warning)

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
        for name, u in constants.gatt_service_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 1
        for name, u in constants.gatt_attribute_type_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 2
        for name, u in (
                constants.gatt_characteristic_descriptor_uuid.iteritems()):
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 3
        for name, u in constants.gatt_characteristic_type_uuid.iteritems():
            if u == uuid:
                self._logger.debug("match %s", name + ": 0x" + hexlify(u))
                return 4
        self._logger.debug("no match")
        return -1

    def _scan_rsp_data(self, data):
        """
        Parse scan response data.
        Note: the data will come in a format like the following:
        [data_length, data_type, data..., data_length, data_type, data...]

        data -- the args['data'] list from _ble_evt_scan_response.

        Returns a name and a dictionary containing the parsed data in pairs of
        field_name': value.
        """
        # Result stored here
        data_dict = {
            # 'name': value,
        }
        bytes_left_in_field = 0
        field_name = None
        field_value = []
        # Iterate over data bytes to put in field
        dev_name = ""
        for b in data:
            if bytes_left_in_field == 0:
                # New field
                bytes_left_in_field = b
                field_value = []
            else:
                field_value.append(b)
                bytes_left_in_field -= 1
                if bytes_left_in_field == 0:
                    # End of field
                    field_name = (
                        constants.scan_response_data_type[field_value[0]])
                    field_value = field_value[1:]
                    # Field type specific formats
                    if field_name == 'complete_local_name' or\
                            field_name == 'shortened_local_name':
                        dev_name = bytearray(field_value).decode("utf-8")
                        data_dict[field_name] = dev_name
                    elif field_name ==\
                            'complete_list_128-bit_service_class_uuids':
                        data_dict[field_name] = []
                        for i in range(0, len(field_value)/16):  # 16 bytes
                            service_uuid = '0x'+hexlify(bytearray(list(reversed(
                                field_value[i*16:i*16+16]))))
                            data_dict[field_name].append(service_uuid)
                    else:
                        data_dict[field_name] = bytearray(field_value)
        return dev_name, data_dict

    def _process_packets_until(self, expected_packet_choices, timeout=None,
                               exception_type=BGAPIError):
        """
        Process packets until a packet of one of the expected types is found.

        expected_packet_choices -- a list of BGLib.PacketType.xxxxx. Upon
                                   processing a packet of a type contained in
                                   the list, this function will return.
        timeout -- maximum time in seconds to process packets.

        exception_type -- the type of exception to raise if a timeout occurs.

        Raises an exception of exception_type if a timeout occurs.
        """
        # Log
        epc_str = ""
        for pt in expected_packet_choices:
            epc_str += '{0} '.format(pt)
        self._logger.info("process packets until " + epc_str)

        start_time = None
        if timeout is not None:
            start_time = time.time()

        found = False
        while not found:
            # Get packet from queue
            packet = None
            try:
                packet = self._recvr_queue.get(block=True, timeout=0.1)
            except Queue.Empty:
                if timeout is not None:
                    elapsed_time = time.time() - start_time
                    if elapsed_time >= timeout:
                        raise exception_type(
                            "timed out after %d seconds" % elapsed_time)
                    continue

            # Process packet
            self._logger.debug("got packet")
            packet_type, args = self._lib.decode_packet(packet)
            self._logger.debug('packet type {0}'.format(packet_type))
            if packet_type in expected_packet_choices:
                found = True
            # Call handler for this packet
            if packet_type in self._packet_handlers:
                self._logger.debug("Calling handler " +
                                   self._packet_handlers[packet_type].__name__)
                self._packet_handlers[packet_type](args)

        # Log
        self._logger.debug("done processing packets")

    def _recv_packets(self):
        """
        Read bytes from serial and enqueue the packets if the packet is not a.
        Stops if the self._recvr_thread_stop event is set.
        """
        att_value = self._lib.PacketType.ble_evt_attclient_attribute_value
        while not self._recvr_thread_stop.is_set():
            byte = self._ser.read()
            if len(byte) > 0:
                byte = ord(byte)
                packet = self._lib.parse_byte(byte)
                if packet is not None:
                    packet_type, args = self._lib.decode_packet(packet)

                    self._lock.acquire()
                    callbacks = dict(self._callbacks)
                    self._lock.release()
                    handles_subscribed_to = callbacks.keys()

                    if packet_type != att_value:
                        self._recvr_queue.put(packet, block=True, timeout=0.1)
                    elif args['atthandle'] in handles_subscribed_to:
                        # This is a notification/indication. Handle now.
                        callback_exists = (args['atthandle'] in callbacks)
                        if callback_exists:
                            self._logger.debug(
                                "Calling callback " +
                                callbacks[args['atthandle']].__name__)
                            threading.Thread(
                                target=callbacks[args['atthandle']],
                                args=(bytearray(args['value']),)).start()
                    else:
                        self._recvr_queue.put(packet, block=True, timeout=0.1)

    # Generic event/response handler -------------------------------------------
    def _generic_handler(self, args):
        """
        Generic event/response handler. Used for receiving packets from the
        interface that don't need any specific action taken.

        args -- dictionary containing the parameters for the event/response
                given in the Bluegia Bluetooth Smart Software API.
        """
        self._logger.warn("Unhandled packet type.")

    # Event handlers -----------------------------------------------------------
    def _ble_evt_attclient_attribute_value(self, args):
        """
        Handles the event for values of characteristics.

        args -- dictionary containing the connection handle ('connection'),
                attribute handle ('atthandle'), attribute type ('type'),
                and attribute value ('value')
        """
        # Set flags, record info
        self._attribute_value_received = True
        self._attribute_value = args['value']

        # Log
        self._logger.info("_ble_evt_attclient_attriute_value")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("attribute handle = %s", hex(args['atthandle']))
        self._logger.debug("attribute type = %s", hex(args['type']))
        self._logger.debug("attribute value = %s",
                           hexlify(bytearray(args['value'])))

    def _ble_evt_attclient_find_information_found(self, args):
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

        args -- dictionary containing the connection handle ('connection'),
                characteristic handle ('chrhandle'), and characteristic UUID
                ('uuid')
        """
        uuid = bytearray(list(reversed(args['uuid'])))
        uuid_str = "0x"+hexlify(uuid)

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

    def _ble_evt_attclient_procedure_completed(self, args):
        """
        Handles the event for completion of writes to remote device.

        args -- dictionary containing the connection handle ('connection'),
                return code ('result'), characteristic handle ('chrhandle')
        """
        # Log
        self._logger.info("_ble_evt_attclient_procedure_completed")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("characteristic handle = %s", hex(args['chrhandle']))
        self._logger.info("return code = %s",
                          get_return_message(args['result']))

        # Set flag, return value
        self._procedure_completed = True
        self._event_return = args['result']

    def _ble_evt_connection_disconnected(self, args):
        """
        Handles the event for the termination of a connection.

        args -- dictionary containing the connection handle ('connection'),
                return code ('reason')
        """
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

    def _ble_evt_connection_status(self, args):
        """
        Handles the event for reporting connection parameters.

        args -- dictionary containing the connection handle ('connection'),
                connection status flags ('flags'), device address ('address'),
                device address type ('address_type'), connection interval
                ('conn_interval'), connection timeout (timeout'), device latency
                ('latency'), device bond handle ('bonding')
        """
        # Set flags, notify
        self._connection_handle = args['connection']
        flags = ""
        if self._connection_status_flag(
                args['flags'], constants.connection_status_flag['connected']):
            self._connected = True
            flags += 'connected, '
        if self._connection_status_flag(
                args['flags'], constants.connection_status_flag['encrypted']):
            self._encrypted = True
            flags += 'encrypted, '
        if self._connection_status_flag(
                args['flags'], constants.connection_status_flag['completed']):
            flags += 'completed, '
        if self._connection_status_flag(
                args['flags'],
                constants.connection_status_flag['parameters_change']):
            flags += 'parameters_change, '

        # Log
        self._logger.info("_ble_evt_connection_status")
        self._logger.debug("connection = %s", hex(args['connection']))
        self._logger.info("flags = %s", flags)
        addr_str = "0x"+hexlify(bytearray(args['address']))
        self._logger.debug("address = %s", addr_str)
        if (args['address_type'] ==
                constants.ble_address_type['gap_address_type_public']):
            address_type = "public"
        elif (args['address_type'] ==
                constants.ble_address_type['gap_address_type_random']):
            address_type = "random"
        else:
            address_type = "Bad type"
        self._logger.debug("address type = %s", address_type)
        self._logger.debug("connection interval = %f ms",
                           args['conn_interval'] * 1.25)
        self._logger.debug("timeout = %d", args['timeout'] * 10)
        self._logger.debug("latency = %d intervals", args['latency'])
        self._logger.debug("bonding = %s", hex(args['bonding']))

    def _ble_evt_gap_scan_response(self, args):
        """
        Handles the event for reporting the contents of an advertising or scan
        response packet.
        This event will occur during device discovery but not direct connection.

        args -- dictionary containing the RSSI value ('rssi'), packet type
                ('packet_type'), address of packet sender ('sender'), address
                type ('address_type'), existing bond handle ('bond'), and
                scan resonse data list ('data')
        """
        # Parse packet
        packet_type = constants.scan_response_packet_type[args['packet_type']]
        address = ":".join(list(reversed(
            [format(b, '02x') for b in args['sender']])))
        address_type = "unknown"
        for name, value in constants.ble_address_type.iteritems():
            if value == args['address_type']:
                address_type = name
                break
        name, data_dict = self._scan_rsp_data(args['data'])

        # Store device information
        if address not in self._devices_discovered:
            self._devices_discovered[address] = AdvertisingAndScanInfo()
        dev = self._devices_discovered[address]
        if dev.name == "":
            dev.name = name
        if dev.address == "":
            dev.address = address
        if (packet_type not in dev.packet_data) or\
                len(dev.packet_data[packet_type]) < len(data_dict):
            dev.packet_data[packet_type] = data_dict
        dev.rssi = args['rssi']

        # Log
        self._logger.info("_ble_evt_gap_scan_response")
        self._logger.debug("rssi = %d dBm", args['rssi'])
        self._logger.debug("packet type = %s", packet_type)
        self._logger.info("sender address = %s", address)
        self._logger.debug("address type = %s", address_type)
        self._logger.debug("data %s", str(data_dict))

    def _ble_evt_sm_bond_status(self, args):
        """
        Handles the event for reporting a stored bond.

        Adds the stored bond to the list of bond handles if no _bond_expected.
        Sets _bonded True if _bond_expected.

        args -- dictionary containing the bond handle ('bond'), encryption key
                size used in the long-term key ('keysize'), was man in the
                middle used ('mitm'), keys stored for bonding ('keys')
        """
        # Add to list of stored bonds found or set flag
        if self._bond_expected:
            self._bond_expected = False
            self._bonded = True
        else:
            self._stored_bonds.append(args['bond'])

        # Log
        self._logger.info("_ble_evt_sm_bond_status")
        self._logger.debug("bond handle = %s", hex(args['bond']))
        self._logger.debug("keysize = %d", args['keysize'])
        self._logger.debug("man in the middle = %d", args['mitm'])
        self._logger.debug("keys = %s", hex(args['keys']))

    def _ble_evt_sm_bonding_fail(self, args):
        """
        Handles the event for the failure to establish a bond for a connection.

        args -- dictionary containing the return code ('result')
        """
        # Set flags
        self._bonding_fail = True
        self._event_return = args['result']

        # Log
        self._logger.info("_ble_evt_sm_bonding_fail")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    # Response handlers --------------------------------------------------------
    def _ble_rsp_attclient_attribute_write(self, args):
        """
        Handles the response for writing values of characteristics.

        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_attclient_attriute_write")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_attclient_find_information(self, args):
        """
        Handles the response for characteristic discovery. Note that this only
        indicates success or failure. The find_information_found event contains
        the characteristic/descriptor information.

        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_attclient_find_information")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_attclient_read_by_handle(self, args):
        """
        Handles the response for characteristic reads. Note that this only
        indicates success or failure. The attribute_value event contains the
        characteristic value.

        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_attclient_read_by_handle")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_connection_disconnect(self, args):
        """
        Handles the response for connection disconnection.

        args -- dictionary containing the connection handle ('connection'),
                return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_connection_disconnect")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        msg = "Disconnected by local user"
        if args['result'] != 0:
            msg = get_return_message(args['result'])
        self._logger.info("Return code = %s", msg)

    def _ble_rsp_connection_get_rssi(self, args):
        """
        Handles the response that contains the RSSI for the connection.

        args -- dictionary containing the connection handle ('connection'),
                receiver signal strength indicator ('rssi')
        """
        # Set flags
        self._response_return = args['rssi']

        # Log
        self._logger.info("_ble_rsp_connection_get_rssi")
        self._logger.debug("connection handle = %s", hex(args['connection']))
        self._logger.debug("rssi = %d", args['rssi'])

    def _ble_rsp_gap_connect_direct(self, args):
        """
        Handles the response for direct connection to a device. Note that this
        only indicates success or failure of the initiation of the command. The
        the connection will not have been established until an advertising
        packet from the device is received and the connection_status received.

        args -- dictionary containing the connection handle
                ('connection_handle'), return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_gap_connect_direct")
        self._logger.debug("connection handle = %s",
                           hex(args['connection_handle']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_gap_discover(self, args):
        """
        Handles the response for the start of the GAP device discovery
        procedure.

        args -- dictionary containing the return code ('result')
        """
        # Set flags, notify
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_gap_discover")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_gap_end_procedure(self, args):
        """
        Handles the response for the termination of a GAP procedure (device
        discovery and scanning).

        args -- dictionary containing the return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_gap_end_procedure")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_gap_set_mode(self, args):
        """
        Handles the response for the change of gap_discovererable_mode and/or
        gap_connectable_mode.

        args -- dictionary containing the return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_gap_set_mode")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_gap_set_scan_parameters(self, args):
        """
        Handles the response for the change of the gap scan parameters.

        args -- dictionary containing the return code ('result')
        """
        # Set flags, notify
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_gap_set_scan_parameters")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_sm_delete_bonding(self, args):
        """
        Handles the response for the deletion of a stored bond.

        args -- dictionary containing the return code ('result')
        """
        # Remove bond
        if args['result'] == 0:
            self._stored_bonds.pop()

        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_sm_delete_bonding")
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_sm_encrypt_start(self, args):
        """
        Handles the response for the start of an encrypted connection.

        args -- dictionary containing the connection handle ('handle'),
                return code ('result')
        """
        # Set flags
        self._response_return = args['result']

        # Log
        self._logger.info("_ble_rsp_sm_encrypt_start")
        self._logger.debug("connection handle = %s",
                           hex(args['handle']))
        self._logger.info("Return code = %s",
                          get_return_message(args['result']))

    def _ble_rsp_sm_get_bonds(self, args):
        """
        Handles the response for the start of stored bond enumeration. Sets
        self._num_bonds to the number of stored bonds.

        args -- dictionary containing the number of stored bonds ('bonds),
        """
        # Set flags
        self._num_bonds = args['bonds']

        # Log
        self._logger.info("_ble_rsp_sm_get_bonds")
        self._logger.info("num bonds = %d", args['bonds'])

    def _ble_rsp_sm_set_bondable_mode(self, args):
        """
        Handles the response for the change of bondable mode.

        args -- An empty dictionary.
        """
        # Log
        self._logger.info("_ble_rsp_set_bondable_mode")

    def _uuid_bytearray(self, uuid):
        """
        Turns a UUID string in the format "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        to a bytearray.

        uuid -- the UUID to convert.

        Returns a bytearray containing the UUID.
        """
        self._logger.info("_uuid_bytearray %s", uuid)
        return unhexlify(uuid.replace("-", ""))
