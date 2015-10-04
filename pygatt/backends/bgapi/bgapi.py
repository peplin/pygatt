from __future__ import print_function

import logging
import Queue
import serial
import time
import threading
from binascii import hexlify
from uuid import UUID
from enum import Enum
from collections import defaultdict

from pygatt.exceptions import BLEError, NotConnectedError
from pygatt.backends import BLEBackend, Characteristic
from pygatt.util import uuid16_to_uuid

from . import bglib, constants
from .bglib import EventPacketType, ResponsePacketType
from .packets import BGAPICommandPacketBuilder as CommandBuilder
from .error_codes import get_return_message, ErrorCode
from .util import find_usb_serial_devices

log = logging.getLogger(__name__)

BLED112_VENDOR_ID = 0x2458
BLED112_PRODUCT_ID = 0x0001


UUIDType = Enum('UUIDType', ['custom', 'service', 'attribute',
                             'descriptor', 'characteristic'])


class BGAPIError(BLEError):
    pass


class ExpectedResponseTimeout(BGAPIError):
    def __init__(self, expected_packets, timeout):
        super(ExpectedResponseTimeout, self).__init__(
            "Timed out after %fs waiting for %s" % (
                timeout or 0, expected_packets))


def valid_connection_handle_required(func):
    def wrapper(self, connection_handle, *args, **kwargs):
        if connection_handle not in self._connections:
            raise NotConnectedError()
        return func(self, connection_handle, *args, **kwargs)
    return wrapper


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
    def __init__(self, serial_port=None):
        """
        Initialize the BGAPI device to be ready for use with a BLE device, i.e.,
        stop ongoing procedures, disconnect any connections, optionally start
        the receiver thread, and optionally delete any stored bonds.

        serial_port -- The name of the serial port for the BGAPI-compatible
        USB interface.
        """
        self._lib = bglib.BGLib()
        if serial_port is None:
            log.info("Auto-discovering serial port for BLED112")
            detected_devices = find_usb_serial_devices(
                vendor_id=BLED112_VENDOR_ID,
                product_id=BLED112_PRODUCT_ID)
            if len(detected_devices) > 0:
                serial_port = detected_devices[0].port_name
            else:
                raise BGAPIError("Unable to auto-detect BLED112 serial port")
        self._serial_port = serial_port

        self._ser = None
        self._receiver = None
        self._running = None

        # buffer for packets received
        self._receiver_queue = Queue.Queue()

        # State
        self._num_bonds = 0  # number of bonds stored on the dongle
        self._stored_bonds = []  # bond handles stored on the dongle
        self._devices_discovered = {
            # 'address': AdvertisingAndScanInfo,
            # Note: address formatted like "01:23:45:67:89:AB"
        }
        self._characteristics = defaultdict(dict)
        self._connections = {}

        self._current_characteristic = None  # used in char/descriptor discovery
        self._packet_handlers = {
            ResponsePacketType.sm_get_bonds: self._ble_rsp_sm_get_bonds,
            EventPacketType.attclient_attribute_value: (
                self._ble_evt_attclient_attribute_value),
            EventPacketType.attclient_find_information_found: (
                self._ble_evt_attclient_find_information_found),
            EventPacketType.connection_status: self._ble_evt_connection_status,
            EventPacketType.connection_disconnected: (
                self._ble_evt_connection_disconnected),
            EventPacketType.gap_scan_response: self._ble_evt_gap_scan_response,
            EventPacketType.sm_bond_status: self._ble_evt_sm_bond_status,
        }

        log.info("Initialized new BGAPI backend on %s", serial_port)

    def start(self):
        """
        Put the interface into a known state to start. And start the receiver
        thread.
        """
        if self._running and self._running.is_set():
            self.stop()

        self._ser = serial.Serial(self._serial_port, baudrate=256000,
                                  timeout=0.25)
        self._receiver = threading.Thread(target=self._receive)
        self._receiver.daemon = True

        self._running = threading.Event()
        self._running.set()
        self._receiver.start()

        self.disable_advertising()

        # Stop any ongoing procedure
        log.info("Stopping any outstanding GAP procedure")
        self._send_command(CommandBuilder.gap_end_procedure())
        try:
            self.expect(ResponsePacketType.gap_end_procedure)
        except BGAPIError:
            # Ignore any errors if there was no GAP procedure running
            pass

    def stop(self):
        for connection_handle in self._connections.keys():
            self.disconnect(connection_handle, fail_quietly=True)
        if self._running.is_set():
            log.info('Stopping')
        self._running.clear()

        if self._receiver:
            self._receiver.join()
        self._receiver = None

        if self._ser:
            self._ser.close()
            self._ser = None

    def disable_advertising(self):
        log.info("Disabling advertising")
        self._send_command(
            CommandBuilder.gap_set_mode(
                constants.gap_discoverable_mode['non_discoverable'],
                constants.gap_connectable_mode['non_connectable']))
        self.expect(ResponsePacketType.gap_set_mode)

    def _send_command(self, *args, **kwargs):
        if self._ser is None:
            log.warn("Unexpectedly not connected to USB device")
            raise NotConnectedError()
        return self._lib.send_command(self._ser, *args, **kwargs)

    def clear_bond(self, address=None):
        """
        Delete the bonds stored on the dongle.

        Note: this does not delete the corresponding bond stored on the remote
              device.
        """
        # Find bonds
        log.debug("Fetching existing bonds for devices")
        self._stored_bonds = []
        self._send_command(CommandBuilder.sm_get_bonds())

        try:
            self.expect(ResponsePacketType.sm_get_bonds)
        except NotConnectedError:
            pass

        if self._num_bonds == 0:
            return

        while len(self._stored_bonds) < self._num_bonds:
            self.expect(EventPacketType.sm_bond_status)

        for b in reversed(self._stored_bonds):
            log.info("Deleting bond %s", b)

            self._send_command(CommandBuilder.sm_delete_bonding(b))
            self.expect(ResponsePacketType.sm_delete_bonding)

    def scan(self, timeout=10, scan_interval=75, scan_window=50, active=True,
             discover_mode=constants.gap_discover_mode['observation']):
        """
        Perform a scan to discover BLE devices.

        scan_interval -- the number of miliseconds until scanning is restarted.
        scan_window -- the number of miliseconds the scanner will listen on one
                     frequency for advertisement packets.
        active -- True --> ask sender for scan response data. False --> don't.
        timeout -- the number of seconds this scan should last.
        discover_mode -- one of the gap_discover_mode constants.
        """
        parameters = 1 if active else 0
        # NOTE: the documentation seems to say that the times are in units of
        # 625us but the ranges it gives correspond to units of 1ms....
        self._send_command(
            CommandBuilder.gap_set_scan_parameters(
                scan_interval, scan_window, parameters
            ))

        self.expect(ResponsePacketType.gap_set_scan_parameters)

        log.info("Starting an %s scan", "active" if active else "passive")
        self._send_command(CommandBuilder.gap_discover(discover_mode))

        self.expect(ResponsePacketType.gap_discover)

        log.debug("Pausing for for %ds to allow scan to complete", timeout)
        time.sleep(timeout)

        log.info("Stopping scan")
        self._send_command(CommandBuilder.gap_end_procedure())
        self.expect(ResponsePacketType.gap_end_procedure)

        devices = []
        for address, info in self._devices_discovered.iteritems():
            devices.append({
                'address': address,
                'name': info.name,
                'rssi': info.rssi
            })
        return devices

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
        for handle, address in self._connections.iteritems():
            if address == address:
                return handle

        address_bytes = [int(b, 16) for b in address.split(":")]
        interval_min = 60
        interval_max = 76
        supervision_timeout = 100
        latency = 0  # intervals that can be skipped
        log.debug("Connecting to device at address %s (timeout %ds)",
                  address, timeout)
        self._send_command(
            CommandBuilder.gap_connect_direct(
                address_bytes, addr_type, interval_min, interval_max,
                supervision_timeout, latency))

        self.expect(ResponsePacketType.gap_connect_direct)
        try:
            _, packet = self.expect(EventPacketType.connection_status,
                                    timeout=timeout)
            # TODO should really check that it's a connected status, and for the
            # right address.
            handle = packet['connection_handle']
            self._connections[handle] = {
                'address': address
            }
            log.debug("Connected to %s", address)
            return handle
        except ExpectedResponseTimeout:
            raise NotConnectedError()

    @valid_connection_handle_required
    def disconnect(self, connection_handle, fail_quietly=False):
        """
        Disconnect from the device if connected.

        fail_quietly -- do not raise an exception on failure.
        """
        address = self._connections[connection_handle]
        log.debug("Disconnecting from %s", address)
        self._send_command(
            CommandBuilder.connection_disconnect(connection_handle))

        try:
            self.expect(ResponsePacketType.connection_disconnect)
        except (BGAPIError, NotConnectedError):
            if not fail_quietly:
                raise
        self._connections.pop(connection_handle, None)
        log.info("Disconnected from %s", address)

    @valid_connection_handle_required
    def bond(self, connection_handle):
        """
        Create a bond and encrypted connection with the device.

        This requires that a connection is already extablished with the device.
        """

        # Set to bondable mode so bonds are store permanently
        self._send_command(
            CommandBuilder.sm_set_bondable_mode(constants.bondable['yes']))
        self.expect(ResponsePacketType.sm_set_bondable_mode)

        address = self._connections[connection_handle]['address']
        log.info("Bonding to %s", address)
        self._send_command(
            CommandBuilder.sm_encrypt_start(
                connection_handle, constants.bonding['create_bonding']))
        self.expect(ResponsePacketType.sm_encrypt_start)

        while (connection_handle in self._connections and
               not self._connections[connection_handle].get('encrypted', None)):
            packet_type, response = self.expect_any(
                [EventPacketType.connection_status,
                 EventPacketType.sm_bonding_fail])
            if packet_type == EventPacketType.sm_bonding_fail:
                raise BGAPIError("Bonding failed")

    @valid_connection_handle_required
    def discover_characteristics(self, connection_handle):
        att_handle_start = 0x0001  # first valid handle
        att_handle_end = 0xFFFF  # last valid handle
        log.info("Fetching characteristics for connection %d",
                 connection_handle)
        self._send_command(
            CommandBuilder.attclient_find_information(
                connection_handle, att_handle_start, att_handle_end))

        self.expect(ResponsePacketType.attclient_find_information)
        self.expect(EventPacketType.attclient_procedure_completed,
                    timeout=10)

        for char_uuid_str, char_obj in (
                self._characteristics[connection_handle].iteritems()):
            log.debug("Characteristic 0x%s is handle 0x%x",
                      char_uuid_str, char_obj.handle)
            for desc_uuid_str, desc_handle in (
                    char_obj.descriptors.iteritems()):
                log.debug("Characteristic descriptor 0x%s is handle %x",
                          desc_uuid_str, desc_handle)
        return self._characteristics[connection_handle]

    @valid_connection_handle_required
    def char_write(self, connection_handle, handle, value,
                   wait_for_response=False):
        """
        Write a value to a characteristic on the device.

        This requires that a connection is already extablished with the device.

        handle -- the characteristic/descriptor handle (integer) to write to.
        value -- a bytearray holding the value to write.

        Raises BGAPIError on failure.
        """
        if wait_for_response:
            raise NotImplementedError("bgapi subscribe wait for response")

        while True:
            value_list = [b for b in value]
            log.info("attribute_write")
            self._send_command(
                CommandBuilder.attclient_attribute_write(
                    connection_handle, handle, value_list))

            self.expect(ResponsePacketType.attclient_attribute_write)
            packet_type, response = self.expect(
                EventPacketType.attclient_procedure_completed)
            if (response['result'] !=
                    ErrorCode.insufficient_authentication.value):
                # Continue to retry until we are bonded
                break

    @valid_connection_handle_required
    def _char_read(self, connection_handle, handle):
        """
        Read a value from a characteristic on the device.

        This requires that a connection is already established with the device.

        handle -- the characteristic handle (integer) to read from.

        Returns a bytearray containing the value read, on success.
        Raised BGAPIError on failure.
        """
        log.info("Reading characteristic at handle %d", handle)
        self._send_command(
            CommandBuilder.attclient_read_by_handle(
                connection_handle, handle))

        self.expect(ResponsePacketType.attclient_read_by_handle)
        matched_packet_type, response = self.expect_any(
            [EventPacketType.attclient_attribute_value,
             EventPacketType.attclient_procedure_completed])
        # TODO why not just expect *only* the attribute value response, then it
        # would time out and raise an exception if allwe got was the 'procedure
        # completed' response?
        if matched_packet_type != EventPacketType.attclient_attribute_value:
            raise BGAPIError("Unable to read characteristic")
        return bytearray(response['value'])

    @valid_connection_handle_required
    def get_rssi(self, connection_handle):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        This requires that a connection is already established with the device.

        Returns the RSSI as in integer in dBm.
        """
        # The BGAPI has some strange behavior where it will return 25 for
        # the RSSI value sometimes... Try a maximum of 3 times.
        for i in range(0, 3):
            self._send_command(
                CommandBuilder.connection_get_rssi(connection_handle))
            _, response = self.expect(ResponsePacketType.connection_get_rssi)
            rssi = response['rssi']
            if rssi != 25:
                return rssi
            time.sleep(0.1)
        raise BGAPIError("get rssi failed")

    @staticmethod
    def _connection_status_flag(flags, flag_to_find):
        """
        Is the given flag in the connection status flags?

        flags -- the 'flags' parameter returned by ble_evt_connection_status.
        flag_to_find -- the flag to look for in flags.

        Returns true if flag_to_find is in flags. Returns false otherwise.
        """
        return (flags & flag_to_find) == flag_to_find

    @staticmethod
    def _get_uuid_type(uuid):
        """
        Checks if the UUID is a custom 128-bit UUID or a GATT characteristic
        descriptor UUID.

        uuid -- the UUID as a bytearray.

        Return a UUIDType.
        """
        if len(uuid) == 16:  # 128-bit --> 16 byte
            return UUIDType.custom
        if uuid in constants.gatt_service_uuid.values():
            return UUIDType.service
        if uuid in constants.gatt_attribute_type_uuid.values():
            return UUIDType.attribute
        if uuid in constants.gatt_characteristic_descriptor_uuid.values():
            return UUIDType.descriptor
        if uuid in constants.gatt_characteristic_type_uuid.values():
            return UUIDType.characteristic
        log.warn("UUID %s is of unknown type", hexlify(uuid))
        return None

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
                    if (field_name == 'complete_local_name' or
                            field_name == 'shortened_local_name'):
                        dev_name = bytearray(field_value).decode("utf-8")
                        data_dict[field_name] = dev_name
                    elif (field_name ==
                          'complete_list_128-bit_service_class_uuids'):
                        data_dict[field_name] = []
                        for i in range(0, len(field_value)/16):  # 16 bytes
                            service_uuid = '0x'+hexlify(bytearray(list(reversed(
                                field_value[i*16:i*16+16]))))
                            data_dict[field_name].append(service_uuid)
                    else:
                        data_dict[field_name] = bytearray(field_value)
        return dev_name, data_dict

    def expect(self, expected, *args, **kargs):
        return self.expect_any([expected], *args, **kargs)

    def expect_any(self, expected_packet_choices, timeout=None,
                   assert_return_success=True):
        """
        Process packets until a packet of one of the expected types is found.

        expected_packet_choices -- a list of BGLib.PacketType.xxxxx. Upon
                                   processing a packet of a type contained in
                                   the list, this function will return.
        timeout -- maximum time in seconds to process packets.
        assert_return_success -- raise an exception if the return code from a
            matched message is non-zero.

        Raises an ExpectedResponseTimeout if one of the expected responses is
            not receiving withint the time limit.
        """
        timeout = timeout or 1
        log.info("Expecting a response of one of %s within %fs",
                 expected_packet_choices, timeout or 0)

        start_time = None
        if timeout is not None:
            start_time = time.time()

        while True:
            packet = None
            try:
                # TODO can we increase the timeout here?
                packet = self._receiver_queue.get(timeout=0.1)
            except Queue.Empty:
                if timeout is not None:
                    if time.time() - start_time > timeout:
                        raise ExpectedResponseTimeout(
                            expected_packet_choices, timeout)
                    continue

            if packet is None:
                raise ExpectedResponseTimeout(expected_packet_choices, timeout)

            packet_type, response = self._lib.decode_packet(packet)
            return_code = response.get('result', 0)
            log.debug("Received a %s packet: %s",
                      packet_type, get_return_message(return_code))

            if packet_type in self._packet_handlers:
                self._packet_handlers[packet_type](response)

            if packet_type in expected_packet_choices:
                return packet_type, response

    def _receive(self):
        """
        Read bytes from serial and enqueue the packets if the packet is not a.
        Stops if the self._running event is not set.
        """
        log.info("Running receiver")
        while self._running.is_set():
            byte = self._ser.read()
            if len(byte) > 0:
                byte = ord(byte)
                packet = self._lib.parse_byte(byte)
                if packet is not None:
                    packet_type, args = self._lib.decode_packet(packet)
                    if packet_type == EventPacketType.attclient_attribute_value:
                        # TODO need to check connection handle, then call a
                        # calback on each connection handle get to the
                        # BLEdevice's handle_notification function
                        # self._handle_notification(args['atthandle'],
                                                  # bytearray(args['value']))
                        pass
                    self._receiver_queue.put(packet)
        log.info("Stopping receiver")

    def _ble_evt_attclient_attribute_value(self, args):
        """
        Handles the event for values of characteristics.

        args -- dictionary containing the attribute handle ('atthandle'),
        attribute type ('type'), and attribute value ('value')
        """
        log.debug("attribute handle = %x", args['atthandle'])
        log.debug("attribute type = %x", args['type'])
        log.debug("attribute value = 0x%s", hexlify(bytearray(args['value'])))

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

        args -- dictionary containing the characteristic handle ('chrhandle'),
        and characteristic UUID ('uuid')
        """
        raw_uuid = bytearray(reversed(args['uuid']))
        uuid_type = self._get_uuid_type(raw_uuid)
        if uuid_type != UUIDType.custom:
            uuid = uuid16_to_uuid(
                int(hexlify(bytearray(reversed(args['uuid']))), 16))
        else:
            uuid = UUID(hexlify(raw_uuid))

        # TODO is there a way to get the characteristic from the packet instead
        # of having to track the "current" characteristic?
        if (uuid_type == UUIDType.descriptor and
                self._current_characteristic is not None):
            self._current_characteristic.add_descriptor(uuid, args['chrhandle'])
        elif uuid_type == UUIDType.custom:
            log.debug("Found custom characteristic %s" % uuid)
            new_char = Characteristic(uuid, args['chrhandle'])
            self._current_characteristic = new_char
            self._characteristics[
                args['connection_handle']][uuid] = new_char

    def _ble_evt_connection_disconnected(self, args):
        """
        Handles the event for the termination of a connection.
        """
        self._connections.pop(args['connection_handle'], None)
        # TODO do we need to raise this? what if it's expected to be
        # disconnected now?
        raise NotConnectedError()

    def _ble_evt_connection_status(self, args):
        """
        Handles the event for reporting connection status.

        args -- dictionary containing the connection status flags ('flags'),
            device address ('address'), device address type ('address_type'),
            connection interval ('conn_interval'), connection timeout
            (timeout'), device latency ('latency'), device bond handle
            ('bonding')
        """
        connection_handle = args['connection_handle']

        address_type = "unknown"
        if (args['address_type'] ==
                constants.ble_address_type['gap_address_type_public']):
            address_type = "public"
        elif (args['address_type'] ==
                constants.ble_address_type['gap_address_type_random']):
            address_type = "random"

        if self._connection_status_flag(
                args['flags'],
                constants.connection_status_flag['connected']):
            self._connections[connection_handle] = {
                'address': args['address'],
                'encrypted': False,
                'address_type': address_type
            }

            if self._connection_status_flag(
                    args['flags'],
                    constants.connection_status_flag['encrypted']):
                self._connections[connection_handle]['encrypted'] = True
        else:
            self._connections.pop(connection_handle, None)

        log.info("Connection status: handle=0x%x, flags=%s, address=0x%s, "
                 "address_type=%s, connection interval=%fms, timeout=%d, "
                 "latency=%d intervals, bonding=0x%x",
                 connection_handle,
                 self._connections[connection_handle]['address'],
                 hexlify(bytearray(args['address'])),
                 address_type,
                 args['conn_interval'] * 1.25,
                 args['timeout'] * 10,
                 args['latency'],
                 args['bonding'])

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
        name, data_dict = self._scan_rsp_data(args['data'])

        # Store device information
        if address not in self._devices_discovered:
            self._devices_discovered[address] = AdvertisingAndScanInfo()
        dev = self._devices_discovered[address]
        if dev.name == "":
            dev.name = name
        if dev.address == "":
            dev.address = address
        if (packet_type not in dev.packet_data or
                len(dev.packet_data[packet_type]) < len(data_dict)):
            dev.packet_data[packet_type] = data_dict
        dev.rssi = args['rssi']
        log.info("Received a scan response from %s with rssi=%d dBM "
                 "and data=%s",
                 address, args['rssi'], data_dict)

    def _ble_evt_sm_bond_status(self, args):
        """
        Handles the event for reporting a stored bond.

        Adds the stored bond to the list of bond handles.

        args -- dictionary containing the bond handle ('bond'), encryption key
                size used in the long-term key ('keysize'), was man in the
                middle used ('mitm'), keys stored for bonding ('keys')
        """
        # Add to list of stored bonds found or set flag
        self._stored_bonds.append(args['bond'])

    def _ble_rsp_sm_delete_bonding(self, args):
        """
        Handles the response for the deletion of a stored bond.

        args -- dictionary containing the return code ('result')
        """
        result = args['result']
        if result == 0:
            self._stored_bonds.pop()
        return result

    def _ble_rsp_sm_get_bonds(self, args):
        """
        Handles the response for the start of stored bond enumeration. Sets
        self._num_bonds to the number of stored bonds.

        args -- dictionary containing the number of stored bonds ('bonds'),
        """
        self._num_bonds = args['bonds']
        log.info("num bonds = %d", args['bonds'])
