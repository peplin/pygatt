from __future__ import print_function

# for Python 2/3 compatibility
import logging
try:
    import queue
except:
    import Queue as queue
import serial
import time
import threading
from binascii import hexlify, unhexlify
from uuid import UUID
from enum import Enum
from collections import defaultdict

from pygatt.exceptions import NotConnectedError
from pygatt.backends import BLEBackend, Characteristic
from pygatt.util import uuid16_to_uuid

from . import bglib, constants
from .exceptions import BGAPIError, ExpectedResponseTimeout
from .device import BGAPIBLEDevice
from .bglib import EventPacketType, ResponsePacketType
from .packets import BGAPICommandPacketBuilder as CommandBuilder
from .error_codes import get_return_message
from .util import find_usb_serial_devices

log = logging.getLogger(__name__)

BLED112_VENDOR_ID = 0x2458
BLED112_PRODUCT_ID = 0x0001


UUIDType = Enum('UUIDType', ['custom', 'service', 'attribute',
                             'descriptor', 'characteristic'])


def bgapi_address_to_hex(address):
    address = hexlify(bytearray(list(reversed(address)))).upper()
    return ':'.join(''.join(pair) for pair in zip(*[iter(address)] * 2))


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
    A BLE backend for a BGAPI compatible USB adapter.
    """
    def __init__(self, serial_port=None):
        """
        Initialize the backend, but don't start the USB connection yet. Must
        call .start().

        serial_port -- The name of the serial port for the BGAPI-compatible
            USB interface. If not provided, will attempt to auto-detect.
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
        self._lock = threading.Lock()

        # buffer for packets received
        self._receiver_queue = queue.Queue()

        self._connected_devices = {
            # handle: BLEDevice
        }

        # State
        self._num_bonds = 0  # number of bonds stored on the adapter
        self._stored_bonds = []  # bond handles stored on the adapter
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
        Connect to the USB adapter, reset it's state and start a backgroud
        receiver thread.
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

        self.set_bondable(False)

        # TODO should disconnect from anything so we are in a clean slate

        # Stop any ongoing procedure
        log.debug("Stopping any outstanding GAP procedure")
        self.send_command(CommandBuilder.gap_end_procedure())
        try:
            self.expect(ResponsePacketType.gap_end_procedure)
        except BGAPIError:
            # Ignore any errors if there was no GAP procedure running
            pass

    def stop(self):
        for device in self._connections.values():
            try:
                device.disconnect()
            except NotConnectedError:
                pass
        if self._running.is_set():
            log.info('Stopping')
        self._running.clear()

        if self._receiver:
            self._receiver.join()
        self._receiver = None

        if self._ser:
            self._ser.close()
            self._ser = None

    def set_bondable(self, bondable):
        self.send_command(
            CommandBuilder.sm_set_bondable_mode(
                constants.bondable['yes' if bondable else 'no']))
        self.expect(ResponsePacketType.sm_set_bondable_mode)

    def disable_advertising(self):
        log.info("Disabling advertising")
        self.send_command(
            CommandBuilder.gap_set_mode(
                constants.gap_discoverable_mode['non_discoverable'],
                constants.gap_connectable_mode['non_connectable']))
        self.expect(ResponsePacketType.gap_set_mode)

    def send_command(self, *args, **kwargs):
        with self._lock:
            if self._ser is None:
                log.warn("Unexpectedly not connected to USB device")
                raise NotConnectedError()
            return self._lib.send_command(self._ser, *args, **kwargs)

    def clear_bond(self, address=None):
        """
        Delete the bonds stored on the adapter.

        address - the address of the device to unbond. If not provided, will
            erase all bonds.

        Note: this does not delete the corresponding bond stored on the remote
              device.
        """
        # Find bonds
        log.info("Fetching existing bonds for devices")
        self._stored_bonds = []
        self.send_command(CommandBuilder.sm_get_bonds())

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

            self.send_command(CommandBuilder.sm_delete_bonding(b))
            self.expect(ResponsePacketType.sm_delete_bonding)

    def scan(self, timeout=10, scan_interval=75, scan_window=50, active=True,
             discover_mode=constants.gap_discover_mode['observation']):
        """
        Perform a scan to discover BLE devices.

        timeout -- the number of seconds this scan should last.
        scan_interval -- the number of miliseconds until scanning is restarted.
        scan_window -- the number of miliseconds the scanner will listen on one
                     frequency for advertisement packets.
        active -- True --> ask sender for scan response data. False --> don't.
        discover_mode -- one of the gap_discover_mode constants.
        """
        parameters = 1 if active else 0
        # NOTE: the documentation seems to say that the times are in units of
        # 625us but the ranges it gives correspond to units of 1ms....
        self.send_command(
            CommandBuilder.gap_set_scan_parameters(
                scan_interval, scan_window, parameters
            ))

        self.expect(ResponsePacketType.gap_set_scan_parameters)

        log.info("Starting an %s scan", "active" if active else "passive")
        self.send_command(CommandBuilder.gap_discover(discover_mode))

        self.expect(ResponsePacketType.gap_discover)

        log.info("Pausing for for %ds to allow scan to complete", timeout)
        time.sleep(timeout)

        log.info("Stopping scan")
        self.send_command(CommandBuilder.gap_end_procedure())
        self.expect(ResponsePacketType.gap_end_procedure)

        devices = []
        for address, info in self._devices_discovered.iteritems():
            devices.append({
                'address': address,
                'name': info.name,
                'rssi': info.rssi
            })
        log.info("Discovered %d devices: %s", len(devices), devices)
        self._devices_discovered = {}
        return devices

    def connect(self, address, timeout=5,
                addr_type=constants.ble_address_type[
                    'gap_address_type_public'],
                interval_min=60, interval_max=76, supervision_timeout=100,
                latency=0):
        """
        Connnect directly to a device given the ble address then discovers and
        stores the characteristic and characteristic descriptor handles.

        Requires that the adapter is not connected to a device already.

        address -- a bytearray containing the device mac address.
        timeout -- number of seconds to wait before returning if not connected.
        addr_type -- one of the ble_address_type constants.

        Raises BGAPIError or NotConnectedError on failure.
        """

        address_bytes = bytearray(unhexlify(address.replace(":", "")))
        for device in self._connections.values():
            if device._address == bgapi_address_to_hex(address_bytes):
                return device

        log.info("Connecting to device at address %s (timeout %ds)",
                 address, timeout)
        self.set_bondable(False)
        self.send_command(
            CommandBuilder.gap_connect_direct(
                address_bytes, addr_type, interval_min, interval_max,
                supervision_timeout, latency))

        self.expect(ResponsePacketType.gap_connect_direct)
        try:
            _, packet = self.expect(EventPacketType.connection_status,
                                    timeout=timeout)
            # TODO what do we do if the status isn't 'connected'? Retry? Raise
            # an exception? Should also check the address matches the expected
            # TODO i'm finding that when reconnecting to the same MAC, we geta
            # conneciotn status of "disconnected" but that is picked up here as
            # "connected", then we don't get anything else.
            if self._connection_status_flag(
                    packet['flags'],
                    constants.connection_status_flag['connected']):
                device = BGAPIBLEDevice(bgapi_address_to_hex(packet['address']),
                                        packet['connection_handle'],
                                        self)
                if self._connection_status_flag(
                        packet['flags'],
                        constants.connection_status_flag['encrypted']):
                    device.encrypted = True
                self._connections[packet['connection_handle']] = device
                log.info("Connected to %s", address)
                return device
        except ExpectedResponseTimeout:
            raise NotConnectedError()

    def discover_characteristics(self, connection_handle):
        att_handle_start = 0x0001  # first valid handle
        att_handle_end = 0xFFFF  # last valid handle
        log.info("Fetching characteristics for connection %d",
                 connection_handle)
        self.send_command(
            CommandBuilder.attclient_find_information(
                connection_handle, att_handle_start, att_handle_end))

        self.expect(ResponsePacketType.attclient_find_information)
        self.expect(EventPacketType.attclient_procedure_completed,
                    timeout=10)

        for char_uuid_str, char_obj in (
                self._characteristics[connection_handle].iteritems()):
            log.info("Characteristic 0x%s is handle 0x%x",
                     char_uuid_str, char_obj.handle)
            for desc_uuid_str, desc_handle in (
                    char_obj.descriptors.iteritems()):
                log.info("Characteristic descriptor 0x%s is handle 0x%x",
                         desc_uuid_str, desc_handle)
        return self._characteristics[connection_handle]

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
                            service_uuid = (
                                "0x%s" %
                                bgapi_address_to_hex(field_value[i*16:i*16+16]))
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
        log.debug("Expecting a response of one of %s within %fs",
                  expected_packet_choices, timeout or 0)

        start_time = None
        if timeout is not None:
            start_time = time.time()

        while True:
            packet = None
            try:
                # TODO can we increase the timeout here?
                packet = self._receiver_queue.get(timeout=0.1)
            except queue.Empty:
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
                        device = self._connections[args['connection_handle']]
                        device.receive_notification(args['atthandle'],
                                                    bytearray(args['value']))
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
            uuid = uuid16_to_uuid(int(
                bgapi_address_to_hex(args['uuid']).replace(':', ''), 16))
        else:
            uuid = UUID(hexlify(raw_uuid))

        # TODO is there a way to get the characteristic from the packet instead
        # of having to track the "current" characteristic?
        if (uuid_type == UUIDType.descriptor and
                self._current_characteristic is not None):
            self._current_characteristic.add_descriptor(uuid, args['chrhandle'])
        elif uuid_type == UUIDType.custom:
            log.info("Found custom characteristic %s" % uuid)
            new_char = Characteristic(uuid, args['chrhandle'])
            self._current_characteristic = new_char
            self._characteristics[
                args['connection_handle']][uuid] = new_char

    def _ble_evt_connection_disconnected(self, args):
        """
        Handles the event for the termination of a connection.
        """
        self._connections.pop(args['connection_handle'], None)

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
        if not self._connection_status_flag(
                args['flags'],
                constants.connection_status_flag['connected']):
            # Disconnected
            self._connections.pop(connection_handle, None)

        log.info("Connection status: handle=0x%x, flags=%s, address=0x%s, "
                 "connection interval=%fms, timeout=%d, "
                 "latency=%d intervals, bonding=0x%x",
                 connection_handle,
                 args['address'],
                 hexlify(bytearray(args['address'])),
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
        address = bgapi_address_to_hex(args['sender'])
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
        log.debug("Received a scan response from %s with rssi=%d dBM "
                  "and data=%s", address, args['rssi'], data_dict)

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
        log.debug("num bonds = %d", args['bonds'])
