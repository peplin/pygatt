from __future__ import print_function

import logging
import Queue
import serial
import time
import threading
from binascii import hexlify, unhexlify

from pygatt.exceptions import BluetoothLEError, NotConnectedError
from pygatt.backends.backend import BLEBackend

from . import bglib, constants
from .bglib import EventPacketType, ResponsePacketType
from .packets import BGAPICommandPacketBuilder as CommandBuilder
from .error_codes import get_return_message
from .util import find_usb_serial_devices

log = logging.getLogger(__name__)

BLED112_VENDOR_ID = 0x2458
BLED112_PRODUCT_ID = 0x0001


class BGAPIError(BluetoothLEError):
    pass


class ExpectedResponseTimeout(BGAPIError):
    def __init__(self, expected_packets, timeout):
        super(ExpectedResponseTimeout, self).__init__(
            "Timed out after %fs waiting for %s" % (
                timeout or 0, expected_packets))


class Characteristic(object):
    """
    GATT characteristic. For internal use within BGAPIBackend.
    """
    def __init__(self, name, handle):
        """
        Sets the characteritic name and handle.

        handle - a bytearray
        """
        self.handle = handle
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
        self._running = threading.Event()

        # buffer for packets received
        self._receiver_queue = Queue.Queue()

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
        self._characteristics = {  # the device characteristics discovered
            # uuid_string: Characteristic()
        }
        self._characteristics_cached = False  # characteristics already found
        self._current_characteristic = None  # used in char/descriptor discovery

        # Flags
        self._bonded = False  # device is bonded
        self._connected = False  # device is connected
        self._encrypted = False  # connection is encrypted
        self._bond_expected = False  # tell bond_status handler to set _bonded

        self._packet_handlers = {
            ResponsePacketType.sm_get_bonds: self._ble_rsp_sm_get_bonds,
            EventPacketType.attclient_attribute_value: (
                self._ble_evt_attclient_attribute_value),
            EventPacketType.attclient_find_information_found: (
                self._ble_evt_attclient_find_information_found),
            EventPacketType.attclient_procedure_completed: (
                self._ble_evt_attclient_procedure_completed),
            EventPacketType.connection_status: self._ble_evt_connection_status,
            EventPacketType.connection_disconnected: (
                self._ble_evt_connection_disconnected),
            EventPacketType.gap_scan_response: self._ble_evt_gap_scan_response,
            EventPacketType.sm_bond_status: self._ble_evt_sm_bond_status,
        }

        log.info("Initialized new BGAPI backend on %s", serial_port)

    def bond(self):
        """
        Create a bond and encrypted connection with the device.

        This requires that a connection is already extablished with the device.
        """
        self._assert_connected()

        # Set to bondable mode
        self._bond_expected = True
        log.info("Bonding to device")
        self._lib.send_command(
            self._ser,
            CommandBuilder.sm_set_bondable_mode(constants.bondable['yes']))

        self.expect(ResponsePacketType.sm_set_bondable_mode)
        log.debug("Enabling encryption")
        self._lib.send_command(
            self._ser,
            CommandBuilder.sm_encrypt_start(
                self._connection_handle, constants.bonding['create_bonding']))

        self.expect(ResponsePacketType.sm_encrypt_start)
        while self._connected and not self._bonded and not self._encrypted:
            matched_packet_type, response = self.expect_any(
                [EventPacketType.connection_status,
                 EventPacketType.sm_bonding_fail])
            if matched_packet_type == EventPacketType.sm_bonding_fail:
                raise BGAPIError("Bonding failed")
            # TODO how many times shoulud we try to bond? when does this loop
            # exit?

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

        self._assert_connected()

        value_list = [b for b in value]
        log.info("attribute_write")
        self._lib.send_command(
            self._ser,
            CommandBuilder.attclient_attribute_write(
                self._connection_handle, handle, value_list))

        self.expect(ResponsePacketType.attclient_attribute_write)
        self.expect(EventPacketType.attclient_procedure_completed)

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
        self._assert_connected()

        log.info("Reading characteristic at handle %d", handle)
        self._expected_attribute_handle = handle
        self._lib.send_command(
            self._ser,
            CommandBuilder.attclient_read_by_handle(
                self._connection_handle, handle))

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
        if self._connected:
            raise BGAPIError("Already connected")

        address_bytes = [int(b, 16) for b in address.split(":")]
        interval_min = 60
        interval_max = 76
        supervision_timeout = 100
        latency = 0  # intervals that can be skipped
        log.info("Connecting to device at address %s (timeout %dms)",
                 address, timeout / 10)
        self._lib.send_command(
            self._ser,
            CommandBuilder.gap_connect_direct(
                address_bytes, addr_type, interval_min, interval_max,
                supervision_timeout, latency))

        self.expect(ResponsePacketType.gap_connect_direct)
        try:
            self.expect(EventPacketType.connection_status, timeout=timeout)
        except ExpectedResponseTimeout:
            raise NotConnectedError()

    def delete_stored_bonds(self):
        """
        Delete the bonds stored on the dongle.

        Note: this does not delete the corresponding bond stored on the remote
              device.
        """
        # Find bonds
        log.debug("Fetching existing bonds for devicess")
        self._stored_bonds = []
        self._lib.send_command(self._ser, CommandBuilder.sm_get_bonds())

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

            self._lib.send_command(self._ser,
                                   CommandBuilder.sm_delete_bonding(b))
            self.expect(ResponsePacketType.sm_delete_bonding)

    def disconnect(self, fail_quietly=False):
        """
        Disconnect from the device if connected.

        fail_quietly -- do not raise an exception on failure.
        """

        if self._ser is None:
            return

        log.debug("Disconnecting")
        self._lib.send_command(
            self._ser,
            CommandBuilder.connection_disconnect(self._connection_handle))

        try:
            self.expect(ResponsePacketType.connection_disconnect)
        except (BGAPIError, NotConnectedError):
            if not fail_quietly:
                raise
        log.info("Disconnected")

    def encrypt(self):
        """
        Begin encryption on the connection with the device.

        This requires that a connection is already established with the device.

        Raises BGAPIError on failure.
        """
        self._assert_connected()

        self._lib.send_command(
            self._ser,
            CommandBuilder.sm_set_bondable_mode(constants.bondable['no']))

        # TODO expecting the matching response for a command is a repeated
        # pattern - the send_command function should have an option to wait for
        # the response for the command and return it.
        self.expect(ResponsePacketType.sm_set_bondable_mode)

        log.info("Starting encryption")
        self._lib.send_command(
            self._ser,
            CommandBuilder.sm_encrypt_start(
                self._connection_handle,
                constants.bonding['do_not_create_bonding']))

        self.expect(ResponsePacketType.sm_encrypt_start)
        self.expect(EventPacketType.connection_status)
        if not self._encrypted:
            msg = "Expected to be encrypted, but wasn't"
            log.warn(msg)
            raise BGAPIError(msg)

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
        self._assert_connected()

        # Discover characteristics if not cached
        if not self._characteristics_cached:
            att_handle_start = 0x0001  # first valid handle
            att_handle_end = 0xFFFF  # last valid handle
            log.info("Fetching characteristics")
            self._lib.send_command(
                self._ser,
                CommandBuilder.attclient_find_information(
                    self._connection_handle, att_handle_start, att_handle_end))

            self.expect(EventPacketType.attclient_procedure_completed,
                        timeout=10)
            self._characteristics_cached = True

            for char_uuid_str, char_obj in self._characteristics.iteritems():
                log.debug("Characteristic 0x%s is handle 0x%x",
                          char_uuid_str, char_obj.handle)
                for desc_uuid_str, desc_handle in (
                        char_obj.descriptors.iteritems()):
                    log.debug("Characteristic descriptor 0x%s is handle %x",
                              desc_uuid_str, desc_handle)

        # Return the handle if it exists
        char = None
        if characteristic_uuid not in self._characteristics:
            warning = (
                "No characteristic found matching %s" % characteristic_uuid)
            log.warn(warning)
            raise BGAPIError(warning)
        char = self._characteristics[characteristic_uuid]
        if descriptor_uuid is None:
            return char.handle
        desc_uuid_str = hexlify(descriptor_uuid)
        if not (desc_uuid_str in char.descriptors):
            warning = "No descriptor found matching %s" % desc_uuid_str
            log.warn(warning)
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
        self._assert_connected()

        log.info("Fetching RSSI one time")
        self._lib.send_command(
            self._ser,
            CommandBuilder.connection_get_rssi(self._connection_handle))

        _, response = self.expect(ResponsePacketType.connection_get_rssi)
        return response['rssi']

    def start(self):
        """
        Put the interface into a known state to start. And start the receiver
        thread.
        """
        self._ser = serial.Serial(self._serial_port, timeout=0.25)

        self._receiver = threading.Thread(target=self._receive)
        self._receiver.daemon = True

        self._running.set()
        self._receiver.start()

        # Disconnect any connections
        self.disconnect(fail_quietly=True)

        # Stop advertising
        log.info("Disabling advertising")
        self._lib.send_command(
            self._ser,
            CommandBuilder.gap_set_mode(
                constants.gap_discoverable_mode['non_discoverable'],
                constants.gap_connectable_mode['non_connectable']))

        try:
            self.expect(ResponsePacketType.gap_set_mode)
        except BGAPIError:
            # TODO should we do something about this error? is it fatal?
            pass

        # Stop any ongoing procedure
        log.info("Stopping any outstanding GAP procedure")
        self._lib.send_command(self._ser, CommandBuilder.gap_end_procedure())

        try:
            self.expect(ResponsePacketType.gap_end_procedure)
        except BGAPIError:
            # TODO should we do something about this error? is it fatal?
            pass

        self._lib.send_command(
            self._ser,
            CommandBuilder.sm_set_bondable_mode(constants.bondable['no']))

        self.expect(ResponsePacketType.sm_set_bondable_mode)

    def reset(self):
        self.disconnect(fail_quietly=True)
        self.delete_stored_bonds()

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
        # Set scan parameters
        if active:
            active = 0x01
        else:
            active = 0x00
        # NOTE: the documentation seems to say that the times are in units of
        # 625us but the ranges it gives correspond to units of 1ms....
        self._lib.send_command(
            self._ser,
            CommandBuilder.gap_set_scan_parameters(
                scan_interval, scan_window, active
            ))

        self.expect(ResponsePacketType.gap_set_scan_parameters)

        log.info("Starting an %s scan", "active" if active == 1 else "passive")
        self._lib.send_command(self._ser,
                               CommandBuilder.gap_discover(discover_mode))

        self.expect(ResponsePacketType.gap_discover)

        log.debug("Pausing for for %ds to allow scan to complete", timeout)
        time.sleep(timeout)

        log.info("Stopping scan")
        self._lib.send_command(self._ser, CommandBuilder.gap_end_procedure())

        self.expect(ResponsePacketType.gap_end_procedure)

        devices = []
        for address, info in self._devices_discovered.iteritems():
            devices.append({
                'address': address,
                'name': info.name,
                'rssi': info.rssi
            })
        return devices

    def subscribe(self, uuid, callback=None, indication=False):
        """
        Ask GATT server to receive notifications from the characteristic.

        This requires that a connection is already established with the device.

        uuid -- the uuid of the characteristic to subscribe to.
        callback -- funtion to call when notified/indicated.
        indication -- receive indications (requires application ACK) rather than
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
        if indication:
            config_val = [0x02, 0x00]  # Enable indications 0x0002
        self.char_write(characteristic_config_handle, config_val)

        if callback is not None:
            self._lock.acquire()
            self._callbacks[characteristic_handle] = callback
            self._lock.release()

    def stop(self):
        self.disconnect(fail_quietly=True)
        self._running.clear()
        if self._receiver:
            self._receiver.join()
        self._receiver = None

        if self._ser:
            self._ser.close()
            self._ser = None

    def _assert_connected(self):
        """
        Checks if there is/isn't a connection already established with a device.

        Raises NotConnectedError on failure if check_if_connected == True.
        """
        if self._ser is None or not self._connected:
            log.warn("Unexpectedly not connected")
            raise NotConnectedError()

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
        log.debug("Determined type of UUID %s" % hexlify(uuid))
        if len(uuid) == 16:  # 128-bit --> 16 byte
            log.debug("%s is a custom UUID", hexlify(uuid))
            return 0
        for name, u in constants.gatt_service_uuid.iteritems():
            if u == uuid:
                log.debug("match %s", name + ": 0x" + hexlify(u))
                return 1
        for name, u in constants.gatt_attribute_type_uuid.iteritems():
            if u == uuid:
                log.debug("match %s", name + ": 0x" + hexlify(u))
                return 2
        for name, u in (
                constants.gatt_characteristic_descriptor_uuid.iteritems()):
            if u == uuid:
                log.debug("match %s", name + ": 0x" + hexlify(u))
                return 3
        for name, u in constants.gatt_characteristic_type_uuid.iteritems():
            if u == uuid:
                log.debug("match %s", name + ": 0x" + hexlify(u))
                return 4
        log.debug("Type of UUID %s is unknown", hexlify(uuid))
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
                packet = self._receiver_queue.get(block=True, timeout=0.1)
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
            log.debug("Received a %s packet "
                      "(status: %s, connection handle: %x)",
                      packet_type, get_return_message(return_code),
                      response.get('connection_handle', 0))

            if packet_type in self._packet_handlers:
                self._packet_handlers[packet_type](response)

            if packet_type in expected_packet_choices:
                if assert_return_success and return_code != 0:
                    exc = BGAPIError(
                        "Response to packet %s errored: %s" %
                        (packet_type, get_return_message(return_code)))
                    log.warn(exc.message)
                    raise exc
                return packet_type, response

    def _receive(self):
        """
        Read bytes from serial and enqueue the packets if the packet is not a.
        Stops if the self._running event is not set.
        """
        att_value = EventPacketType.attclient_attribute_value
        log.info("Running receiver")
        while self._running.is_set():
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
                        self._receiver_queue.put(packet, block=True,
                                                 timeout=0.1)
                    elif args['atthandle'] in handles_subscribed_to:
                        # This is a notification/indication. Handle now.
                        callback_exists = (args['atthandle'] in callbacks)
                        if callback_exists:
                            log.debug(
                                "Calling subscription callback " +
                                callbacks[args['atthandle']].__name__)
                            callback_thread = threading.Thread(
                                target=callbacks[args['atthandle']],
                                args=(bytearray(args['value']),))
                            callback_thread.daemon = True
                            callback_thread.start()
                    else:
                        self._receiver_queue.put(packet, block=True,
                                                 timeout=0.1)
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
        uuid = bytearray(list(reversed(args['uuid'])))
        uuid_str = "0x"+hexlify(uuid)

        log.debug("characteristic handle = %s", hex(args['chrhandle']))
        log.debug("characteristic UUID = %s", uuid_str)

        # Add uuid to characteristics as characteristic or descriptor
        uuid_type = self._get_uuid_type(uuid)
        # 3 == descriptor
        if (uuid_type == 3) and (self._current_characteristic is not None):
            log.debug("GATT characteristic descriptor")
            self._current_characteristic.add_descriptor(hexlify(uuid),
                                                        args['chrhandle'])
        elif uuid_type == 0:  # 0 == custom 128-bit UUID
            log.debug("found custom characteristic")
            new_char = Characteristic(uuid, args['chrhandle'])
            self._current_characteristic = new_char
            self._characteristics[hexlify(uuid)] = new_char

    def _ble_evt_attclient_procedure_completed(self, args):
        """
        Handles the event for completion of writes to remote device.

        args -- dictionary containing the return code ('result'), characteristic
        handle ('chrhandle')
        """
        log.debug("characteristic handle = %s", hex(args['chrhandle']))
        log.info("return code = %s",
                 get_return_message(args['result']))

    def _ble_evt_connection_disconnected(self, args):
        """
        Handles the event for the termination of a connection.
        """
        self._connected = False
        self._encrypted = False
        self._bonded = False
        raise NotConnectedError()

    def _ble_evt_connection_status(self, args):
        """
        Handles the event for reporting connection parameters.

        args -- dictionary containing the connection status flags ('flags'),
            device address ('address'), device address type ('address_type'),
            connection interval ('conn_interval'), connection timeout
            (timeout'), device latency ('latency'), device bond handle
            ('bonding')
        """
        self._connection_handle = args['connection_handle']
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

        log.debug("connection = %s", hex(args['connection_handle']))
        log.info("flags = %s", flags)
        addr_str = "0x"+hexlify(bytearray(args['address']))
        log.debug("address = %s", addr_str)
        if (args['address_type'] ==
                constants.ble_address_type['gap_address_type_public']):
            address_type = "public"
        elif (args['address_type'] ==
                constants.ble_address_type['gap_address_type_random']):
            address_type = "random"
        else:
            address_type = "Bad type"
        log.debug("address type = %s", address_type)
        log.debug("connection interval = %f ms",
                  args['conn_interval'] * 1.25)
        log.debug("timeout = %d", args['timeout'] * 10)
        log.debug("latency = %d intervals", args['latency'])
        log.debug("bonding = %s", hex(args['bonding']))

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

        log.debug("bond handle = %s", hex(args['bond']))
        log.debug("keysize = %d", args['keysize'])
        log.debug("man in the middle = %d", args['mitm'])
        log.debug("keys = %s", hex(args['keys']))

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

        args -- dictionary containing the number of stored bonds ('bonds),
        """
        self._num_bonds = args['bonds']
        log.info("num bonds = %d", args['bonds'])

    def _uuid_bytearray(self, uuid):
        """
        Turns a UUID string in the format "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        to a bytearray.

        uuid -- the UUID to convert.

        Returns a bytearray containing the UUID.
        """
        log.info("_uuid_bytearray %s", uuid)
        return unhexlify(uuid.replace("-", ""))
