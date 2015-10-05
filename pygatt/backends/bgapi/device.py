import logging
import time

from pygatt import BLEDevice, exceptions
from . import constants
from .bgapi import BGAPIError
from .error_codes import ErrorCode
from .packets import BGAPICommandPacketBuilder as CommandBuilder
from .bglib import EventPacketType, ResponsePacketType

log = logging.getLogger(__name__)


def connection_required(func):
    def wrapper(self, *args, **kwargs):
        if self._handle is None:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class BGAPIBLEDevice(BLEDevice):
    def __init__(self, address, handle, backend):
        super(BGAPIBLEDevice, self).__init__(address)
        self._address = address
        self._handle = handle
        self._backend = backend
        self._characteristics = {}

    @connection_required
    def bond(self):
        """
        Create a bond and encrypted connection with the device.

        This requires that a connection is already extablished with the device.
        """

        # Set to bondable mode so bonds are store permanently
        # self._backend.set_bondable(True)
        log.info("Bonding to %s", self._address)
        self._backend.send_command(
            CommandBuilder.sm_encrypt_start(
                self._handle, constants.bonding['create_bonding']))
        self._backend.expect(ResponsePacketType.sm_encrypt_start)

        packet_type, response = self._backend.expect_any(
            [EventPacketType.connection_status,
             EventPacketType.sm_bonding_fail])
        if packet_type == EventPacketType.sm_bonding_fail:
            raise BGAPIError("Bonding failed")

    @connection_required
    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        This requires that a connection is already established with the device.

        Returns the RSSI as in integer in dBm.
        """
        # The BGAPI has some strange behavior where it will return 25 for
        # the RSSI value sometimes... Try a maximum of 3 times.
        for i in range(0, 3):
            self._backend.send_command(
                CommandBuilder.connection_get_rssi(self._handle))
            _, response = self._backend.expect(
                ResponsePacketType.connection_get_rssi)
            rssi = response['rssi']
            if rssi != 25:
                return rssi
            time.sleep(0.1)
        raise BGAPIError("get rssi failed")

    @connection_required
    def char_read(self, uuid):
        """
        Read a value from a characteristic on the device.

        This requires that a connection is already established with the device.

        handle -- the characteristic handle (integer) to read from.

        Returns a bytearray containing the value read, on success.
        Raised BGAPIError on failure.
        """
        handle = self.get_handle(uuid)
        log.info("Reading characteristic at handle %d", handle)
        self._backend.send_command(
            CommandBuilder.attclient_read_by_handle(
                self._handle, handle))

        self._backend.expect(ResponsePacketType.attclient_read_by_handle)
        matched_packet_type, response = self._backend.expect_any(
            [EventPacketType.attclient_attribute_value,
             EventPacketType.attclient_procedure_completed])
        # TODO why not just expect *only* the attribute value response, then it
        # would time out and raise an exception if allwe got was the 'procedure
        # completed' response?
        if matched_packet_type != EventPacketType.attclient_attribute_value:
            raise BGAPIError("Unable to read characteristic")
        return bytearray(response['value'])

    @connection_required
    def char_write_handle(self, char_handle, value, wait_for_response=False):
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
            self._backend.send_command(
                CommandBuilder.attclient_attribute_write(
                    self._handle, char_handle, value_list))

            self._backend.expect(ResponsePacketType.attclient_attribute_write)
            packet_type, response = self._backend.expect(
                EventPacketType.attclient_procedure_completed)
            if (response['result'] !=
                    ErrorCode.insufficient_authentication.value):
                # Continue to retry until we are bonded
                break

    @connection_required
    def disconnect(self):
        """
        Disconnect from the device if connected.
        """
        log.debug("Disconnecting from %s", self._address)
        self._backend.send_command(
            CommandBuilder.connection_disconnect(self._handle))

        self._backend.expect(ResponsePacketType.connection_disconnect)
        log.info("Disconnected from %s", self._address)
        self._handle = None

    @connection_required
    def discover_characteristics(self):
        return self._backend.discover_characteristics(self._handle)
