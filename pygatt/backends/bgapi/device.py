import functools
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
    """Raise an exception if the device is not connected before calling the
    actual function.
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self._handle is None:
            raise exceptions.NotConnectedError()
        return func(self, *args, **kwargs)

    return wrapper


class BGAPIBLEDevice(BLEDevice):
    def __init__(self, address, handle, backend):
        super(BGAPIBLEDevice, self).__init__(address)
        self._handle = handle
        self._backend = backend

    @connection_required
    def bond(self, permanent=False):
        """
        Create a bond and encrypted connection with the device.
        """

        # Set to bondable mode so bonds are store permanently
        if permanent:
            self._backend.set_bondable(True)
        log.debug("Bonding to %s", self._address)
        self._backend.send_command(
            CommandBuilder.sm_encrypt_start(
                self._handle, constants.bonding["create_bonding"]
            )
        )
        self._backend.expect(ResponsePacketType.sm_encrypt_start)

        packet_type, response = self._backend.expect_any(
            [EventPacketType.connection_status, EventPacketType.sm_bonding_fail]
        )
        if packet_type == EventPacketType.sm_bonding_fail:
            raise BGAPIError("Bonding failed")
        log.info("Bonded to %s", self._address)

    @connection_required
    def get_rssi(self):
        """
        Get the receiver signal strength indicator (RSSI) value from the device.

        Returns the RSSI as in integer in dBm.
        """
        # The BGAPI has some strange behavior where it will return 25 for
        # the RSSI value sometimes... Try a maximum of 3 times.
        for i in range(0, 3):
            self._backend.send_command(CommandBuilder.connection_get_rssi(self._handle))
            _, response = self._backend.expect(ResponsePacketType.connection_get_rssi)
            rssi = response["rssi"]
            if rssi != 25:
                return rssi
            time.sleep(0.1)
        raise BGAPIError("get rssi failed")

    @connection_required
    def char_read(self, uuid, timeout=None):
        return self.char_read_handle(self.get_handle(uuid), timeout=timeout)

    @connection_required
    def char_read_handle(self, handle, timeout=None):
        log.info("Reading characteristic at handle %d", handle)
        self._backend.send_command(
            CommandBuilder.attclient_read_by_handle(self._handle, handle)
        )

        self._backend.expect(ResponsePacketType.attclient_read_by_handle)
        success = False
        while not success:
            matched_packet_type, response = self._backend.expect_any(
                [
                    EventPacketType.attclient_attribute_value,
                    EventPacketType.attclient_procedure_completed,
                ],
                timeout=timeout,
            )
            # TODO why not just expect *only* the attribute value response,
            # then it would time out and raise an exception if allwe got was
            # the 'procedure completed' response?
            if matched_packet_type != EventPacketType.attclient_attribute_value:
                raise BGAPIError("Unable to read characteristic")
            if response["atthandle"] == handle:
                # Otherwise we received a response from a wrong handle (e.g.
                # from a notification) so we keep trying to wait for the
                # correct one
                success = True
        return bytearray(response["value"])

    @connection_required
    def char_read_long(self, uuid, timeout=None):
        return self.char_read_long_handle(self.get_handle(uuid), timeout=timeout)

    @connection_required
    def char_read_long_handle(self, handle, timeout=None):
        log.info("Reading long characteristic at handle %d", handle)
        self._backend.send_command(
            CommandBuilder.attclient_read_long(self._handle, handle)
        )

        self._backend.expect(ResponsePacketType.attclient_read_long)
        success = False
        response = b""
        while not success:
            matched_packet_type, chunk = self._backend.expect_any(
                [
                    EventPacketType.attclient_attribute_value,
                    EventPacketType.attclient_procedure_completed,
                ],
                timeout=timeout,
            )

            if matched_packet_type == EventPacketType.attclient_attribute_value:
                if chunk["atthandle"] == handle:
                    # Concatenate the data
                    response += chunk["value"]
            elif matched_packet_type == EventPacketType.attclient_procedure_completed:
                if chunk["chrhandle"] == handle:
                    success = True
        return bytearray(response)

    @connection_required
    def char_write_handle(self, char_handle, value, wait_for_response=True):
        while True:
            value_list = [b for b in value]
            # An "attribute write" is always acknowledged by the remote host.
            if wait_for_response:
                self._backend.send_command(
                    CommandBuilder.attclient_attribute_write(
                        self._handle, char_handle, value_list
                    )
                )
                self._backend.expect(ResponsePacketType.attclient_attribute_write)
                packet_type, response = self._backend.expect(
                    EventPacketType.attclient_procedure_completed,
                    # According to the BLE spec, the device has 30 seconds to
                    # repsonse to the attribute write.
                    timeout=30,
                )

            # A "command" write is unacknowledged - don't wait for a response.
            else:
                self._backend.send_command(
                    CommandBuilder.attclient_write_command(
                        self._handle, char_handle, value_list
                    )
                )
                packet_type, response = self._backend.expect(
                    ResponsePacketType.attclient_write_command
                )

            if response["result"] != ErrorCode.insufficient_authentication.value:
                # Continue to retry until we are bonded
                break

    # ASC - adapted from
    # https://raw.githubusercontent.com/mjbrown/bgapi/master/bgapi/module.py
    # - reliable_write_by_handle
    @connection_required
    def char_write_long_handle(self, char_handle, value, wait_for_response=False):
        maxv = 18

        for i in range(int(((len(value) - 1) / maxv) + 1)):
            chunk = value[maxv * i : min(maxv * (i + 1), len(value))]
            value_list = [b for b in chunk]
            self._backend.send_command(
                CommandBuilder.attclient_prepare_write(
                    self._handle, char_handle, maxv * i, value_list
                )
            )

            packet_type, response = self._backend.expect(
                ResponsePacketType.attclient_prepare_write
            )

            packet_type, response = self._backend.expect(
                EventPacketType.attclient_procedure_completed
            )
            time.sleep(0.1)

        time.sleep(0.1)
        self._backend.send_command(
            CommandBuilder.attclient_execute_write(self._handle, 1)
        )  # 1 = commit, 0 = cancel
        self._backend.expect(ResponsePacketType.attclient_execute_write)
        packet_type, response = self._backend.expect(
            EventPacketType.attclient_procedure_completed
        )
        time.sleep(0.1)

    @connection_required
    def disconnect(self):
        log.debug("Disconnecting from %s", self._address)
        self._backend.send_command(CommandBuilder.connection_disconnect(self._handle))

        self._backend.expect(ResponsePacketType.connection_disconnect)
        log.info("Disconnected from %s", self._address)
        self._handle = None

    @connection_required
    def discover_characteristics(self):
        self._characteristics = self._backend.discover_characteristics(self._handle)
        return self._characteristics
