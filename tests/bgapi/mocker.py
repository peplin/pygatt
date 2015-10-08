from mock import patch
from binascii import unhexlify

from tests.serial_mock import SerialMock

from .packets import BGAPIPacketBuilder


def uuid_to_bytearray(uuid_str):
    """
    Turns a UUID string in the format "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    to a bytearray.

    uuid -- the UUID to convert.

    Returns a bytearray containing the UUID.
    """
    return unhexlify(uuid_str.replace('-', ''))


class MockBGAPISerialDevice(object):
    def __init__(self, serial_port_name='mock'):
        self.serial_port_name = serial_port_name
        self.mocked_serial = SerialMock(self.serial_port_name, 0.25)
        self.patcher = patch('serial.Serial',
                             return_value=self.mocked_serial).start()

    def stop(self):
        self.patcher.stop()

    @staticmethod
    def _get_connection_status_flags_byte(flags):
        flags_byte = 0x00
        if 'connected' in flags:
            flags_byte |= 0x01
        if 'encrypted' in flags:
            flags_byte |= 0x02
        if 'completed' in flags:
            flags_byte |= 0x04
        if 'parameters_change' in flags:
            flags_byte |= 0x08
        return flags_byte

    def stage_disconnected_by_remote(
            self, connection_handle=0x00):
        # Stage ble_evt_connection_disconnected (terminated by remote user)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.connection_disconnected(
                connection_handle, 0x0213))

    def stage_disconnect_packets(self, connected, fail, connection_handle=0x00):
        if connected:
            if fail:
                raise NotImplementedError()

            # Stage ble_rsp_connection_disconnect (success)
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.connection_disconnect(
                    connection_handle, 0x0000))
            # Stage ble_evt_connection_disconnected (success by local user)
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.connection_disconnected(
                    connection_handle, 0x0000))
        else:  # not connected always fails
            # Stage ble_rsp_connection_disconnect (fail, not connected)
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.connection_disconnect(
                    connection_handle, 0x0186))

    def stage_run_packets(self, connection_handle=0x00):
        # Stage ble_rsp_connection_disconnect (not connected, fail)
        self.stage_disconnect_packets(False, True)
        # Stage ble_rsp_gap_set_mode (success)
        self.mocked_serial.stage_output(BGAPIPacketBuilder.gap_set_mode(0x0000))
        # Stage ble_rsp_gap_end_procedure (fail, device in wrong state)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.gap_end_procedure(0x0181))
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.sm_set_bondable_mode())

    def stage_connect_packets(self, addr, flags, connection_handle=0x00):
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.sm_set_bondable_mode())
        # Stage ble_rsp_gap_connect_direct (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.gap_connect_direct(connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        self.mocked_serial.stage_output(BGAPIPacketBuilder.connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    def stage_get_rssi_packets(self, connection_handle=0x00,
                               rssi=-80):
        # Stage ble_rsp_connection_get_rssi
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.connection_get_rssi(connection_handle, rssi))

    def stage_bond_packets(self, addr, flags,
                           connection_handle=0x00, bond_handle=0x01):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        self.mocked_serial.stage_output(BGAPIPacketBuilder.sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_sm_bond_status
        self.mocked_serial.stage_output(BGAPIPacketBuilder.sm_bond_status(
            bond_handle, 0x00, 0x00, 0x00))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        self.mocked_serial.stage_output(BGAPIPacketBuilder.connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    def stage_clear_bonds_packets(
            self, bonds, disconnects=False):
        """bonds -- list of 8-bit integer bond handles"""
        if disconnects:
            self.stage_disconnected_by_remote()
        # Stage ble_rsp_get_bonds
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.sm_get_bonds(len(bonds)))
        # Stage ble_evt_sm_bond_status (bond handle)
        for b in bonds:
            if disconnects:
                self.stage_disconnected_by_remote()
            self.mocked_serial.stage_output(BGAPIPacketBuilder.sm_bond_status(
                b, 0x00, 0x00, 0x00))
        # Stage ble_rsp_sm_delete_bonding (success)
        for b in bonds:
            if disconnects:
                self.stage_disconnected_by_remote()
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.sm_delete_bonding(0x0000))

    def stage_scan_packets(self, scan_responses=[]):
        # Stage ble_rsp_gap_set_scan_parameters (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.gap_set_scan_parameters(0x0000))
        # Stage ble_rsp_gap_discover (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.gap_discover(0x0000))
        for srp in scan_responses:
            # Stage ble_evt_gap_scan_response
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.gap_scan_response(
                    srp['rssi'], srp['packet_type'], srp['bd_addr'],
                    srp['addr_type'], srp['bond'],
                    [len(srp['data'])+1]+srp['data']))
        # Stage ble_rsp_gap_end_procedure (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.gap_end_procedure(0x0000))

    def stage_discover_characteristics_packets(
            self, uuid_handle_list, connection_handle=0x00):
        # Stage ble_rsp_attclient_find_information (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.attclient_find_information(
                connection_handle, 0x0000))
        for i in range(0, len(uuid_handle_list)/2):
            uuid = uuid_to_bytearray(uuid_handle_list[2*i])
            handle = uuid_handle_list[2*i + 1]
            # Stage ble_evt_attclient_find_information_found
            u = [len(uuid) + 1]
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.attclient_find_information_found(
                    connection_handle, handle,
                    (u+list(reversed([ord(b) for b in uuid])))))
        # Stage ble_evt_attclient_procedure_completed (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.attclient_procedure_completed(
                connection_handle, 0x0000, 0xFFFF))

    def stage_char_read_packets(
            self, att_handle, att_type, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_read_by_handle (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.attclient_read_by_handle(
                connection_handle, 0x0000))
        # Stage ble_evt_attclient_attribute_value
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.attclient_attribute_value(
                connection_handle, att_handle, att_type, [len(value)+1]+value))

    def stage_char_write_packets(
            self, handle, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_attribute_write (success)
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.attclient_attribute_write(
                connection_handle, 0x0000))
        # Stage ble_evt_attclient_procedure_completed
        self.mocked_serial.stage_output(
            BGAPIPacketBuilder.attclient_procedure_completed(
                connection_handle, 0x0000, handle))

    def stage_indication_packets(
            self, handle, packet_values, connection_handle=0x00):
        # Stage ble_evt_attclient_attribute_value
        for value in packet_values:
            val = list(value)
            self.mocked_serial.stage_output(
                BGAPIPacketBuilder.attclient_attribute_value(
                    connection_handle, handle, 0x00, value=[len(val)+1]+val))
