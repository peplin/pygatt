from .packets import BGAPIPacketBuilder
from .util import uuid_to_bytearray


class BGAPIBackendSpy(object):
    def __init__(self, backend):
        self.backend = backend

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

    def stage_ble_evt_connection_disconnected_by_remote_user(
            self, backend, connection_handle=0x00):
        # Stage ble_evt_connection_disconnected (terminated by remote user)
        backend._ser.stage_output(BGAPIPacketBuilder.connection_disconnected(
            connection_handle, 0x0213))

    def stage_disconnect_packets(
            self, backend, connected, fail, connection_handle=0x00):
        """Stage the packets for backend.disconnect()."""
        if connected:
            if fail:
                raise NotImplementedError()
            else:
                # Stage ble_rsp_connection_disconnect (success)
                backend._ser.stage_output(
                    BGAPIPacketBuilder.connection_disconnect(
                        connection_handle, 0x0000))
                # Stage ble_evt_connection_disconnected (success by local user)
                backend._ser.stage_output(
                    BGAPIPacketBuilder.connection_disconnected(
                        connection_handle, 0x0000))
        else:  # not connected always fails
            # Stage ble_rsp_connection_disconnect (fail, not connected)
            backend._ser.stage_output(
                BGAPIPacketBuilder.connection_disconnect(
                    connection_handle, 0x0186))

    def stage_run_packets(self, backend, connection_handle=0x00):
        # Stage ble_rsp_connection_disconnect (not connected, fail)
        self.stage_disconnect_packets(backend, False, True)
        # Stage ble_rsp_gap_set_mode (success)
        backend._ser.stage_output(BGAPIPacketBuilder.gap_set_mode(0x0000))
        # Stage ble_rsp_gap_end_procedure (fail, device in wrong state)
        backend._ser.stage_output(BGAPIPacketBuilder.gap_end_procedure(0x0181))
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        backend._ser.stage_output(BGAPIPacketBuilder.sm_set_bondable_mode())

    def stage_connect_packets(self, backend, addr, flags,
                              connection_handle=0x00):
        # Stage ble_rsp_gap_connect_direct (success)
        backend._ser.stage_output(BGAPIPacketBuilder.gap_connect_direct(
            connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        backend._ser.stage_output(BGAPIPacketBuilder.connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    def stage_get_rssi_packets(self, backend, connection_handle=0x00,
                               rssi=-80):
        # Stage ble_rsp_connection_get_rssi
        backend._ser.stage_output(
            BGAPIPacketBuilder.connection_get_rssi(connection_handle, rssi))

    def stage_encrypt_packets(self, backend, addr, flags,
                              connection_handle=0x00):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        backend._ser.stage_output(BGAPIPacketBuilder.sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        backend._ser.stage_output(BGAPIPacketBuilder.sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        backend._ser.stage_output(BGAPIPacketBuilder.connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    def stage_bond_packets(self, backend, addr, flags,
                           connection_handle=0x00, bond_handle=0x01):
        # Stage ble_rsp_sm_set_bondable_mode (always success)
        backend._ser.stage_output(BGAPIPacketBuilder.sm_set_bondable_mode())
        # Stage ble_rsp_sm_encrypt_start (success)
        backend._ser.stage_output(BGAPIPacketBuilder.sm_encrypt_start(
            connection_handle, 0x0000))
        # Stage ble_evt_sm_bond_status
        backend._ser.stage_output(BGAPIPacketBuilder.sm_bond_status(
            bond_handle, 0x00, 0x00, 0x00))
        # Stage ble_evt_connection_status
        flags_byte = self._get_connection_status_flags_byte(flags)
        backend._ser.stage_output(BGAPIPacketBuilder.connection_status(
            addr, flags_byte, connection_handle, 0,
            0x0014, 0x0006, 0x0000, 0xFF))

    def stage_delete_stored_bonds_packets(
            self, backend, bonds, disconnects=False):
        """bonds -- list of 8-bit integer bond handles"""
        if disconnects:
            self.stage_ble_evt_connection_disconnected_by_remote_user(backend)
        # Stage ble_rsp_get_bonds
        backend._ser.stage_output(BGAPIPacketBuilder.sm_get_bonds(len(bonds)))
        # Stage ble_evt_sm_bond_status (bond handle)
        for b in bonds:
            if disconnects:
                self.stage_ble_evt_connection_disconnected_by_remote_user(
                    backend)
            backend._ser.stage_output(BGAPIPacketBuilder.sm_bond_status(
                b, 0x00, 0x00, 0x00))
        # Stage ble_rsp_sm_delete_bonding (success)
        for b in bonds:
            if disconnects:
                self.stage_ble_evt_connection_disconnected_by_remote_user(
                    backend)
            backend._ser.stage_output(
                BGAPIPacketBuilder.sm_delete_bonding(0x0000))

    def stage_scan_packets(self, backend, scan_responses=[]):
        # Stage ble_rsp_gap_set_scan_parameters (success)
        backend._ser.stage_output(
            BGAPIPacketBuilder.gap_set_scan_parameters(0x0000))
        # Stage ble_rsp_gap_discover (success)
        backend._ser.stage_output(
            BGAPIPacketBuilder.gap_discover(0x0000))
        for srp in scan_responses:
            # Stage ble_evt_gap_scan_response
            backend._ser.stage_output(BGAPIPacketBuilder.gap_scan_response(
                srp['rssi'], srp['packet_type'], srp['bd_addr'],
                srp['addr_type'], srp['bond'],
                [len(srp['data'])+1]+srp['data']))
        # Stage ble_rsp_gap_end_procedure (success)
        backend._ser.stage_output(
            BGAPIPacketBuilder.gap_end_procedure(0x0000))

    def stage_get_handle_packets(
            self, backend, uuid_handle_list, connection_handle=0x00):
        # Stage ble_rsp_attclient_find_information (success)
        backend._ser.stage_output(BGAPIPacketBuilder.attclient_find_information(
            connection_handle, 0x0000))
        for i in range(0, len(uuid_handle_list)/2):
            uuid = uuid_to_bytearray(uuid_handle_list[2*i])
            handle = uuid_handle_list[2*i + 1]
            # Stage ble_evt_attclient_find_information_found
            u = [len(uuid) + 1]
            backend._ser.stage_output(
                BGAPIPacketBuilder.attclient_find_information_found(
                    connection_handle, handle,
                    (u+list(reversed([ord(b) for b in uuid])))))
        # Stage ble_evt_attclient_procedure_completed (success)
        backend._ser.stage_output(
            BGAPIPacketBuilder.attclient_procedure_completed(
                connection_handle, 0x0000, 0xFFFF))

    def stage_char_read_packets(
            self, backend, att_handle, att_type, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_read_by_handle (success)
        backend._ser.stage_output(BGAPIPacketBuilder.attclient_read_by_handle(
            connection_handle, 0x0000))
        # Stage ble_evt_attclient_attribute_value
        backend._ser.stage_output(BGAPIPacketBuilder.attclient_attribute_value(
            connection_handle, att_handle, att_type, [len(value)+1]+value))

    def stage_char_write_packets(
            self, backend, handle, value, connection_handle=0x00):
        # Stage ble_rsp_attclient_attribute_write (success)
        backend._ser.stage_output(BGAPIPacketBuilder.attclient_attribute_write(
            connection_handle, 0x0000))
        # Stage ble_evt_attclient_procedure_completed
        backend._ser.stage_output(
            BGAPIPacketBuilder.attclient_procedure_completed(
                connection_handle, 0x0000, handle))

    def stage_subscribe_packets(self, backend, uuid_char, handle_char,
                                indications=False, connection_handle=0x00):
        # Stage get_handle packets
        uuid_desc = '2902'
        handle_desc = 0x5678
        self.stage_get_handle_packets(backend, [
            uuid_char, handle_char,
            uuid_desc, handle_desc])
        handle = backend.get_handle(uuid_to_bytearray(uuid_char),
                                    uuid_to_bytearray(uuid_desc))
        # Stage char_write packets
        if indications:
            value = [0x02, 0x00]
        else:
            value = [0x01, 0x00]
        self.stage_char_write_packets(backend, handle, value,
                                      connection_handle=connection_handle)

    def stage_indication_packets(
            self, backend, handle, packet_values, connection_handle=0x00):
        # Stage ble_evt_attclient_attribute_value
        for value in packet_values:
            val = list(value)
            backend._ser.stage_output(
                BGAPIPacketBuilder.attclient_attribute_value(
                    connection_handle, handle, 0x00, value=[len(val)+1]+val))
