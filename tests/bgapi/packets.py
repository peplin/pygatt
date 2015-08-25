from struct import pack


class BGAPIPacketBuilder(object):
    @staticmethod
    def ble_rsp_attclient_attribute_write(
            connection_handle, return_code):
        # TODO create a Packet class to wrap this, where you pass in the various
        # values, then call .pack(). where do we unpack? could that be the same
        # class?
        # NOTE: I think that would be more trouble than it is worth. No need to
        #       introduce the extra complexity
        return pack('<4BBH', 0x00, 0x03, 0x04, 0x05, connection_handle,
                    return_code)

    @staticmethod
    def ble_rsp_attclient_find_information(
            connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x04, 0x03, connection_handle,
                    return_code)

    @staticmethod
    def ble_rsp_attclient_read_by_handle(connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x04, 0x04, connection_handle,
                    return_code)

    @staticmethod
    def ble_rsp_connection_disconnect(connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x03, 0x00, connection_handle,
                    return_code)

    @staticmethod
    def ble_rsp_connection_get_rssi(connection_handle, rssi_value):
        return pack('<4BBb', 0x00, 0x02, 0x03, 0x01, connection_handle,
                    rssi_value)

    @staticmethod
    def ble_rsp_gap_connect_direct(connection_handle, return_code):
        return pack('<4BHB', 0x00, 0x03, 0x06, 0x03, return_code,
                    connection_handle)

    @staticmethod
    def ble_rsp_gap_discover(return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x02, return_code)

    @staticmethod
    def ble_rsp_gap_end_procedure(return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x04, return_code)

    @staticmethod
    def ble_rsp_gap_set_mode(return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x01, return_code)

    @staticmethod
    def ble_rsp_gap_set_scan_parameters(return_code):
        return pack('<4BH', 0x00, 0x02, 0x06, 0x07, return_code)

    @staticmethod
    def ble_rsp_sm_delete_bonding(return_code):
        return pack('<4BH', 0x00, 0x02, 0x05, 0x02, return_code)

    @staticmethod
    def ble_rsp_sm_encrypt_start(connection_handle, return_code):
        return pack('<4BBH', 0x00, 0x03, 0x05, 0x00, connection_handle,
                    return_code)

    @staticmethod
    def ble_rsp_sm_get_bonds(num_bonds):
        assert((num_bonds >= 0) and (num_bonds <= 8))  # hardware constraint
        return pack('<4BB', 0x00, 0x01, 0x05, 0x05, num_bonds)

    @staticmethod
    def ble_rsp_sm_set_bondable_mode():
        return pack('<4B', 0x00, 0x00, 0x05, 0x01)

    @staticmethod
    def ble_evt_attclient_attribute_value(
            connection_handle, att_handle, att_type, value):
        # the first byte of value must be the length of value
        assert((len(value) > 0) and (value[0] == len(value)))
        return pack('<4BBHB' + str(len(value)) + 's', 0x80, 4 + len(value),
                    0x04, 0x05, connection_handle, att_handle, att_type,
                    b''.join(chr(i) for i in value))

    @staticmethod
    def ble_evt_attclient_find_information_found(connection_handle, chr_handle,
                                                 uuid):
        # the first byte of uuid must be the length of uuid
        assert((len(uuid) > 0) and (uuid[0] == len(uuid)))
        return pack('<4BBH' + str(len(uuid)) + 's', 0x80, 3 + len(uuid), 0x04,
                    0x04, connection_handle, chr_handle,
                    b''.join(chr(i) for i in uuid))

    @staticmethod
    def ble_evt_attclient_procedure_completed(
            connection_handle, return_code, chr_handle):
        return pack('<4BB2H', 0x80, 0x05, 0x04, 0x01, connection_handle,
                    return_code, chr_handle)

    @staticmethod
    def ble_evt_connection_status(addr, flags, connection_handle, address_type,
                                  connection_interval, timeout, latency,
                                  bonding):
        return pack(
            '<4B2B6BB3HB', 0x80, 0x10, 0x03, 0x00, connection_handle, flags,
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], address_type,
            connection_interval, timeout, latency, bonding)

    @staticmethod
    def ble_evt_connection_disconnected(connection_handle, return_code):
        return pack('<4BBH', 0x80, 0x03, 0x03, 0x04, connection_handle,
                    return_code)

    @staticmethod
    def ble_evt_gap_scan_response(
            rssi, packet_type, bd_addr, addr_type, bond, data):
        # the first byte of data must be the length of data
        assert((len(data) > 0) and (data[0] == len(data)))
        return pack('<4Bb9B' + str(len(data)) + 's', 0x80, 10 + len(data),
                    0x06, 0x00, rssi, packet_type, bd_addr[5], bd_addr[4],
                    bd_addr[3], bd_addr[2], bd_addr[1], bd_addr[0], addr_type,
                    bond, b''.join(chr(i) for i in data))

    @staticmethod
    def ble_evt_sm_bond_status(bond_handle, keysize, mitm, keys):
        return pack('<4B4B', 0x80, 0x04, 0x05, 0x04, bond_handle, keysize, mitm,
                    keys)

    @staticmethod
    def ble_evt_sm_bonding_fail(connection_handle, return_code):
        return pack('<4BBH', 0x80, 0x03, 0x05, 0x01, connection_handle,
                    return_code)
