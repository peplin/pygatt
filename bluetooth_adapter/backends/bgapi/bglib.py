"""
MODIFIED Bluegiga BGAPI/BGLib implementation
============================================
Bluegiga BGLib Python interface library
2013-05-04 by Jeff Rowberg <jeff@rowberg.net>
Updates should (hopefully) always be available at
https://github.com/jrowberg/bglib
Thanks to Masaaki Shibata for Python event handler code
http://www.emptypage.jp/notes/pyevent.en.html
============================================
BGLib Python interface library code is placed under the MIT license
Copyright (c) 2013 Jeff Rowberg

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
===============================================
"""

from __future__ import print_function

from enum import Enum
import logging
from struct import pack, unpack


log = logging.getLogger(__name__)


class PacketType(Enum):
    """Packet type enum for packets received."""
    # Responses
    ble_rsp_system_reset = 0
    ble_rsp_system_hello = 1
    ble_rsp_system_address_get = 2
    ble_rsp_system_reg_write = 3
    ble_rsp_system_reg_read = 4
    ble_rsp_system_get_counters = 5
    ble_rsp_system_get_connections = 6
    ble_rsp_system_read_memory = 7
    ble_rsp_system_get_info = 8
    ble_rsp_system_endpoint_tx = 9
    ble_rsp_system_whitelist_append = 10
    ble_rsp_system_whitelist_remove = 11
    ble_rsp_system_whitelist_clear = 12
    ble_rsp_system_endpoint_rx = 13
    ble_rsp_system_endpoint_set_watermarks = 14
    ble_rsp_flash_ps_defrag = 15
    ble_rsp_flash_ps_dump = 16
    ble_rsp_flash_ps_erase_all = 17
    ble_rsp_flash_ps_save = 18
    ble_rsp_flash_ps_load = 19
    ble_rsp_flash_ps_erase = 20
    ble_rsp_flash_erase_page = 21
    ble_rsp_flash_write_words = 22
    ble_rsp_attributes_write = 23
    ble_rsp_attributes_read = 24
    ble_rsp_attributes_read_type = 25
    ble_rsp_attributes_user_read_response = 26
    ble_rsp_attributes_user_write_response = 27
    ble_rsp_connection_disconnect = 28
    ble_rsp_connection_get_rssi = 29
    ble_rsp_connection_update = 30
    ble_rsp_connection_version_update = 31
    ble_rsp_connection_channel_map_get = 32
    ble_rsp_connection_channel_map_set = 33
    ble_rsp_connection_features_get = 34
    ble_rsp_connection_get_status = 35
    ble_rsp_connection_raw_tx = 36
    ble_rsp_attclient_find_by_type_value = 37
    ble_rsp_attclient_read_by_group_type = 38
    ble_rsp_attclient_read_by_type = 39
    ble_rsp_attclient_find_information = 40
    ble_rsp_attclient_read_by_handle = 41
    ble_rsp_attclient_attribute_write = 42
    ble_rsp_attclient_write_command = 43
    ble_rsp_attclient_indicate_confirm = 44
    ble_rsp_attclient_read_long = 45
    ble_rsp_attclient_prepare_write = 46
    ble_rsp_attclient_execute_write = 47
    ble_rsp_attclient_read_multiple = 48
    ble_rsp_sm_encrypt_start = 49
    ble_rsp_sm_set_bondable_mode = 50
    ble_rsp_sm_delete_bonding = 51
    ble_rsp_sm_set_parameters = 52
    ble_rsp_sm_passkey_entry = 53
    ble_rsp_sm_get_bonds = 54
    ble_rsp_sm_set_oob_data = 55
    ble_rsp_gap_set_privacy_flags = 56
    ble_rsp_gap_set_mode = 57
    ble_rsp_gap_discover = 58
    ble_rsp_gap_connect_direct = 59
    ble_rsp_gap_end_procedure = 60
    ble_rsp_gap_connect_selective = 61
    ble_rsp_gap_set_filtering = 62
    ble_rsp_gap_set_scan_parameters = 63
    ble_rsp_gap_set_adv_parameters = 64
    ble_rsp_gap_set_adv_data = 65
    ble_rsp_gap_set_directed_connectable_mode = 66
    ble_rsp_hardware_io_port_config_irq = 67
    ble_rsp_hardware_set_soft_timer = 68
    ble_rsp_hardware_adc_read = 69
    ble_rsp_hardware_io_port_config_direction = 70
    ble_rsp_hardware_io_port_config_function = 71
    ble_rsp_hardware_io_port_config_pull = 72
    ble_rsp_hardware_io_port_write = 73
    ble_rsp_hardware_io_port_read = 74
    ble_rsp_hardware_spi_config = 75
    ble_rsp_hardware_spi_transfer = 76
    ble_rsp_hardware_i2c_read = 77
    ble_rsp_hardware_i2c_write = 78
    ble_rsp_hardware_set_txpower = 79
    ble_rsp_hardware_timer_comparator = 80
    ble_rsp_test_phy_tx = 81
    ble_rsp_test_phy_rx = 82
    ble_rsp_test_phy_end = 83
    ble_rsp_test_phy_reset = 84
    ble_rsp_test_get_channel_map = 85
    ble_rsp_test_debug = 86
    # Events
    ble_evt_system_boot = 87
    ble_evt_system_debug = 88
    ble_evt_system_endpoint_watermark_rx = 89
    ble_evt_system_endpoint_watermark_tx = 90
    ble_evt_system_script_failure = 91
    ble_evt_system_no_license_key = 92
    ble_evt_flash_ps_key = 93
    ble_evt_attributes_value = 94
    ble_evt_attributes_user_read_request = 95
    ble_evt_attributes_status = 96
    ble_evt_connection_status = 97
    ble_evt_connection_version_ind = 98
    ble_evt_connection_feature_ind = 99
    ble_evt_connection_raw_rx = 100
    ble_evt_connection_disconnected = 101
    ble_evt_attclient_indicated = 102
    ble_evt_attclient_procedure_completed = 103
    ble_evt_attclient_group_found = 104
    ble_evt_attclient_attribute_found = 105
    ble_evt_attclient_find_information_found = 106
    ble_evt_attclient_attribute_value = 107
    ble_evt_attclient_read_multiple_response = 108
    ble_evt_sm_smp_data = 109
    ble_evt_sm_bonding_fail = 110
    ble_evt_sm_passkey_display = 111
    ble_evt_sm_passkey_request = 112
    ble_evt_sm_bond_status = 113
    ble_evt_gap_scan_response = 114
    ble_evt_gap_mode_changed = 115
    ble_evt_hardware_io_port_status = 116
    ble_evt_hardware_soft_timer = 117
    ble_evt_hardware_adc_result = 118


class BGLib(object):
    """
    Modified version of jrowberg's BGLib implementation.
    """
    def __init__(self):
        self.bgapi_rx_buffer = []
        self.bgapi_rx_expected_length = 0
        # Packet message types
        self._ble_event = 0x80
        self._ble_response = 0x00
        self._wifi_event = 0x88
        self._wifi_response = 0x08

    def ble_cmd_system_reset(self, boot_in_dfu):
        log.debug("construct command ble_cmd_system_reset")
        return pack('<4BB', 0, 1, 0, 0, boot_in_dfu)

    def ble_cmd_system_hello(self):
        log.debug("construct command ble_cmd_system_hello")
        return pack('<4B', 0, 0, 0, 1)

    def ble_cmd_system_address_get(self):
        log.debug("construct command ble_cmd_system_address_get")
        return pack('<4B', 0, 0, 0, 2)

    def ble_cmd_system_reg_write(self, address, value):
        log.debug("construct command ble_cmd_system_reg_write")
        return pack('<4BHB', 0, 3, 0, 3, address, value)

    def ble_cmd_system_reg_read(self, address):
        log.debug("construct command ble_cmd_system_reg_read")
        return pack('<4BH', 0, 2, 0, 4, address)

    def ble_cmd_system_get_counters(self):
        log.debug("construct command ble_cmd_system_get_counters")
        return pack('<4B', 0, 0, 0, 5)

    def ble_cmd_system_get_connections(self):
        log.debug("construct command ble_cmd_system_get_connections")
        return pack('<4B', 0, 0, 0, 6)

    def ble_cmd_system_read_memory(self, address, length):
        log.debug("construct command ble_cmd_system_read_memory")
        return pack('<4BIB', 0, 5, 0, 7, address, length)

    def ble_cmd_system_get_info(self):
        log.debug("construct command ble_cmd_system_get_info")
        return pack('<4B', 0, 0, 0, 8)

    def ble_cmd_system_endpoint_tx(self, endpoint, data):
        log.debug("construct command ble_cmd_system_endpoint_tx")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 0, 9,
                    endpoint, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_system_whitelist_append(self, address, address_type):
        log.debug("construct command ble_cmd_system_whitelist_append")
        return pack('<4B6sB', 0, 7, 0, 10, b''.join(chr(i) for i in address),
                    address_type)

    def ble_cmd_system_whitelist_remove(self, address, address_type):
        log.debug("construct command ble_cmd_system_whitelist_remove")
        return pack('<4B6sB', 0, 7, 0, 11, b''.join(chr(i) for i in address),
                    address_type)

    def ble_cmd_system_whitelist_clear(self):
        log.debug("construct command ble_cmd_system_whitelist_clear")
        return pack('<4B', 0, 0, 0, 12)

    def ble_cmd_system_endpoint_rx(self, endpoint, size):
        log.debug("construct command ble_cmd_system_endpoint_rx")
        return pack('<4BBB', 0, 2, 0, 13, endpoint, size)

    def ble_cmd_system_endpoint_set_watermarks(self, endpoint, rx, tx):
        log.debug(
            "construct command ble_cmd_system_endpoint_set_watermarks")
        return pack('<4BBBB', 0, 3, 0, 14, endpoint, rx, tx)

    def ble_cmd_flash_ps_defrag(self):
        log.debug("construct command ble_cmd_flash_ps_defrag")
        return pack('<4B', 0, 0, 1, 0)

    def ble_cmd_flash_ps_dump(self):
        log.debug("construct command ble_cmd_flash_ps_dump")
        return pack('<4B', 0, 0, 1, 1)

    def ble_cmd_flash_ps_erase_all(self):
        log.debug("construct command ble_cmd_flash_ps_erase_all")
        return pack('<4B', 0, 0, 1, 2)

    def ble_cmd_flash_ps_save(self, key, value):
        log.debug("construct command ble_cmd_flash_ps_save")
        return pack('<4BHB' + str(len(value)) + 's', 0, 3 + len(value), 1, 3,
                    key, len(value), b''.join(chr(i) for i in value))

    def ble_cmd_flash_ps_load(self, key):
        log.debug("construct command ble_cmd_flash_ps_load")
        return pack('<4BH', 0, 2, 1, 4, key)

    def ble_cmd_flash_ps_erase(self, key):
        log.debug("construct command ble_cmd_flash_ps_erase")
        return pack('<4BH', 0, 2, 1, 5, key)

    def ble_cmd_flash_erase_page(self, page):
        log.debug("construct command ble_cmd_flash_ps_erase_page")
        return pack('<4BB', 0, 1, 1, 6, page)

    def ble_cmd_flash_write_words(self, address, words):
        log.debug("construct command ble_cmd_flash_write_words")
        return pack('<4BHB' + str(len(words)) + 's', 0, 3 + len(words), 1, 7,
                    address, len(words), b''.join(chr(i) for i in words))

    def ble_cmd_attributes_write(self, handle, offset, value):
        log.debug("construct command ble_cmd_attributes_write")
        return pack('<4BHBB' + str(len(value)) + 's', 0, 4 + len(value), 2, 0,
                    handle, offset, len(value), b''.join(chr(i) for i in value))

    def ble_cmd_attributes_read(self, handle, offset):
        log.debug("construct command ble_cmd_attributes_read")
        return pack('<4BHH', 0, 4, 2, 1, handle, offset)

    def ble_cmd_attributes_read_type(self, handle):
        log.debug("construct command ble_cmd_attributes_read_type")
        return pack('<4BH', 0, 2, 2, 2, handle)

    def ble_cmd_attributes_user_read_response(self, connection, att_error,
                                              value):
        log.debug(
            "construct command ble_cmd_attributes_user_read_response")
        return pack('<4BBBB' + str(len(value)) + 's', 0, 3 + len(value), 2, 3,
                    connection, att_error, len(value),
                    b''.join(chr(i) for i in value))

    def ble_cmd_attributes_user_write_response(self, connection, att_error):
        log.debug(
            "construct command ble_cmd_attributes_user_write_response")
        return pack('<4BBB', 0, 2, 2, 4, connection, att_error)

    def ble_cmd_connection_disconnect(self, connection):
        log.debug("construct command ble_cmd_connection_disconnnect")
        return pack('<4BB', 0, 1, 3, 0, connection)

    def ble_cmd_connection_get_rssi(self, connection):
        log.debug("construct command ble_cmd_connection_get_rssi")
        return pack('<4BB', 0, 1, 3, 1, connection)

    def ble_cmd_connection_update(self, connection, interval_min, interval_max,
                                  latency, timeout):
        log.debug("construct command ble_cmd_connection_update")
        return pack('<4BBHHHH', 0, 9, 3, 2, connection, interval_min,
                    interval_max, latency, timeout)

    def ble_cmd_connection_version_update(self, connection):
        log.debug("construct command ble_cmd_connection_version_update")
        return pack('<4BB', 0, 1, 3, 3, connection)

    def ble_cmd_connection_channel_map_get(self, connection):
        log.debug(
            "construct command ble_cmd_connection_channel_map_get")
        return pack('<4BB', 0, 1, 3, 4, connection)

    def ble_cmd_connection_channel_map_set(self, connection, map):
        log.debug(
            "construct command ble_cmd_connection_channel_map_set")
        return pack('<4BBB' + str(len(map)) + 's', 0, 2 + len(map), 3, 5,
                    connection, len(map), b''.join(chr(i) for i in map))

    def ble_cmd_connection_features_get(self, connection):
        log.debug("construct command ble_cmd_connection_features_get")
        return pack('<4BB', 0, 1, 3, 6, connection)

    def ble_cmd_connection_get_status(self, connection):
        log.debug("construct command ble_cmd_connection_get_status")
        return pack('<4BB', 0, 1, 3, 7, connection)

    def ble_cmd_connection_raw_tx(self, connection, data):
        log.debug("construct command ble_cmd_connection_raw_tx")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 3, 8,
                    connection, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_attclient_find_by_type_value(self, connection, start, end, uuid,
                                             value):
        log.debug(
            "construct command ble_cmd_attclient_find_by_type_value")
        return pack('<4BBHHHB' + str(len(value)) + 's', 0, 8 + len(value), 4, 0,
                    connection, start, end, uuid, len(value),
                    b''.join(chr(i) for i in value))

    def ble_cmd_attclient_read_by_group_type(self, connection, start, end,
                                             uuid):
        log.debug(
            "construct command ble_cmd_attclient_read_by_group_type")
        return pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 1,
                    connection, start, end, len(uuid),
                    b''.join(chr(i) for i in uuid))

    def ble_cmd_attclient_read_by_type(self, connection, start, end, uuid):
        log.debug("construct command ble_cmd_attclient_read_by_type")
        return pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 2,
                    connection, start, end, len(uuid),
                    b''.join(chr(i) for i in uuid))

    def ble_cmd_attclient_find_information(self, connection, start, end):
        log.debug(
            "construct command ble_cmd_attclient_find_information")
        return pack('<4BBHH', 0, 5, 4, 3, connection, start, end)

    def ble_cmd_attclient_read_by_handle(self, connection, chrhandle):
        log.debug("construct command ble_cmd_attclient_read_by_handle")
        return pack('<4BBH', 0, 3, 4, 4, connection, chrhandle)

    def ble_cmd_attclient_attribute_write(self, connection, atthandle, data):
        log.debug("construct command ble_cmd_attclient_attribute_write")
        return pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 5,
                    connection, atthandle, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_write_command(self, connection, atthandle, data):
        log.debug("construct command ble_cmd_attclient_write_command")
        return pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 6,
                    connection, atthandle, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_indicate_confirm(self, connection):
        log.debug(
            "construct command ble_cmd_attclient_indicate_confirm")
        return pack('<4BB', 0, 1, 4, 7, connection)

    def ble_cmd_attclient_read_long(self, connection, chrhandle):
        log.debug("construct command ble_cmd_attclient_read_long")
        return pack('<4BBH', 0, 3, 4, 8, connection, chrhandle)

    def ble_cmd_attclient_prepare_write(self, connection, atthandle, offset,
                                        data):
        log.debug("construct command ble_cmd_attclient_prepare_write")
        return pack('<4BBHHB' + str(len(data)) + 's', 0, 6 + len(data), 4, 9,
                    connection, atthandle, offset, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_execute_write(self, connection, commit):
        log.debug("construct command ble_cmd_attclient_execute_write")
        return pack('<4BBB', 0, 2, 4, 10, connection, commit)

    def ble_cmd_attclient_read_multiple(self, connection, handles):
        log.debug("construct command ble_cmd_attclient_read_multiple")
        return pack('<4BBB' + str(len(handles)) + 's', 0, 2 + len(handles), 4,
                    11, connection, len(handles),
                    b''.join(chr(i) for i in handles))

    def ble_cmd_sm_encrypt_start(self, handle, bonding):
        log.debug("construct command ble_cmd_sm_encrypt_start")
        return pack('<4BBB', 0, 2, 5, 0, handle, bonding)

    def ble_cmd_sm_set_bondable_mode(self, bondable):
        log.debug("construct command ble_cmd_sm_set_bondable_mode")
        return pack('<4BB', 0, 1, 5, 1, bondable)

    def ble_cmd_sm_delete_bonding(self, handle):
        log.debug("construct command ble_cmd_sm_delete_bonding")
        return pack('<4BB', 0, 1, 5, 2, handle)

    def ble_cmd_sm_set_parameters(self, mitm, min_key_size, io_capabilities):
        log.debug("construct command ble_cmd_sm_set_parameters")
        return pack('<4BBBB', 0, 3, 5, 3, mitm, min_key_size, io_capabilities)

    def ble_cmd_sm_passkey_entry(self, handle, passkey):
        log.debug("construct command ble_cmd_sm_passkey_entry")
        return pack('<4BBI', 0, 5, 5, 4, handle, passkey)

    def ble_cmd_sm_get_bonds(self):
        log.debug("construct command ble_cmd_sm_get_bonds")
        return pack('<4B', 0, 0, 5, 5)

    def ble_cmd_sm_set_oob_data(self, oob):
        log.debug("construct command ble_cmd_sm_oob_data")
        return pack('<4BB' + str(len(oob)) + 's', 0, 1 + len(oob), 5, 6,
                    len(oob), b''.join(chr(i) for i in oob))

    def ble_cmd_gap_set_privacy_flags(self, peripheral_privacy,
                                      central_privacy):
        log.debug("construct command ble_cmd_gap_set_privacy_flags")
        return pack('<4BBB', 0, 2, 6, 0, peripheral_privacy, central_privacy)

    def ble_cmd_gap_set_mode(self, discover, connect):
        log.debug("construct command ble_cmd_gap_set_mode")
        return pack('<4BBB', 0, 2, 6, 1, discover, connect)

    def ble_cmd_gap_discover(self, mode):
        log.debug("construct command ble_cmd_gap_discover")
        return pack('<4BB', 0, 1, 6, 2, mode)

    def ble_cmd_gap_connect_direct(self, address, addr_type, conn_interval_min,
                                   conn_interval_max, timeout, latency):
        log.debug("construct command ble_cmd_gap_connect_direct")
        return pack('<4B6sBHHHH', 0, 15, 6, 3,
                    b''.join(chr(i) for i in address), addr_type,
                    conn_interval_min, conn_interval_max, timeout, latency)

    def ble_cmd_gap_end_procedure(self):
        log.debug("construct command ble_cmd_gap_end_procedure")
        return pack('<4B', 0, 0, 6, 4)

    def ble_cmd_gap_connect_selective(self, conn_interval_min,
                                      conn_interval_max, timeout, latency):
        log.debug("construct command ble_cmd_gap_connect_selective")
        return pack('<4BHHHH', 0, 8, 6, 5, conn_interval_min, conn_interval_max,
                    timeout, latency)

    def ble_cmd_gap_set_filtering(self, scan_policy, adv_policy,
                                  scan_duplicate_filtering):
        log.debug("construct command ble_cmd_gap_set_filtering")
        return pack('<4BBBB', 0, 3, 6, 6, scan_policy, adv_policy,
                    scan_duplicate_filtering)

    def ble_cmd_gap_set_scan_parameters(self, scan_interval, scan_window,
                                        active):
        log.debug("construct command ble_cmd_gap_set_scan_parameters")
        return pack('<4BHHB', 0, 5, 6, 7, scan_interval, scan_window, active)

    def ble_cmd_gap_set_adv_parameters(self, adv_interval_min,
                                       adv_interval_max, adv_channels):
        log.debug("construct command ble_cmd_gap_set_adv_parameters")
        return pack('<4BHHB', 0, 5, 6, 8, adv_interval_min, adv_interval_max,
                    adv_channels)

    def ble_cmd_gap_set_adv_data(self, set_scanrsp, adv_data):
        log.debug("construct command ble_cmd_gap_set_adv_data")
        return pack('<4BBB' + str(len(adv_data)) + 's', 0, 2 + len(adv_data), 6,
                    9, set_scanrsp, len(adv_data),
                    b''.join(chr(i) for i in adv_data))

    def ble_cmd_gap_set_directed_connectable_mode(self, address, addr_type):
        log.debug(
            "construct command ble_cmd_gap_set_directed_connectable_mode")
        return pack('<4B6sB', 0, 7, 6, 10, b''.join(chr(i) for i in address),
                    addr_type)

    def ble_cmd_hardware_io_port_config_irq(self, port, enable_bits,
                                            falling_edge):
        log.debug(
            "construct command ble_cmd_hardware_io_port_config_irq")
        return pack('<4BBBB', 0, 3, 7, 0, port, enable_bits, falling_edge)

    def ble_cmd_hardware_set_soft_timer(self, time, handle, single_shot):
        log.debug("construct command ble_cmd_hardware_set_soft_timer")
        return pack('<4BIBB', 0, 6, 7, 1, time, handle, single_shot)

    def ble_cmd_hardware_adc_read(self, input, decimation, reference_selection):
        log.debug("construct command ble_cmd_hardware_adc_read")
        return pack('<4BBBB', 0, 3, 7, 2, input, decimation,
                    reference_selection)

    def ble_cmd_hardware_io_port_config_direction(self, port, direction):
        log.debug(
            "construct command ble_cmd_hardware_io_port_config_direction")
        return pack('<4BBB', 0, 2, 7, 3, port, direction)

    def ble_cmd_hardware_io_port_config_function(self, port, function):
        log.debug(
            "construct command ble_cmd_hardware_io_port_config_function")
        return pack('<4BBB', 0, 2, 7, 4, port, function)

    def ble_cmd_hardware_io_port_config_pull(self, port, tristate_mask,
                                             pull_up):
        log.debug(
            "construct command ble_cmd_hardware_io_port_config_pull")
        return pack('<4BBBB', 0, 3, 7, 5, port, tristate_mask, pull_up)

    def ble_cmd_hardware_io_port_write(self, port, mask, data):
        log.debug("construct command ble_cmd_hardware_io_prot_write")
        return pack('<4BBBB', 0, 3, 7, 6, port, mask, data)

    def ble_cmd_hardware_io_port_read(self, port, mask):
        log.debug("construct command ble_cmd_hardware_io_port_read")
        return pack('<4BBB', 0, 2, 7, 7, port, mask)

    def ble_cmd_hardware_spi_config(self, channel, polarity, phase, bit_order,
                                    baud_e, baud_m):
        log.debug("construct command ble_cmd_hardware_spi_config")
        return pack('<4BBBBBBB', 0, 6, 7, 8, channel, polarity, phase,
                    bit_order, baud_e, baud_m)

    def ble_cmd_hardware_spi_transfer(self, channel, data):
        log.debug("construct command ble_cmd_hardware_spi_transfer")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 7, 9,
                    channel, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_hardware_i2c_read(self, address, stop, length):
        log.debug("construct command ble_cmd_hardware_i2c_read")
        return pack('<4BBBB', 0, 3, 7, 10, address, stop, length)

    def ble_cmd_hardware_i2c_write(self, address, stop, data):
        log.debug("construct command ble_cmd_hardware_i2c_write")
        return pack('<4BBBB' + str(len(data)) + 's', 0, 3 + len(data), 7, 11,
                    address, stop, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_hardware_set_txpower(self, power):
        log.debug("construct command ble_cmd_hardware_set_txpower")
        return pack('<4BB', 0, 1, 7, 12, power)

    def ble_cmd_hardware_timer_comparator(self, timer, channel, mode,
                                          comparator_value):
        log.debug("construct command ble_cmd_hardware_timer_comparator")
        return pack('<4BBBBH', 0, 5, 7, 13, timer, channel, mode,
                    comparator_value)

    def ble_cmd_test_phy_tx(self, channel, length, type):
        log.debug("construct command ble_cmd_test_phy_tx")
        return pack('<4BBBB', 0, 3, 8, 0, channel, length, type)

    def ble_cmd_test_phy_rx(self, channel):
        log.debug("construct command ble_cmd_test_phy_rx")
        return pack('<4BB', 0, 1, 8, 1, channel)

    def ble_cmd_test_phy_end(self):
        log.debug("construct command ble_cmd_test_phy_end")
        return pack('<4B', 0, 0, 8, 2)

    def ble_cmd_test_phy_reset(self):
        log.debug("construct command ble_cmd_test_phy_reset")
        return pack('<4B', 0, 0, 8, 3)

    def ble_cmd_test_get_channel_map(self):
        log.debug("construct command ble_cmd_test_get_channel_map")
        return pack('<4B', 0, 0, 8, 4)

    def ble_cmd_test_debug(self, input):
        log.debug("construct command ble_cmd_test_debug")
        return pack('<4BB' + str(len(input)) + 's', 0, 1 + len(input), 8, 5,
                    len(input), b''.join(chr(i) for i in input))

    def send_command(self, ser, packet):
        """
        Send a packet to the BLED12 over serial.

        ser -- The serial.Serial object to write to.
        packet -- The packet to write.
        """
        log.debug("Sending command")
        ser.write(packet)

    def parse_byte(self, byte):
        """
        Re-build packets read in from bytes over serial one byte at a time.

        byte -- the next byte to add to the packet.

        Returns a list of the bytes in the packet once a full packet is read.
        Returns None otherwise.
        """
        if (len(self.bgapi_rx_buffer) == 0 and
            (byte == self._ble_event or byte == self._ble_response or
             byte == self._wifi_event or byte == self._wifi_response)):
            self.bgapi_rx_buffer.append(byte)
        elif len(self.bgapi_rx_buffer) == 1:
            self.bgapi_rx_buffer.append(byte)
            self.bgapi_rx_expected_length = 4 +\
                (self.bgapi_rx_buffer[0] & 0x07) + self.bgapi_rx_buffer[1]
        elif len(self.bgapi_rx_buffer) > 1:
            self.bgapi_rx_buffer.append(byte)

        if self.bgapi_rx_expected_length > 0 and\
           len(self.bgapi_rx_buffer) == self.bgapi_rx_expected_length:
            log.debug("read complete packet")
            packet = self.bgapi_rx_buffer
            self.bgapi_rx_buffer = []
            return packet
        return None

    def decode_packet(self, packet):
        """
        Decode the packet and call the appropriate handler for the packet type.

        packet -- a list of bytes in the packet to decode.

        Returns PacketType, args{}.

          BGAPI packet structure (as of 2012-11-07):
            Byte 0:
                  [7] - 1 bit, Message Type (MT)     Command/Response, 1 = Event
                [6:3] - 4 bits, Technology Type (TT)    0000 = BLE, 0001 = Wi-Fi
                [2:0] - 3 bits, Length High (LH)      Payload length (high bits)
            Byte 1:     8 bits, Length Low (LL)        Payload length (low bits)
            Byte 2:     8 bits, Class ID (CID)          Command class ID
            Byte 3:     8 bits, Command ID (CMD)         Command ID
            Bytes 4-n:  0 - 2048 Bytes, Payload (PL) Up to 2048 bytes of payload
        """
        assert(packet is not None)

        packet_type, payload_length, packet_class, packet_command = packet[:4]
        bgapi_rx_payload = b''.join(chr(i) for i in packet[4:])
        if packet_type & 0x88 == 0x00:
            # 0x00 = BLE response packet
            if packet_class == 0:
                if packet_command == 0:  # ble_rsp_system_reset
                    log.debug(
                        "decoding packet ble_rsp_system_reset")
                    return PacketType.ble_rsp_system_reset, {}
                elif packet_command == 1:  # ble_rsp_system_hello
                    log.debug(
                        "decoding packet ble_rsp_system_hello")
                    return PacketType.ble_rsp_system_hello, {}
                elif packet_command == 2:  # ble_rsp_system_address_get
                    log.debug(
                        "decoding packet ble_rsp_system_address_get")
                    address = unpack('<6s', bgapi_rx_payload[:6])[0]
                    address = [ord(b) for b in address]
                    args = {
                        'address': address
                    }
                    return PacketType.ble_rsp_system_address_get, args
                elif packet_command == 3:  # ble_rsp_system_reg_write
                    log.debug(
                        "decoding packet ble_rsp_system_reg_write")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_system_reg_write, args
                elif packet_command == 4:  # ble_rsp_system_reg_read
                    log.debug(
                        "decoding packet ble_rsp_system_reg_read")
                    address, value =\
                        unpack('<HB', bgapi_rx_payload[:3])
                    args = {
                        'address': address, 'value': value
                    }
                    return PacketType.ble_rsp_system_reg_read, args
                elif packet_command == 5:  # ble_rsp_system_get_counters
                    log.debug(
                        "decoding packet ble_rsp_system_get_counters")
                    txok, txretry, rxok, rxfail, mbuf =\
                        unpack('<BBBBB', bgapi_rx_payload[:5])
                    args = {
                        'txok': txok, 'txretry': txretry, 'rxok': rxok,
                        'rxfail': rxfail, 'mbuf': mbuf
                    }
                    return PacketType.ble_rsp_system_get_counters, args
                elif packet_command == 6:  # ble_rsp_system_get_connections
                    log.debug(
                        "decoding packet ble_rsp_system_get_connections")
                    maxconn = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'maxconn': maxconn
                    }
                    return PacketType.ble_rsp_system_get_connections, args
                elif packet_command == 7:  # ble_rsp_system_read_memory
                    log.debug(
                        "decoding packet ble_rsp_system_read_memory")
                    address, data_len =\
                        unpack('<IB', bgapi_rx_payload[:5])
                    data_data = [ord(b) for b in bgapi_rx_payload[5:]]
                    args = {
                        'address': address, 'data': data_data
                    }
                    return PacketType.ble_rsp_system_read_memory, args
                elif packet_command == 8:  # ble_rsp_system_get_info
                    log.debug(
                        "decoding packet ble_rsp_system_get_info")
                    data = unpack('<HHHHHBB', bgapi_rx_payload[:12])
                    args = {
                        'major': data[0], 'minor': data[1],
                        'patch': data[2], 'build': data[3],
                        'll_version': data[4], 'protocol_version': data[5],
                        'hw': data[6]
                    }
                    return PacketType.ble_rsp_system_get_info, args
                elif packet_command == 9:  # ble_rsp_system_endpoint_tx
                    log.debug(
                        "decoding packet ble_rsp_system_endpoint_tx")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_system_endpoint_tx, args
                # ble_rsp_system_whitelist_append
                elif packet_command == 10:
                    log.debug(
                        "decoding packet ble_rsp_system_whitelist_append")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_system_whitelist_append, args
                # ble_rsp_system_whitelist_remove
                elif packet_command == 11:
                    log.debug(
                        "decoding packet ble_rsp_system_whitelist_remove")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_system_whitelist_remove
                elif packet_command == 12:  # ble_rsp_system_whitelist_clear
                    log.debug(
                        "decoding packet ble_rsp_system_whitelist_clear")
                    return PacketType.ble_rsp_system_whitelist_clear, {}
                elif packet_command == 13:  # ble_rsp_system_endpoint_rx
                    log.debug(
                        "decoding packet ble_rsp_system_endpoint_rx")
                    result, data_len =\
                        unpack('<HB', bgapi_rx_payload[:3])
                    data_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'result': result, 'data': data_data
                    }
                    return PacketType.ble_rsp_system_endpoint_rx, args
                # ble_rsp_system_endpoint_set_watermarks
                elif packet_command == 14:
                    log.debug(
                        "decoding packet ble_rsp_system_endpoint_set_"
                        "watermarks")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.
                            ble_rsp_system_endpoint_set_watermarks, args)
            elif packet_class == 1:
                if packet_command == 0:  # ble_rsp_flash_ps_defrag
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_defrag")
                    return PacketType.ble_rsp_flash_ps_defrag, {}
                elif packet_command == 1:  # ble_rsp_flash_ps_dump
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_dump")
                    return PacketType.ble_rsp_flash_ps_dump, {}
                elif packet_command == 2:  # ble_rsp_flash_ps_erase_all
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_erase_all")
                    return PacketType.ble_rsp_flash_ps_erase_all, {}
                elif packet_command == 3:  # ble_rsp_flash_ps_save
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_save")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_flash_ps_save, args
                elif packet_command == 4:  # ble_rsp_flash_ps_load
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_load")
                    result, value_len = unpack('<HB',
                                               bgapi_rx_payload[:3])
                    value_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'result': result, 'value': value_data
                    }
                    return PacketType.ble_rsp_flash_ps_load, args
                elif packet_command == 5:  # ble_rsp_flash_ps_erase
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_erase")
                    return PacketType.ble_rsp_flash_ps_erase, {}
                elif packet_command == 6:  # ble_rsp_flash_ps_erase_page
                    log.debug(
                        "decoding packet ble_rsp_flash_ps_erase_page")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_flash_erase_page, args
                elif packet_command == 7:  # ble_rsp_flash_write_words
                    log.debug(
                        "decoding packet ble_rsp_flash_write_words")
                    return PacketType.ble_rsp_flash_write_words, {}
            elif packet_class == 2:
                if packet_command == 0:  # ble_rsp_attributes_write
                    log.debug(
                        "decoding packet ble_rsp_attributes_write")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_attributes_write, args
                elif packet_command == 1:  # ble_rsp_attributes_read
                    log.debug(
                        "decoding packet ble_rsp_attributes_read")
                    handle, offset, result, value_len = unpack(
                        '<HHHB', bgapi_rx_payload[:7]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[7:]]
                    args = {
                        'handle': handle, 'offset': offset,
                        'result': result, 'value': value_data
                    }
                    return PacketType.ble_rsp_attributes_read, args
                elif packet_command == 2:  # ble_rsp_attributes_read_type
                    log.debug(
                        "decoding packet ble_rsp_attributes_read_type")
                    handle, result, value_len = unpack(
                        '<HHB', bgapi_rx_payload[:5]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[5:]]
                    args = {
                        'handle': handle, 'result': result,
                        'value': value_data
                    }
                    return PacketType.ble_rsp_attributes_read_type, args
                # ble_rsp_attributes_user_read_response
                elif packet_command == 3:
                    log.debug(
                        "decoding packet ble_rsp_attributes_user_read_"
                        "response")
                    return (PacketType.
                            ble_rsp_attributes_user_read_response, {})
                # ble_rsp_attributes_user_write_response
                elif packet_command == 4:
                    log.debug(
                        "decoding packet ble_rsp_attributes_user_write_"
                        "response")
                    return (PacketType.
                            ble_rsp_attributes_user_write_response, {})
            elif packet_class == 3:
                if packet_command == 0:  # ble_rsp_connection_disconnect
                    log.debug(
                        "decoding packet ble_rsp_connection_disconnect")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_connection_disconnect, args
                elif packet_command == 1:  # ble_rsp_connection_get_rssi
                    log.debug(
                        "decoding packet ble_rsp_connection_get_rssi")
                    connection, rssi = unpack(
                        '<Bb', bgapi_rx_payload[:2]
                    )
                    args = {
                        'connection': connection, 'rssi': rssi
                    }
                    return PacketType.ble_rsp_connection_get_rssi, args
                elif packet_command == 2:  # ble_rsp_connection_update
                    log.debug(
                        "decoding packet ble_rsp_connection_update")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_connection_update, args
                # ble_rsp_connection_version_update
                elif packet_command == 3:
                    log.debug(
                        "decoding packet ble_rsp_connection_version_update")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.ble_rsp_connection_version_update,
                            args)
                # ble_rsp_connection_channel_map_get
                elif packet_command == 4:
                    log.debug(
                        "decoding packet ble_rsp_connection_channel_map_"
                        "get")
                    connection, map_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    map_data = [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'map': map_data
                    }
                    return (PacketType.ble_rsp_connection_channel_map_get,
                            args)
                # ble_rsp_connection_channel_map_set
                elif packet_command == 5:
                    log.debug(
                        "decoding packet ble_rsp_connection_channel_map_"
                        "set")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.ble_rsp_connection_channel_map_set,
                            args)
                elif packet_command == 6:  # ble_rsp_connection_features_get
                    log.debug(
                        "decoding packet ble_rsp_connection_features_get")
                    connection, result = unpack('<BH',
                                                bgapi_rx_payload[:3])
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_connection_features_get, args
                elif packet_command == 7:  # ble_rsp_connection_get_status
                    log.debug(
                        "decoding packet ble_rsp_connection_get_status")
                    connection = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'connection': connection
                    }
                    return PacketType.ble_rsp_connection_get_status, args
                elif packet_command == 8:  # ble_rsp_connection_raw_tx
                    log.debug(
                        "decoding packet ble_rsp_connection_raw_tx")
                    connection = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'connection': connection
                    }
                    return PacketType.ble_rsp_connection_raw_tx, args
            elif packet_class == 4:
                # ble_rsp_attclient_find_by_type_value
                if packet_command == 0:
                    log.debug(
                        "decoding packet ble_rsp_attclient_find_by_type_"
                        "value")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.
                            ble_rsp_attclient_find_by_type_value, args)
                # ble_rsp_attclient_read_by_group_type
                elif packet_command == 1:
                    log.debug(
                        "decoding packet ble_rsp_attclient_read_by_group_"
                        "type")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.
                            ble_rsp_attclient_read_by_group_type, args)
                elif packet_command == 2:  # ble_rsp_attclient_read_by_type
                    log.debug(
                        "decoding packet ble_rsp_attclient_read_by_type")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_attclient_read_by_type, args
                # ble_rsp_attclient_find_information
                elif packet_command == 3:
                    log.debug(
                        "decoding packet ble_rsp_attclient_find_"
                        "information")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.ble_rsp_attclient_find_information,
                            args)
                # ble_rsp_attclient_read_by_handle
                elif packet_command == 4:
                    log.debug(
                        "decoding packet ble_rsp_attclient_read_by_handle")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.ble_rsp_attclient_read_by_handle,
                            args)
                # ble_rsp_attclient_attribute_write
                elif packet_command == 5:
                    log.debug(
                        "decoding packet ble_rsp_attclient_attribute_write")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (PacketType.ble_rsp_attclient_attribute_write,
                            args)
                elif packet_command == 6:  # ble_rsp_attclient_write_command
                    log.debug(
                        "decoding packet ble_rsp_attclient_write_command")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_attclient_write_command, args
                # ble_rsp_attclient_indicate_confirm
                elif packet_command == 7:
                    log.debug(
                        "decoding packet ble_rsp_attclient_indicate_"
                        "confirm")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.ble_rsp_attclient_indicate_confirm,
                            args)
                elif packet_command == 8:  # ble_rsp_attclient_read_long
                    log.debug(
                        "decoding packet ble_rsp_attclient_read_long")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_attclient_read_long, args
                elif packet_command == 9:  # ble_rsp_attclient_prepare_write
                    log.debug(
                        "decoding packet ble_rsp_attclient_prepare_write")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_attclient_prepare_write, args
                # ble_rsp_attclient_execute_write
                elif packet_command == 10:
                    log.debug(
                        "decoding packet ble_rsp_attclient_execute_write")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_attclient_execute_write, args
                # ble_rsp_attclient_read_multiple
                elif packet_command == 11:
                    log.debug(
                        "decoding packet ble_rsp_attclient_read_multiple")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return PacketType.ble_rsp_attclient_read_multiple, args
            elif packet_class == 5:
                if packet_command == 0:  # ble_rsp_sm_encrypt_start
                    log.debug(
                        "decoding packet ble_rsp_sm_encrypt_start")
                    handle, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'handle': handle, 'result': result
                    }
                    return PacketType.ble_rsp_sm_encrypt_start, args
                elif packet_command == 1:  # ble_rsp_sm_set_bondable_mode
                    log.debug(
                        "decoding packet ble_rsp_sm_set_bondable_mode")
                    return PacketType.ble_rsp_sm_set_bondable_mode, {}
                elif packet_command == 2:  # ble_rsp_sm_delete_bonding
                    log.debug(
                        "decoding packet ble_rsp_sm_delete_bonding")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_sm_delete_bonding, args
                elif packet_command == 3:  # ble_rsp_sm_set_parameters
                    log.debug(
                        "decoding packet ble_rsp_sm_set_parameters")
                    return PacketType.ble_rsp_sm_set_parameters, {}
                elif packet_command == 4:  # ble_rsp_sm_passkey_entry
                    log.debug(
                        "decoding packet ble_rsp_sm_passkey_entry")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_sm_passkey_entry, args
                elif packet_command == 5:  # ble_rsp_sm_get_bonds
                    log.debug(
                        "decoding packet ble_rsp_sm_get_bonds")
                    bonds = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'bonds': bonds
                    }
                    return PacketType.ble_rsp_sm_get_bonds, args
                elif packet_command == 6:  # ble_rsp_sm_set_oob_data
                    log.debug(
                        "decoding packet ble_rsp_sm_set_oob_data")
                    return PacketType.ble_rsp_sm_set_oob_data, {}
            elif packet_class == 6:
                if packet_command == 0:  # ble_rsp_gap_set_privacy_flags
                    log.debug(
                        "decoding packet ble_rsp_gap_set_privacy_flags")
                    return PacketType.ble_rsp_gap_set_privacy_flags, {}
                elif packet_command == 1:  # ble_rsp_gap_set_mode
                    log.debug(
                        "decoding packet ble_rsp_gap_set_mode")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_set_mode, args
                elif packet_command == 2:  # ble_rsp_gap_discover
                    log.debug(
                        "decoding packet ble_rsp_gap_discover")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_discover, args
                elif packet_command == 3:  # ble_rsp_gap_connect_direct
                    log.debug(
                        "decoding packet ble_rsp_gap_connect_direct")
                    result, connection_handle = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    args = {
                        'result': result,
                        'connection_handle': connection_handle
                    }
                    return PacketType.ble_rsp_gap_connect_direct, args
                elif packet_command == 4:  # ble_rsp_gap_end_procedure
                    log.debug(
                        "decoding packet ble_rsp_gap_end_procedure")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_end_procedure, args
                elif packet_command == 5:  # ble_rsp_gap_connect_selective
                    log.debug(
                        "decoding packet ble_rsp_gap_connect_selective")
                    result, connection_handle = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    args = {
                        'result': result,
                        'connection_handle': connection_handle
                    }
                    return PacketType.ble_rsp_gap_connect_selective, args
                elif packet_command == 6:  # ble_rsp_gap_set_filtering
                    log.debug(
                        "decoding packet ble_rsp_gap_set_filtering")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_set_filtering, args
                elif packet_command == 7:  # ble_rsp_gap_set_scan_parameters
                    log.debug(
                        "decoding packet ble_rsp_gap_set_scan_parameters")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_set_scan_parameters, args
                elif packet_command == 8:  # ble_rsp_gap_set_adv_parameters
                    log.debug(
                        "decoding packet ble_rsp_gap_set_adv_parameters")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_set_adv_parameters, args
                elif packet_command == 9:  # ble_rsp_gap_set_adv_data
                    log.debug(
                        "decoding packet ble_rsp_gap_set_adv_data")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_gap_set_adv_data, args
                # ble_rsp_gap_set_directed_connectable_mode
                elif packet_command == 10:
                    log.debug(
                        "decoding packet ble_rsp_gap_set_directed_"
                        "connectable_mode")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.
                            ble_rsp_gap_set_directed_connectable_mode, args)
            elif packet_class == 7:
                # ble_rsp_hardware_io_port_config_irq
                if packet_command == 0:
                    log.debug(
                        "decoding packet ble_rsp_hardware_io_port_config_"
                        "irq")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.ble_rsp_hardware_io_port_config_irq,
                            args)
                elif packet_command == 1:  # ble_rsp_hardware_set_soft_timer
                    log.debug(
                        "decoding packet ble_rsp_hardware_set_soft_timer")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_hardware_set_soft_timer, args
                elif packet_command == 2:  # ble_rsp_hardware_adc_read
                    log.debug(
                        "decoding packet ble_rsp_hardware_adc_read")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_hardware_adc_read, args
                # ble_rsp_hardware_io_port_config_direction
                elif packet_command == 3:
                    log.debug(
                        "decoding packet ble_rsp_hardware_io_port_config_"
                        "direction")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.
                            ble_rsp_hardware_io_port_config_direction, args)
                # ble_rsp_hardware_io_port_config_function
                elif packet_command == 4:
                    log.debug(
                        "decoding packet ble_rsp_hardware_io_port_config_"
                        "function")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.
                            ble_rsp_hardware_io_port_config_function, args)
                # ble_rsp_hardware_io_port_config_pull
                elif packet_command == 5:
                    log.debug(
                        "decoding packet ble_rsp_hardware_io_port_config_"
                        "pull")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.
                            ble_rsp_hardware_io_port_config_pull, args)
                elif packet_command == 6:  # ble_rsp_hardware_io_port_write
                    log.debug(
                        "decoding packet ble_rsp_hardware_io_port_write")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_hardware_io_port_write, args
                elif packet_command == 7:  # ble_rsp_hardware_io_port_read
                    log.debug(
                        "decoding packet ble_rsp_hardware_io_port_read")
                    result, port, data = unpack(
                        '<HBB', bgapi_rx_payload[:4]
                    )
                    args = {
                        'result': result, 'port': port, 'data': data
                    }
                    return PacketType.ble_rsp_hardware_io_port_read, args
                elif packet_command == 8:  # ble_rsp_hardware_spi_config
                    log.debug(
                        "decoding packet ble_rsp_hardware_spi_config")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return PacketType.ble_rsp_hardware_spi_config, args
                elif packet_command == 9:  # ble_rsp_hardware_spi_transfer
                    log.debug(
                        "decoding packet ble_rsp_hardware_spi_transfer")
                    result, channel, data_len = unpack(
                        '<HBB', bgapi_rx_payload[:4]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[4:]]
                    args = {
                        'result': result, 'channel': channel,
                        'data': data_data
                    }
                    return PacketType.ble_rsp_hardware_spi_transfer, args
                elif packet_command == 10:  # ble_rsp_hardware_i2c_read
                    log.debug(
                        "decoding packet ble_rsp_hardware_i2c_read")
                    result, data_len = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'result': result, 'data': data_data
                    }
                    return PacketType.ble_rsp_hardware_i2c_read, args
                elif packet_command == 11:  # ble_rsp_hardware_i2c_write
                    log.debug(
                        "decoding packet ble_rsp_hardware_i2c_write")
                    written = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'written': written
                    }
                    return PacketType.ble_rsp_hardware_i2c_write, args
                elif packet_command == 12:  # ble_rsp_hardware_set_txpower
                    log.debug(
                        "decoding packet ble_rsp_hardware_set_txpower")
                    return PacketType.ble_rsp_hardware_set_txpower, {}
                # ble_rsp_hardware_timer_comparator
                elif packet_command == 13:
                    log.debug(
                        "decoding packet ble_rsp_hardware_timer_comparator")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (PacketType.
                            ble_rsp_hardware_timer_comparator, args)
            elif packet_class == 8:
                if packet_command == 0:  # ble_rsp_test_phy_tx
                    log.debug(
                        "decoding packet ble_rsp_test_phy_tx")
                    return PacketType.ble_rsp_test_phy_tx, {}
                elif packet_command == 1:  # ble_rsp_test_phy_rx
                    log.debug(
                        "decoding packet ble_rsp_test_phy_rx")
                    return PacketType.ble_rsp_test_phy_rx, {}
                elif packet_command == 2:  # ble_rsp_test_phy_end
                    log.debug(
                        "decoding packet ble_rsp_test_phy_end")
                    counter = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'counter': counter
                    }
                    return PacketType.ble_rsp_test_phy_end, args
                elif packet_command == 3:  # ble_rsp_test_phy_reset
                    log.debug(
                        "decoding packet ble_rsp_test_phy_reset")
                    return PacketType.ble_rsp_test_phy_reset, {}
                elif packet_command == 4:  # ble_rsp_test_get_channel_map
                    log.debug(
                        "decoding packet ble_rsp_test_get_channel_map")
                    # channel_map_len = unpack(
                    #    '<B', bgapi_rx_payload[:1]
                    # )[0]
                    channel_map_data =\
                        [ord(b) for b in bgapi_rx_payload[1:]]
                    args = {
                        'channel_map': channel_map_data
                    }
                    return PacketType.ble_rsp_test_get_channel_map, args
                elif packet_command == 5:  # ble_rsp_test_debug
                    log.debug(
                        "decoding packet ble_rsp_test_debug")
                    # output_len = unpack('<B',
                    #                     bgapi_rx_payload[:1])[0]
                    output_data =\
                        [ord(b) for b in bgapi_rx_payload[1:]]
                    args = {
                        'output': output_data
                    }
                    return PacketType.ble_rsp_test_debug, args
        elif packet_type & 0x88 == 0x80:
            # 0x80 = BLE event packet
            if packet_class == 0:
                if packet_command == 0:  # ble_evt_system_boot
                    log.debug(
                        "decoding packet ble_evt_system_boot")
                    data = unpack('<HHHHHBB', bgapi_rx_payload[:12])
                    args = {
                        'major': data[0], 'minor': data[1],
                        'patch': data[2], 'build': data[3],
                        'll_version': data[4], 'protocol_version': data[5],
                        'hw': data[6]
                    }
                    return PacketType.ble_evt_system_boot, args
                elif packet_command == 1:  # ble_evt_system_debug
                    log.debug(
                        "decoding packet ble_evt_system_debug")
                    data_len = unpack('<B', bgapi_rx_payload[:1])[0]
                    data_data = [ord(b) for b in bgapi_rx_payload[1:]]
                    args = {
                        'data': data_data
                    }
                    return PacketType.ble_evt_system_debug, args
                # ble_evt_system_endpoint_watermark_rx
                elif packet_command == 2:
                    log.debug(
                        "decoding packet ble_evt_system_endpoint_"
                        "watermark_rx")
                    endpoint, data = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    args = {
                        'endpoint': endpoint, 'data': data
                    }
                    return (PacketType.
                            ble_evt_system_endpoint_watermark_rx, args)
                # ble_evt_system_endpoint_watermark_tx
                elif packet_command == 3:
                    log.debug(
                        "decoding packet ble_evt_system_endpoint_"
                        "watermark_tx")
                    endpoint, data = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    args = {
                        'endpoint': endpoint, 'data': data
                    }
                    return (PacketType.
                            ble_evt_system_endpoint_watermark_tx, args)
                elif packet_command == 4:  # ble_evt_system_script_failure
                    log.debug(
                        "decoding packet ble_evt_system_script_failure")
                    address, reason = unpack(
                        '<HH', bgapi_rx_payload[:4]
                    )
                    args = {
                        'address': address, 'reason': reason
                    }
                    return PacketType.ble_evt_system_script_failure, args
                elif packet_command == 5:  # ble_evt_system_no_license_key
                    log.debug(
                        "decoding packet ble_evt_system_no_license_key")
                    return PacketType.ble_evt_system_no_license_key, {}
            elif packet_class == 1:
                if packet_command == 0:  # ble_evt_flash_ps_key
                    log.debug(
                        "decoding packet ble_evt_flash_ps_key")
                    key, value_len = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'key': key, 'value': value_data
                    }
                    return PacketType.ble_evt_flash_ps_key, args
            elif packet_class == 2:
                if packet_command == 0:  # ble_evt_attributes_value
                    log.debug(
                        "decoding packet ble_evt_attributes_value")
                    connection, reason, handle, offset, value_len = unpack(
                        '<BBHHB', bgapi_rx_payload[:7]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[7:]]
                    args = {
                        'connection': connection, 'reason': reason,
                        'handle': handle, 'offset': offset,
                        'value': value_data
                    }
                    return PacketType.ble_evt_attributes_value, args
                # ble_evt_attributes_user_read_request
                elif packet_command == 1:
                    log.debug(
                        "decoding packet ble_evt_attributes_user_read_"
                        "request")
                    connection, handle, offset, maxsize = unpack(
                        '<BHHB', bgapi_rx_payload[:6]
                    )
                    args = {
                        'connection': connection, 'handle': handle,
                        'offset': offset, 'maxsize': maxsize
                    }
                    return (PacketType.
                            ble_evt_attributes_user_read_request, args)
                elif packet_command == 2:  # ble_evt_attributes_status
                    log.debug(
                        "decoding packet ble_evt_attributes_status")
                    handle, flags = unpack('<HB', bgapi_rx_payload[:3])
                    args = {
                        'handle': handle, 'flags': flags
                    }
                    return PacketType.ble_evt_attributes_status, args
            elif packet_class == 3:
                if packet_command == 0:  # ble_evt_connection_status
                    log.debug(
                        "decoding packet ble_evt_connection_status")
                    data = unpack('<BB6sBHHHB', bgapi_rx_payload[:16])
                    address = [ord(b) for b in data[2]]
                    args = {
                        'connection': data[0], 'flags': data[1],
                        'address': address, 'address_type': data[3],
                        'conn_interval': data[4], 'timeout': data[5],
                        'latency': data[6], 'bonding': data[7]
                    }
                    return PacketType.ble_evt_connection_status, args
                elif packet_command == 1:  # ble_evt_connection_version_ind
                    log.debug(
                        "decoding packet ble_evt_connection_version_ind")
                    connection, vers_nr, comp_id, sub_vers_nr = unpack(
                        '<BBHH', bgapi_rx_payload[:6]
                    )
                    args = {
                        'connection': connection, 'vers_nr': vers_nr,
                        'comp_id': comp_id, 'sub_vers_nr': sub_vers_nr
                    }
                    return PacketType.ble_evt_connection_version_ind, args
                elif packet_command == 2:  # ble_evt_connection_feature_ind
                    log.debug(
                        "decoding packet ble_evt_connection_feature_ind")
                    connection, features_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    features_data =\
                        [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'features': features_data
                    }
                    return PacketType.ble_evt_connection_feature_ind, args
                elif packet_command == 3:  # ble_evt_connection_raw_rx
                    log.debug(
                        "decoding packet ble_evt_connection_raw_rx")
                    connection, data_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'data': data_data
                    }
                    return PacketType.ble_evt_connection_raw_rx, args
                elif packet_command == 4:  # ble_evt_connection_disconnected
                    log.debug(
                        "decoding packet ble_evt_connection_disconnected")
                    connection, reason = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'reason': reason
                    }
                    return PacketType.ble_evt_connection_disconnected, args
            elif packet_class == 4:
                if packet_command == 0:  # ble_evt_attclient_indicated
                    log.debug(
                        "decoding packet ble_evt_attclient_indicated")
                    connection, attrhandle = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'attrhandle': attrhandle
                    }
                    return PacketType.ble_evt_attclient_indicated, args
                # ble_evt_attclient_procedure_completed
                elif packet_command == 1:
                    log.debug(
                        "decoding packet ble_evt_attclient_procedure_"
                        "completed")
                    connection, result, chrhandle = unpack(
                        '<BHH', bgapi_rx_payload[:5]
                    )
                    args = {
                        'connection': connection, 'result': result,
                        'chrhandle': chrhandle
                    }
                    return (PacketType.
                            ble_evt_attclient_procedure_completed, args)
                elif packet_command == 2:  # ble_evt_attclient_group_found
                    log.debug(
                        "decoding packet ble_evt_attclient_group_found")
                    connection, start, end, uuid_len = unpack(
                        '<BHHB', bgapi_rx_payload[:6]
                    )
                    uuid_data = [ord(b) for b in bgapi_rx_payload[6:]]
                    args = {
                        'connection': connection, 'start': start,
                        'end': end, 'uuid': uuid_data
                    }
                    return PacketType.ble_evt_attclient_group_found, args
                # ble_evt_attclient_attribute_found
                elif packet_command == 3:
                    log.debug(
                        "decoding packet ble_evt_attclient_attribute_found")
                    data = unpack('<BHHBB', bgapi_rx_payload[:7])
                    uuid_data = [ord(b) for b in bgapi_rx_payload[7:]]
                    args = {
                        'connection': data[0], 'chrdecl': data[1],
                        'value': data[2], 'properties': data[3],
                        'uuid': uuid_data
                    }
                    return (PacketType.ble_evt_attclient_attribute_found,
                            args)
                # ble_evt_attclient_find_information_found
                elif packet_command == 4:
                    log.debug(
                        "decoding packet ble_evt_attclient_find_"
                        "information_found")
                    connection, chrhandle, uuid_len = unpack(
                        '<BHB', bgapi_rx_payload[:4]
                    )
                    uuid_data = [ord(b) for b in bgapi_rx_payload[4:]]
                    args = {
                        'connection': connection, 'chrhandle': chrhandle,
                        'uuid': uuid_data
                    }
                    return (PacketType.
                            ble_evt_attclient_find_information_found, args)
                # ble_evt_attclient_attribute_value
                elif packet_command == 5:
                    log.debug(
                        "decoding packet ble_evt_attclient_attribute_value")
                    connection, atthandle, type, value_len = unpack(
                        '<BHBB', bgapi_rx_payload[:5]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[5:]]
                    args = {
                        'connection': connection, 'atthandle': atthandle,
                        'type': type, 'value': value_data
                    }
                    return (PacketType.ble_evt_attclient_attribute_value,
                            args)
                # ble_evt_attclient_read_multiple_response
                elif packet_command == 6:
                    log.debug(
                        "decoding packet ble_evt_attclient_read_multiple_"
                        "response")
                    connection, handles_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    handles_data =\
                        [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'handles': handles_data
                    }
                    return (PacketType.
                            ble_evt_attclient_read_multiple_response, args)
            elif packet_class == 5:
                if packet_command == 0:  # ble_evt_sm_smp_data
                    log.debug(
                        "decoding packet ble_evt_sm_smp_data")
                    handle, packet, data_len = unpack(
                        '<BBB', bgapi_rx_payload[:3]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'handle': handle, 'packet': packet,
                        'data': data_data
                    }
                    return PacketType.ble_evt_sm_smp_data, args
                elif packet_command == 1:  # ble_evt_sm_bonding_fail
                    log.debug(
                        "decoding packet ble_evt_sm_bonding_fail")
                    handle, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'handle': handle, 'result': result
                    }
                    return PacketType.ble_evt_sm_bonding_fail, args
                elif packet_command == 2:  # ble_evt_sm_passkey_display
                    log.debug(
                        "decoding packet ble_evt_sm_passkey_display")
                    handle, passkey = unpack(
                        '<BI', bgapi_rx_payload[:5]
                    )
                    args = {
                        'handle': handle, 'passkey': passkey
                    }
                    return PacketType.ble_evt_sm_passkey_display, args
                elif packet_command == 3:  # ble_evt_sm_passkey_request
                    log.debug(
                        "decoding packet ble_evt_sm_passkey_request")
                    handle = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'handle': handle
                    }
                    return PacketType.ble_evt_sm_passkey_request, args
                elif packet_command == 4:  # ble_evt_sm_bond_status
                    log.debug(
                        "decoding packet ble_evt_sm_bond_status")
                    bond, keysize, mitm, keys = unpack(
                        '<BBBB', bgapi_rx_payload[:4]
                    )
                    args = {
                        'bond': bond, 'keysize': keysize, 'mitm': mitm,
                        'keys': keys
                    }
                    return PacketType.ble_evt_sm_bond_status, args
            elif packet_class == 6:
                if packet_command == 0:  # ble_evt_gap_scan_response
                    log.debug(
                        "decoding packet ble_evt_gap_scan_response")
                    data = unpack('<bB6sBBB', bgapi_rx_payload[:11])
                    sender = [ord(b) for b in data[2]]
                    data_data = [ord(b) for b in bgapi_rx_payload[11:]]
                    args = {
                        'rssi': data[0], 'packet_type': data[1],
                        'sender': sender, 'address_type': data[3],
                        'bond': data[4], 'data': data_data
                    }
                    return PacketType.ble_evt_gap_scan_response, args
                elif packet_command == 1:  # ble_evt_gap_mode_changed
                    log.debug(
                        "decoding packet ble_evt_gap_mode_changed")
                    discover, connect = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    args = {
                        'discover': discover, 'connect': connect
                    }
                    return PacketType.ble_evt_gap_mode_changed, args
            elif packet_class == 7:
                if packet_command == 0:  # ble_evt_hardware_io_port_status
                    log.debug(
                        "decoding packet ble_evt_hardware_io_port_status")
                    timestamp, port, irq, state = unpack(
                        '<IBBB', bgapi_rx_payload[:7]
                    )
                    args = {
                        'timestamp': timestamp, 'port': port, 'irq': irq,
                        'state': state
                    }
                    return PacketType.ble_evt_hardware_io_port_status, args
                elif packet_command == 1:  # ble_evt_hardware_soft_timer
                    log.debug(
                        "decoding packet ble_evt_hardware_io_soft_timer")
                    handle = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'handle': handle
                    }
                    return PacketType.ble_evt_hardware_soft_timer, args
                elif packet_command == 2:  # ble_evt_hardware_adc_result
                    log.debug(
                        "decoding packet ble_evt_hardware_adc_result")
                    input, value = unpack('<Bh', bgapi_rx_payload[:3])
                    args = {
                        'input': input, 'value': value
                    }
                    return PacketType.ble_evt_hardware_adc_result, args
