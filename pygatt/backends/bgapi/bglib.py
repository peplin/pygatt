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

import logging
from struct import pack, unpack

log = logging.getLogger(__name__)


class ResponsePacketType(object):
    system_reset = 0
    system_hello = 1
    system_address_get = 2
    system_reg_write = 3
    system_reg_read = 4
    system_get_counters = 5
    system_get_connections = 6
    system_read_memory = 7
    system_get_info = 8
    system_endpoint_tx = 9
    system_whitelist_append = 10
    system_whitelist_remove = 11
    system_whitelist_clear = 12
    system_endpoint_rx = 13
    system_endpoint_set_watermarks = 14
    flash_ps_defrag = 15
    flash_ps_dump = 16
    flash_ps_erase_all = 17
    flash_ps_save = 18
    flash_ps_load = 19
    flash_ps_erase = 20
    flash_erase_page = 21
    flash_write_words = 22
    attributes_write = 23
    attributes_read = 24
    attributes_read_type = 25
    attributes_user_read_response = 26
    attributes_user_write_response = 27
    connection_disconnect = 28
    connection_get_rssi = 29
    connection_update = 30
    connection_version_update = 31
    connection_channel_map_get = 32
    connection_channel_map_set = 33
    connection_features_get = 34
    connection_get_status = 35
    connection_raw_tx = 36
    attclient_find_by_type_value = 37
    attclient_read_by_group_type = 38
    attclient_read_by_type = 39
    attclient_find_information = 40
    attclient_read_by_handle = 41
    attclient_attribute_write = 42
    attclient_write_command = 43
    attclient_indicate_confirm = 44
    attclient_read_long = 45
    attclient_prepare_write = 46
    attclient_execute_write = 47
    attclient_read_multiple = 48
    sm_encrypt_start = 49
    sm_set_bondable_mode = 50
    sm_delete_bonding = 51
    sm_set_parameters = 52
    sm_passkey_entry = 53
    sm_get_bonds = 54
    sm_set_oob_data = 55
    gap_set_privacy_flags = 56
    gap_set_mode = 57
    gap_discover = 58
    gap_connect_direct = 59
    gap_end_procedure = 60
    gap_connect_selective = 61
    gap_set_filtering = 62
    gap_set_scan_parameters = 63
    gap_set_adv_parameters = 64
    gap_set_adv_data = 65
    gap_set_directed_connectable_mode = 66
    hardware_io_port_config_irq = 67
    hardware_set_soft_timer = 68
    hardware_adc_read = 69
    hardware_io_port_config_direction = 70
    hardware_io_port_config_function = 71
    hardware_io_port_config_pull = 72
    hardware_io_port_write = 73
    hardware_io_port_read = 74
    hardware_spi_config = 75
    hardware_spi_transfer = 76
    hardware_i2c_read = 77
    hardware_i2c_write = 78
    hardware_set_txpower = 79
    hardware_timer_comparator = 80
    test_phy_tx = 81
    test_phy_rx = 82
    test_phy_end = 83
    test_phy_reset = 84
    test_get_channel_map = 85
    test_debug = 86


class EventPacketType(object):
    system_boot = 87
    system_debug = 88
    system_endpoint_watermark_rx = 89
    system_endpoint_watermark_tx = 90
    system_script_failure = 91
    system_no_license_key = 92
    flash_ps_key = 93
    attributes_value = 94
    attributes_user_read_request = 95
    attributes_status = 96
    connection_status = 97
    connection_version_ind = 98
    connection_feature_ind = 99
    connection_raw_rx = 100
    connection_disconnected = 101
    attclient_indicated = 102
    attclient_procedure_completed = 103
    attclient_group_found = 104
    attclient_attribute_found = 105
    attclient_find_information_found = 106
    attclient_attribute_value = 107
    attclient_read_multiple_response = 108
    sm_smp_data = 109
    sm_bonding_fail = 110
    sm_passkey_display = 111
    sm_passkey_request = 112
    sm_bond_status = 113
    gap_scan_response = 114
    gap_mode_changed = 115
    hardware_io_port_status = 116
    hardware_soft_timer = 117
    hardware_adc_result = 118


class BGLib(object):
    """
    Modified version of jrowberg's BGLib implementation.
    """
    def __init__(self, loghandler=None, loglevel=logging.debug):
        """
        Set up logging for this module.

        loghandler -- the logging.handler object to register with the logger.
        loglevel -- the log level to use for this module.
        """
        log.setLevel(loglevel)
        if loghandler is None:
            loghandler = logging.StreamHandler()  # prints to stderr
            formatter = logging.Formatter(
                '%(asctime)s %(name)s %(levelname)s - %(message)s')
            loghandler.setLevel(loglevel)
            loghandler.setFormatter(formatter)
        log.addHandler(loghandler)
        self.bgapi_rx_buffer = []
        self.bgapi_rx_expected_length = 0
        # Packet message types
        self._ble_event = 0x80
        self._ble_response = 0x00
        self._wifi_event = 0x88
        self._wifi_response = 0x08

    def ble_cmd_system_reset(self, boot_in_dfu):
        log.info("construct command ble_cmd_system_reset")
        return pack('<4BB', 0, 1, 0, 0, boot_in_dfu)

    def ble_cmd_system_hello(self):
        log.info("construct command ble_cmd_system_hello")
        return pack('<4B', 0, 0, 0, 1)

    def ble_cmd_system_address_get(self):
        log.info("construct command ble_cmd_system_address_get")
        return pack('<4B', 0, 0, 0, 2)

    def ble_cmd_system_reg_write(self, address, value):
        log.info("construct command ble_cmd_system_reg_write")
        return pack('<4BHB', 0, 3, 0, 3, address, value)

    def ble_cmd_system_reg_read(self, address):
        log.info("construct command ble_cmd_system_reg_read")
        return pack('<4BH', 0, 2, 0, 4, address)

    def ble_cmd_system_get_counters(self):
        log.info("construct command ble_cmd_system_get_counters")
        return pack('<4B', 0, 0, 0, 5)

    def ble_cmd_system_get_connections(self):
        log.info("construct command ble_cmd_system_get_connections")
        return pack('<4B', 0, 0, 0, 6)

    def ble_cmd_system_read_memory(self, address, length):
        log.info("construct command ble_cmd_system_read_memory")
        return pack('<4BIB', 0, 5, 0, 7, address, length)

    def ble_cmd_system_get_info(self):
        log.info("construct command ble_cmd_system_get_info")
        return pack('<4B', 0, 0, 0, 8)

    def ble_cmd_system_endpoint_tx(self, endpoint, data):
        log.info("construct command ble_cmd_system_endpoint_tx")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 0, 9,
                    endpoint, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_system_whitelist_append(self, address, address_type):
        log.info("construct command ble_cmd_system_whitelist_append")
        return pack('<4B6sB', 0, 7, 0, 10, b''.join(chr(i) for i in address),
                    address_type)

    def ble_cmd_system_whitelist_remove(self, address, address_type):
        log.info("construct command ble_cmd_system_whitelist_remove")
        return pack('<4B6sB', 0, 7, 0, 11, b''.join(chr(i) for i in address),
                    address_type)

    def ble_cmd_system_whitelist_clear(self):
        log.info("construct command ble_cmd_system_whitelist_clear")
        return pack('<4B', 0, 0, 0, 12)

    def ble_cmd_system_endpoint_rx(self, endpoint, size):
        log.info("construct command ble_cmd_system_endpoint_rx")
        return pack('<4BBB', 0, 2, 0, 13, endpoint, size)

    def ble_cmd_system_endpoint_set_watermarks(self, endpoint, rx, tx):
        log.info("construct command ble_cmd_system_endpoint_set_watermarks")
        return pack('<4BBBB', 0, 3, 0, 14, endpoint, rx, tx)

    def ble_cmd_flash_ps_defrag(self):
        log.info("construct command ble_cmd_flash_ps_defrag")
        return pack('<4B', 0, 0, 1, 0)

    def ble_cmd_flash_ps_dump(self):
        log.info("construct command ble_cmd_flash_ps_dump")
        return pack('<4B', 0, 0, 1, 1)

    def ble_cmd_flash_ps_erase_all(self):
        log.info("construct command ble_cmd_flash_ps_erase_all")
        return pack('<4B', 0, 0, 1, 2)

    def ble_cmd_flash_ps_save(self, key, value):
        log.info("construct command ble_cmd_flash_ps_save")
        return pack('<4BHB' + str(len(value)) + 's', 0, 3 + len(value), 1, 3,
                    key, len(value), b''.join(chr(i) for i in value))

    def ble_cmd_flash_ps_load(self, key):
        log.info("construct command ble_cmd_flash_ps_load")
        return pack('<4BH', 0, 2, 1, 4, key)

    def ble_cmd_flash_ps_erase(self, key):
        log.info("construct command ble_cmd_flash_ps_erase")
        return pack('<4BH', 0, 2, 1, 5, key)

    def ble_cmd_flash_erase_page(self, page):
        log.info("construct command ble_cmd_flash_ps_erase_page")
        return pack('<4BB', 0, 1, 1, 6, page)

    def ble_cmd_flash_write_words(self, address, words):
        log.info("construct command ble_cmd_flash_write_words")
        return pack('<4BHB' + str(len(words)) + 's', 0, 3 + len(words), 1, 7,
                    address, len(words), b''.join(chr(i) for i in words))

    def ble_cmd_attributes_write(self, handle, offset, value):
        log.info("construct command ble_cmd_attributes_write")
        return pack('<4BHBB' + str(len(value)) + 's', 0, 4 + len(value), 2, 0,
                    handle, offset, len(value), b''.join(chr(i) for i in value))

    def ble_cmd_attributes_read(self, handle, offset):
        log.info("construct command ble_cmd_attributes_read")
        return pack('<4BHH', 0, 4, 2, 1, handle, offset)

    def ble_cmd_attributes_read_type(self, handle):
        log.info("construct command ble_cmd_attributes_read_type")
        return pack('<4BH', 0, 2, 2, 2, handle)

    def ble_cmd_attributes_user_read_response(self, connection, att_error,
                                              value):
        log.info("construct command ble_cmd_attributes_user_read_response")
        return pack('<4BBBB' + str(len(value)) + 's', 0, 3 + len(value), 2, 3,
                    connection, att_error, len(value),
                    b''.join(chr(i) for i in value))

    def ble_cmd_attributes_user_write_response(self, connection, att_error):
        log.info("construct command ble_cmd_attributes_user_write_response")
        return pack('<4BBB', 0, 2, 2, 4, connection, att_error)

    def ble_cmd_connection_disconnect(self, connection):
        log.info("construct command ble_cmd_connection_disconnnect")
        return pack('<4BB', 0, 1, 3, 0, connection)

    def ble_cmd_connection_get_rssi(self, connection):
        log.info("construct command ble_cmd_connection_get_rssi")
        return pack('<4BB', 0, 1, 3, 1, connection)

    def ble_cmd_connection_update(self, connection, interval_min, interval_max,
                                  latency, timeout):
        log.info("construct command ble_cmd_connection_update")
        return pack('<4BBHHHH', 0, 9, 3, 2, connection, interval_min,
                    interval_max, latency, timeout)

    def ble_cmd_connection_version_update(self, connection):
        log.info("construct command ble_cmd_connection_version_update")
        return pack('<4BB', 0, 1, 3, 3, connection)

    def ble_cmd_connection_channel_map_get(self, connection):
        log.info("construct command ble_cmd_connection_channel_map_get")
        return pack('<4BB', 0, 1, 3, 4, connection)

    def ble_cmd_connection_channel_map_set(self, connection, map):
        log.info("construct command ble_cmd_connection_channel_map_set")
        return pack('<4BBB' + str(len(map)) + 's', 0, 2 + len(map), 3, 5,
                    connection, len(map), b''.join(chr(i) for i in map))

    def ble_cmd_connection_features_get(self, connection):
        log.info("construct command ble_cmd_connection_features_get")
        return pack('<4BB', 0, 1, 3, 6, connection)

    def ble_cmd_connection_get_status(self, connection):
        log.info("construct command ble_cmd_connection_get_status")
        return pack('<4BB', 0, 1, 3, 7, connection)

    def ble_cmd_connection_raw_tx(self, connection, data):
        log.info("construct command ble_cmd_connection_raw_tx")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 3, 8,
                    connection, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_attclient_find_by_type_value(self, connection, start, end, uuid,
                                             value):
        log.info("construct command ble_cmd_attclient_find_by_type_value")
        return pack('<4BBHHHB' + str(len(value)) + 's', 0, 8 + len(value), 4, 0,
                    connection, start, end, uuid, len(value),
                    b''.join(chr(i) for i in value))

    def ble_cmd_attclient_read_by_group_type(self, connection, start, end,
                                             uuid):
        log.info("construct command ble_cmd_attclient_read_by_group_type")
        return pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 1,
                    connection, start, end, len(uuid),
                    b''.join(chr(i) for i in uuid))

    def ble_cmd_attclient_read_by_type(self, connection, start, end, uuid):
        log.info("construct command ble_cmd_attclient_read_by_type")
        return pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 2,
                    connection, start, end, len(uuid),
                    b''.join(chr(i) for i in uuid))

    def ble_cmd_attclient_find_information(self, connection, start, end):
        log.info("construct command ble_cmd_attclient_find_information")
        return pack('<4BBHH', 0, 5, 4, 3, connection, start, end)

    def ble_cmd_attclient_read_by_handle(self, connection, chrhandle):
        log.info("construct command ble_cmd_attclient_read_by_handle")
        return pack('<4BBH', 0, 3, 4, 4, connection, chrhandle)

    def ble_cmd_attclient_attribute_write(self, connection, atthandle, data):
        log.info("construct command ble_cmd_attclient_attribute_write")
        return pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 5,
                    connection, atthandle, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_write_command(self, connection, atthandle, data):
        log.info("construct command ble_cmd_attclient_write_command")
        return pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 6,
                    connection, atthandle, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_indicate_confirm(self, connection):
        log.info("construct command ble_cmd_attclient_indicate_confirm")
        return pack('<4BB', 0, 1, 4, 7, connection)

    def ble_cmd_attclient_read_long(self, connection, chrhandle):
        log.info("construct command ble_cmd_attclient_read_long")
        return pack('<4BBH', 0, 3, 4, 8, connection, chrhandle)

    def ble_cmd_attclient_prepare_write(self, connection, atthandle, offset,
                                        data):
        log.info("construct command ble_cmd_attclient_prepare_write")
        return pack('<4BBHHB' + str(len(data)) + 's', 0, 6 + len(data), 4, 9,
                    connection, atthandle, offset, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_execute_write(self, connection, commit):
        log.info("construct command ble_cmd_attclient_execute_write")
        return pack('<4BBB', 0, 2, 4, 10, connection, commit)

    def ble_cmd_attclient_read_multiple(self, connection, handles):
        log.info("construct command ble_cmd_attclient_read_multiple")
        return pack('<4BBB' + str(len(handles)) + 's', 0, 2 + len(handles), 4,
                    11, connection, len(handles),
                    b''.join(chr(i) for i in handles))

    def ble_cmd_sm_encrypt_start(self, handle, bonding):
        log.info("construct command ble_cmd_sm_encrypt_start")
        return pack('<4BBB', 0, 2, 5, 0, handle, bonding)

    def ble_cmd_sm_set_bondable_mode(self, bondable):
        log.info("construct command ble_cmd_sm_set_bondable_mode")
        return pack('<4BB', 0, 1, 5, 1, bondable)

    def ble_cmd_sm_delete_bonding(self, handle):
        log.info("construct command ble_cmd_sm_delete_bonding")
        return pack('<4BB', 0, 1, 5, 2, handle)

    def ble_cmd_sm_set_parameters(self, mitm, min_key_size, io_capabilities):
        log.info("construct command ble_cmd_sm_set_parameters")
        return pack('<4BBBB', 0, 3, 5, 3, mitm, min_key_size, io_capabilities)

    def ble_cmd_sm_passkey_entry(self, handle, passkey):
        log.info("construct command ble_cmd_sm_passkey_entry")
        return pack('<4BBI', 0, 5, 5, 4, handle, passkey)

    def ble_cmd_sm_get_bonds(self):
        log.info("construct command ble_cmd_sm_get_bonds")
        return pack('<4B', 0, 0, 5, 5)

    def ble_cmd_sm_set_oob_data(self, oob):
        log.info("construct command ble_cmd_sm_oob_data")
        return pack('<4BB' + str(len(oob)) + 's', 0, 1 + len(oob), 5, 6,
                    len(oob), b''.join(chr(i) for i in oob))

    def ble_cmd_gap_set_privacy_flags(self, peripheral_privacy,
                                      central_privacy):
        log.info("construct command ble_cmd_gap_set_privacy_flags")
        return pack('<4BBB', 0, 2, 6, 0, peripheral_privacy, central_privacy)

    def ble_cmd_gap_set_mode(self, discover, connect):
        log.info("construct command ble_cmd_gap_set_mode")
        return pack('<4BBB', 0, 2, 6, 1, discover, connect)

    def ble_cmd_gap_discover(self, mode):
        log.info("construct command ble_cmd_gap_discover")
        return pack('<4BB', 0, 1, 6, 2, mode)

    def ble_cmd_gap_connect_direct(self, address, addr_type, conn_interval_min,
                                   conn_interval_max, timeout, latency):
        log.info("construct command ble_cmd_gap_connect_direct")
        return pack('<4B6sBHHHH', 0, 15, 6, 3,
                    b''.join(chr(i) for i in address), addr_type,
                    conn_interval_min, conn_interval_max, timeout, latency)

    def ble_cmd_gap_end_procedure(self):
        log.info("construct command ble_cmd_gap_end_procedure")
        return pack('<4B', 0, 0, 6, 4)

    def ble_cmd_gap_connect_selective(self, conn_interval_min,
                                      conn_interval_max, timeout, latency):
        log.info("construct command ble_cmd_gap_connect_selective")
        return pack('<4BHHHH', 0, 8, 6, 5, conn_interval_min, conn_interval_max,
                    timeout, latency)

    def ble_cmd_gap_set_filtering(self, scan_policy, adv_policy,
                                  scan_duplicate_filtering):
        log.info("construct command ble_cmd_gap_set_filtering")
        return pack('<4BBBB', 0, 3, 6, 6, scan_policy, adv_policy,
                    scan_duplicate_filtering)

    def ble_cmd_gap_set_scan_parameters(self, scan_interval, scan_window,
                                        active):
        log.info("construct command ble_cmd_gap_set_scan_parameters")
        return pack('<4BHHB', 0, 5, 6, 7, scan_interval, scan_window, active)

    def ble_cmd_gap_set_adv_parameters(self, adv_interval_min,
                                       adv_interval_max, adv_channels):
        log.info("construct command ble_cmd_gap_set_adv_parameters")
        return pack('<4BHHB', 0, 5, 6, 8, adv_interval_min, adv_interval_max,
                    adv_channels)

    def ble_cmd_gap_set_adv_data(self, set_scanrsp, adv_data):
        log.info("construct command ble_cmd_gap_set_adv_data")
        return pack('<4BBB' + str(len(adv_data)) + 's', 0, 2 + len(adv_data), 6,
                    9, set_scanrsp, len(adv_data),
                    b''.join(chr(i) for i in adv_data))

    def ble_cmd_gap_set_directed_connectable_mode(self, address, addr_type):
        log.info("construct command ble_cmd_gap_set_directed_connectable_mode")
        return pack('<4B6sB', 0, 7, 6, 10, b''.join(chr(i) for i in address),
                    addr_type)

    def ble_cmd_hardware_io_port_config_irq(self, port, enable_bits,
                                            falling_edge):
        log.info("construct command ble_cmd_hardware_io_port_config_irq")
        return pack('<4BBBB', 0, 3, 7, 0, port, enable_bits, falling_edge)

    def ble_cmd_hardware_set_soft_timer(self, time, handle, single_shot):
        log.info("construct command ble_cmd_hardware_set_soft_timer")
        return pack('<4BIBB', 0, 6, 7, 1, time, handle, single_shot)

    def ble_cmd_hardware_adc_read(self, input, decimation, reference_selection):
        log.info("construct command ble_cmd_hardware_adc_read")
        return pack('<4BBBB', 0, 3, 7, 2, input, decimation,
                    reference_selection)

    def ble_cmd_hardware_io_port_config_direction(self, port, direction):
        log.info("construct command ble_cmd_hardware_io_port_config_direction")
        return pack('<4BBB', 0, 2, 7, 3, port, direction)

    def ble_cmd_hardware_io_port_config_function(self, port, function):
        log.info("construct command ble_cmd_hardware_io_port_config_function")
        return pack('<4BBB', 0, 2, 7, 4, port, function)

    def ble_cmd_hardware_io_port_config_pull(self, port, tristate_mask,
                                             pull_up):
        log.info("construct command ble_cmd_hardware_io_port_config_pull")
        return pack('<4BBBB', 0, 3, 7, 5, port, tristate_mask, pull_up)

    def ble_cmd_hardware_io_port_write(self, port, mask, data):
        log.info("construct command ble_cmd_hardware_io_prot_write")
        return pack('<4BBBB', 0, 3, 7, 6, port, mask, data)

    def ble_cmd_hardware_io_port_read(self, port, mask):
        log.info("construct command ble_cmd_hardware_io_port_read")
        return pack('<4BBB', 0, 2, 7, 7, port, mask)

    def ble_cmd_hardware_spi_config(self, channel, polarity, phase, bit_order,
                                    baud_e, baud_m):
        log.info("construct command ble_cmd_hardware_spi_config")
        return pack('<4BBBBBBB', 0, 6, 7, 8, channel, polarity, phase,
                    bit_order, baud_e, baud_m)

    def ble_cmd_hardware_spi_transfer(self, channel, data):
        log.info("construct command ble_cmd_hardware_spi_transfer")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 7, 9,
                    channel, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_hardware_i2c_read(self, address, stop, length):
        log.info("construct command ble_cmd_hardware_i2c_read")
        return pack('<4BBBB', 0, 3, 7, 10, address, stop, length)

    def ble_cmd_hardware_i2c_write(self, address, stop, data):
        log.info("construct command ble_cmd_hardware_i2c_write")
        return pack('<4BBBB' + str(len(data)) + 's', 0, 3 + len(data), 7, 11,
                    address, stop, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_hardware_set_txpower(self, power):
        log.info("construct command ble_cmd_hardware_set_txpower")
        return pack('<4BB', 0, 1, 7, 12, power)

    def ble_cmd_hardware_timer_comparator(self, timer, channel, mode,
                                          comparator_value):
        log.info("construct command ble_cmd_hardware_timer_comparator")
        return pack('<4BBBBH', 0, 5, 7, 13, timer, channel, mode,
                    comparator_value)

    def ble_cmd_test_phy_tx(self, channel, length, type):
        log.info("construct command ble_cmd_test_phy_tx")
        return pack('<4BBBB', 0, 3, 8, 0, channel, length, type)

    def ble_cmd_test_phy_rx(self, channel):
        log.info("construct command ble_cmd_test_phy_rx")
        return pack('<4BB', 0, 1, 8, 1, channel)

    def ble_cmd_test_phy_end(self):
        log.info("construct command ble_cmd_test_phy_end")
        return pack('<4B', 0, 0, 8, 2)

    def ble_cmd_test_phy_reset(self):
        log.info("construct command ble_cmd_test_phy_reset")
        return pack('<4B', 0, 0, 8, 3)

    def ble_cmd_test_get_channel_map(self):
        log.info("construct command ble_cmd_test_get_channel_map")
        return pack('<4B', 0, 0, 8, 4)

    def ble_cmd_test_debug(self, input):
        log.info("construct command ble_cmd_test_debug")
        return pack('<4BB' + str(len(input)) + 's', 0, 1 + len(input), 8, 5,
                    len(input), b''.join(chr(i) for i in input))

    def send_command(self, ser, packet):
        """
        Send a packet to the BLED12 over serial.

        ser -- The serial.Serial object to write to.
        packet -- The packet to write.
        """
        log.info("Sending command")
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
            log.info("read complete packet")
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
        packet_type, payload_length, packet_class, packet_command = packet[:4]
        bgapi_rx_payload = b''.join(chr(i) for i in packet[4:])
        if packet_type & 0x88 == 0x00:
            # 0x00 = BLE response packet
            if packet_class == 0:
                if packet_command == 0:  # system_reset
                    log.info("received packet system_reset")
                    return ResponsePacketType.system_reset, {}
                elif packet_command == 1:  # system_hello
                    log.info("received packet system_hello")
                    return ResponsePacketType.system_hello, {}
                elif packet_command == 2:  # system_address_get
                    log.info("received packet system_address_get")
                    address = unpack('<6s', bgapi_rx_payload[:6])[0]
                    address = [ord(b) for b in address]
                    args = {
                        'address': address
                    }
                    return ResponsePacketType.system_address_get, args
                elif packet_command == 3:  # system_reg_write
                    log.info("received packet system_reg_write")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.system_reg_write, args
                elif packet_command == 4:  # system_reg_read
                    log.info("received packet system_reg_read")
                    address, value =\
                        unpack('<HB', bgapi_rx_payload[:3])
                    args = {
                        'address': address, 'value': value
                    }
                    return ResponsePacketType.system_reg_read, args
                elif packet_command == 5:  # system_get_counters
                    log.info("received packet system_get_counters")
                    txok, txretry, rxok, rxfail, mbuf =\
                        unpack('<BBBBB', bgapi_rx_payload[:5])
                    args = {
                        'txok': txok, 'txretry': txretry, 'rxok': rxok,
                        'rxfail': rxfail, 'mbuf': mbuf
                    }
                    return ResponsePacketType.system_get_counters, args
                elif packet_command == 6:  # system_get_connections
                    log.info("received packet system_get_connections")
                    maxconn = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'maxconn': maxconn
                    }
                    return ResponsePacketType.system_get_connections, args
                elif packet_command == 7:  # system_read_memory
                    log.info("received packet system_read_memory")
                    address, data_len =\
                        unpack('<IB', bgapi_rx_payload[:5])
                    data_data = [ord(b) for b in bgapi_rx_payload[5:]]
                    args = {
                        'address': address, 'data': data_data
                    }
                    return ResponsePacketType.system_read_memory, args
                elif packet_command == 8:  # system_get_info
                    log.info("received packet system_get_info")
                    data = unpack('<HHHHHBB', bgapi_rx_payload[:12])
                    args = {
                        'major': data[0], 'minor': data[1],
                        'patch': data[2], 'build': data[3],
                        'll_version': data[4], 'protocol_version': data[5],
                        'hw': data[6]
                    }
                    return ResponsePacketType.system_get_info, args
                elif packet_command == 9:  # system_endpoint_tx
                    log.info("received packet system_endpoint_tx")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.system_endpoint_tx, args
                # system_whitelist_append
                elif packet_command == 10:
                    log.info("received packet system_whitelist_append")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.system_whitelist_append, args
                # system_whitelist_remove
                elif packet_command == 11:
                    log.info("received packet system_whitelist_remove")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.system_whitelist_remove
                elif packet_command == 12:  # system_whitelist_clear
                    log.info("received packet system_whitelist_clear")
                    return ResponsePacketType.system_whitelist_clear, {}
                elif packet_command == 13:  # system_endpoint_rx
                    log.info("received packet system_endpoint_rx")
                    result, data_len =\
                        unpack('<HB', bgapi_rx_payload[:3])
                    data_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'result': result, 'data': data_data
                    }
                    return ResponsePacketType.system_endpoint_rx, args
                # system_endpoint_set_watermarks
                elif packet_command == 14:
                    log.info("received packet system_endpoint_set_watermarks")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.system_endpoint_set_watermarks,
                            args)
            elif packet_class == 1:
                if packet_command == 0:  # flash_ps_defrag
                    log.info("received packet flash_ps_defrag")
                    return ResponsePacketType.flash_ps_defrag, {}
                elif packet_command == 1:  # flash_ps_dump
                    log.info("received packet flash_ps_dump")
                    return ResponsePacketType.flash_ps_dump, {}
                elif packet_command == 2:  # flash_ps_erase_all
                    log.info("received packet flash_ps_erase_all")
                    return ResponsePacketType.flash_ps_erase_all, {}
                elif packet_command == 3:  # flash_ps_save
                    log.info("received packet flash_ps_save")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.flash_ps_save, args
                elif packet_command == 4:  # flash_ps_load
                    log.info("received packet flash_ps_load")
                    result, value_len = unpack('<HB',
                                               bgapi_rx_payload[:3])
                    value_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'result': result, 'value': value_data
                    }
                    return ResponsePacketType.flash_ps_load, args
                elif packet_command == 5:  # flash_ps_erase
                    log.info("received packet flash_ps_erase")
                    return ResponsePacketType.flash_ps_erase, {}
                elif packet_command == 6:  # flash_ps_erase_page
                    log.info("received packet flash_ps_erase_page")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.flash_erase_page, args
                elif packet_command == 7:  # flash_write_words
                    log.info("received packet flash_write_words")
                    return ResponsePacketType.flash_write_words, {}
            elif packet_class == 2:
                if packet_command == 0:  # attributes_write
                    log.info("received packet attributes_write")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.attributes_write, args
                elif packet_command == 1:  # attributes_read
                    log.info("received packet attributes_read")
                    handle, offset, result, value_len = unpack(
                        '<HHHB', bgapi_rx_payload[:7]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[7:]]
                    args = {
                        'handle': handle, 'offset': offset,
                        'result': result, 'value': value_data
                    }
                    return ResponsePacketType.attributes_read, args
                elif packet_command == 2:  # attributes_read_type
                    log.info("received packet attributes_read_type")
                    handle, result, value_len = unpack(
                        '<HHB', bgapi_rx_payload[:5]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[5:]]
                    args = {
                        'handle': handle, 'result': result,
                        'value': value_data
                    }
                    return ResponsePacketType.attributes_read_type, args
                # attributes_user_read_response
                elif packet_command == 3:
                    log.info("received packet attributes_user_read_response")
                    return (ResponsePacketType.
                            attributes_user_read_response, {})
                # attributes_user_write_response
                elif packet_command == 4:
                    log.info("received packet attributes_user_write_response")
                    return (ResponsePacketType.
                            attributes_user_write_response, {})
            elif packet_class == 3:
                if packet_command == 0:  # connection_disconnect
                    log.info("received packet connection_disconnect")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.connection_disconnect, args
                elif packet_command == 1:  # connection_get_rssi
                    log.info("received packet connection_get_rssi")
                    connection, rssi = unpack(
                        '<Bb', bgapi_rx_payload[:2]
                    )
                    args = {
                        'connection': connection, 'rssi': rssi
                    }
                    return ResponsePacketType.connection_get_rssi, args
                elif packet_command == 2:  # connection_update
                    log.info("received packet connection_update")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.connection_update, args
                # connection_version_update
                elif packet_command == 3:
                    log.info("received packet connection_version_update")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.connection_version_update,
                            args)
                # connection_channel_map_get
                elif packet_command == 4:
                    log.info("received packet connection_channel_map_get")
                    connection, map_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    map_data = [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'map': map_data
                    }
                    return (ResponsePacketType.connection_channel_map_get,
                            args)
                # connection_channel_map_set
                elif packet_command == 5:
                    log.info("received packet connection_channel_map_set")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.connection_channel_map_set,
                            args)
                elif packet_command == 6:  # connection_features_get
                    log.info("received packet connection_features_get")
                    connection, result = unpack('<BH',
                                                bgapi_rx_payload[:3])
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.connection_features_get, args
                elif packet_command == 7:  # connection_get_status
                    log.info("received packet connection_get_status")
                    connection = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'connection': connection
                    }
                    return ResponsePacketType.connection_get_status, args
                elif packet_command == 8:  # connection_raw_tx
                    log.info("received packet connection_raw_tx")
                    connection = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'connection': connection
                    }
                    return ResponsePacketType.connection_raw_tx, args
            elif packet_class == 4:
                # attclient_find_by_type_value
                if packet_command == 0:
                    log.info("received packet attclient_find_by_type_value")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.
                            attclient_find_by_type_value, args)
                # attclient_read_by_group_type
                elif packet_command == 1:
                    log.info("received packet attclient_read_by_group_type")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.
                            attclient_read_by_group_type, args)
                elif packet_command == 2:  # attclient_read_by_type
                    log.info("received packet attclient_read_by_type")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.attclient_read_by_type, args
                # attclient_find_information
                elif packet_command == 3:
                    log.info("received packet attclient_find_information")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.attclient_find_information,
                            args)
                # attclient_read_by_handle
                elif packet_command == 4:
                    log.info("received packet attclient_read_by_handle")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.attclient_read_by_handle,
                            args)
                # attclient_attribute_write
                elif packet_command == 5:
                    log.info("received packet attclient_attribute_write")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return (ResponsePacketType.attclient_attribute_write,
                            args)
                elif packet_command == 6:  # attclient_write_command
                    log.info("received packet attclient_write_command")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.attclient_write_command, args
                # attclient_indicate_confirm
                elif packet_command == 7:
                    log.info("received packet attclient_indicate_confirm")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.attclient_indicate_confirm,
                            args)
                elif packet_command == 8:  # attclient_read_long
                    log.info("received packet attclient_read_long")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.attclient_read_long, args
                elif packet_command == 9:  # attclient_prepare_write
                    log.info("received packet attclient_prepare_write")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.attclient_prepare_write, args
                # attclient_execute_write
                elif packet_command == 10:
                    log.info("received packet attclient_execute_write")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.attclient_execute_write, args
                # attclient_read_multiple
                elif packet_command == 11:
                    log.info("received packet attclient_read_multiple")
                    connection, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'result': result
                    }
                    return ResponsePacketType.attclient_read_multiple, args
            elif packet_class == 5:
                if packet_command == 0:  # sm_encrypt_start
                    log.info("received packet sm_encrypt_start")
                    handle, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'handle': handle, 'result': result
                    }
                    return ResponsePacketType.sm_encrypt_start, args
                elif packet_command == 1:  # sm_set_bondable_mode
                    log.info("received packet sm_set_bondable_mode")
                    return ResponsePacketType.sm_set_bondable_mode, {}
                elif packet_command == 2:  # sm_delete_bonding
                    log.info("received packet sm_delete_bonding")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.sm_delete_bonding, args
                elif packet_command == 3:  # sm_set_parameters
                    log.info("received packet sm_set_parameters")
                    return ResponsePacketType.sm_set_parameters, {}
                elif packet_command == 4:  # sm_passkey_entry
                    log.info("received packet sm_passkey_entry")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.sm_passkey_entry, args
                elif packet_command == 5:  # sm_get_bonds
                    log.info("received packet sm_get_bonds")
                    bonds = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'bonds': bonds
                    }
                    return ResponsePacketType.sm_get_bonds, args
                elif packet_command == 6:  # sm_set_oob_data
                    log.info("received packet sm_set_oob_data")
                    return ResponsePacketType.sm_set_oob_data, {}
            elif packet_class == 6:
                if packet_command == 0:  # gap_set_privacy_flags
                    log.info("received packet gap_set_privacy_flags")
                    return ResponsePacketType.gap_set_privacy_flags, {}
                elif packet_command == 1:  # gap_set_mode
                    log.info("received packet gap_set_mode")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_set_mode, args
                elif packet_command == 2:  # gap_discover
                    log.info("received packet gap_discover")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_discover, args
                elif packet_command == 3:  # gap_connect_direct
                    log.info("received packet gap_connect_direct")
                    result, connection_handle = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    args = {
                        'result': result,
                        'connection_handle': connection_handle
                    }
                    return ResponsePacketType.gap_connect_direct, args
                elif packet_command == 4:  # gap_end_procedure
                    log.info("received packet gap_end_procedure")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_end_procedure, args
                elif packet_command == 5:  # gap_connect_selective
                    log.info("received packet gap_connect_selective")
                    result, connection_handle = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    args = {
                        'result': result,
                        'connection_handle': connection_handle
                    }
                    return ResponsePacketType.gap_connect_selective, args
                elif packet_command == 6:  # gap_set_filtering
                    log.info("received packet gap_set_filtering")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_set_filtering, args
                elif packet_command == 7:  # gap_set_scan_parameters
                    log.info("received packet gap_set_scan_parameters")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_set_scan_parameters, args
                elif packet_command == 8:  # gap_set_adv_parameters
                    log.info("received packet gap_set_adv_parameters")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_set_adv_parameters, args
                elif packet_command == 9:  # gap_set_adv_data
                    log.info("received packet gap_set_adv_data")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.gap_set_adv_data, args
                # gap_set_directed_connectable_mode
                elif packet_command == 10:
                    log.info("received packet "
                             "gap_set_directed_connectable_mode")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.
                            gap_set_directed_connectable_mode, args)
            elif packet_class == 7:
                # hardware_io_port_config_irq
                if packet_command == 0:
                    log.info("received packet hardware_io_port_config_irq")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.hardware_io_port_config_irq,
                            args)
                elif packet_command == 1:  # hardware_set_soft_timer
                    log.info("received packet hardware_set_soft_timer")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.hardware_set_soft_timer, args
                elif packet_command == 2:  # hardware_adc_read
                    log.info("received packet hardware_adc_read")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.hardware_adc_read, args
                # hardware_io_port_config_direction
                elif packet_command == 3:
                    log.info("received packet "
                             "hardware_io_port_config_direction")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.
                            hardware_io_port_config_direction, args)
                # hardware_io_port_config_function
                elif packet_command == 4:
                    log.info("received packet hardware_io_port_config_function")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.
                            hardware_io_port_config_function, args)
                # hardware_io_port_config_pull
                elif packet_command == 5:
                    log.info("received packet hardware_io_port_config_pull")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.
                            hardware_io_port_config_pull, args)
                elif packet_command == 6:  # hardware_io_port_write
                    log.info("received packet hardware_io_port_write")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.hardware_io_port_write, args
                elif packet_command == 7:  # hardware_io_port_read
                    log.info("received packet hardware_io_port_read")
                    result, port, data = unpack(
                        '<HBB', bgapi_rx_payload[:4]
                    )
                    args = {
                        'result': result, 'port': port, 'data': data
                    }
                    return ResponsePacketType.hardware_io_port_read, args
                elif packet_command == 8:  # hardware_spi_config
                    log.info("received packet hardware_spi_config")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return ResponsePacketType.hardware_spi_config, args
                elif packet_command == 9:  # hardware_spi_transfer
                    log.info("received packet hardware_spi_transfer")
                    result, channel, data_len = unpack(
                        '<HBB', bgapi_rx_payload[:4]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[4:]]
                    args = {
                        'result': result, 'channel': channel,
                        'data': data_data
                    }
                    return ResponsePacketType.hardware_spi_transfer, args
                elif packet_command == 10:  # hardware_i2c_read
                    log.info("received packet hardware_i2c_read")
                    result, data_len = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'result': result, 'data': data_data
                    }
                    return ResponsePacketType.hardware_i2c_read, args
                elif packet_command == 11:  # hardware_i2c_write
                    log.info("received packet hardware_i2c_write")
                    written = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'written': written
                    }
                    return ResponsePacketType.hardware_i2c_write, args
                elif packet_command == 12:  # hardware_set_txpower
                    log.info("received packet hardware_set_txpower")
                    return ResponsePacketType.hardware_set_txpower, {}
                # hardware_timer_comparator
                elif packet_command == 13:
                    log.info("received packet hardware_timer_comparator")
                    result = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'result': result
                    }
                    return (ResponsePacketType.
                            hardware_timer_comparator, args)
            elif packet_class == 8:
                if packet_command == 0:  # test_phy_tx
                    log.info("received packet test_phy_tx")
                    return ResponsePacketType.test_phy_tx, {}
                elif packet_command == 1:  # test_phy_rx
                    log.info("received packet test_phy_rx")
                    return ResponsePacketType.test_phy_rx, {}
                elif packet_command == 2:  # test_phy_end
                    log.info("received packet test_phy_end")
                    counter = unpack('<H', bgapi_rx_payload[:2])[0]
                    args = {
                        'counter': counter
                    }
                    return ResponsePacketType.test_phy_end, args
                elif packet_command == 3:  # test_phy_reset
                    log.info("received packet test_phy_reset")
                    return ResponsePacketType.test_phy_reset, {}
                elif packet_command == 4:  # test_get_channel_map
                    log.info("received packet test_get_channel_map")
                    # channel_map_len = unpack(
                    #    '<B', bgapi_rx_payload[:1]
                    # )[0]
                    channel_map_data =\
                        [ord(b) for b in bgapi_rx_payload[1:]]
                    args = {
                        'channel_map': channel_map_data
                    }
                    return ResponsePacketType.test_get_channel_map, args
                elif packet_command == 5:  # test_debug
                    log.info("received packet test_debug")
                    # output_len = unpack('<B',
                    #                     bgapi_rx_payload[:1])[0]
                    output_data =\
                        [ord(b) for b in bgapi_rx_payload[1:]]
                    args = {
                        'output': output_data
                    }
                    return ResponsePacketType.test_debug, args
        elif packet_type & 0x88 == 0x80:
            # 0x80 = BLE event packet
            if packet_class == 0:
                if packet_command == 0:  # system_boot
                    log.info("received packet system_boot")
                    data = unpack('<HHHHHBB', bgapi_rx_payload[:12])
                    args = {
                        'major': data[0], 'minor': data[1],
                        'patch': data[2], 'build': data[3],
                        'll_version': data[4], 'protocol_version': data[5],
                        'hw': data[6]
                    }
                    return EventPacketType.system_boot, args
                elif packet_command == 1:  # system_debug
                    log.info("received packet system_debug")
                    data_len = unpack('<B', bgapi_rx_payload[:1])[0]
                    data_data = [ord(b) for b in bgapi_rx_payload[1:]]
                    args = {
                        'data': data_data
                    }
                    return EventPacketType.system_debug, args
                # system_endpoint_watermark_rx
                elif packet_command == 2:
                    log.info("received packet system_endpoint_watermark_rx")
                    endpoint, data = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    args = {
                        'endpoint': endpoint, 'data': data
                    }
                    return (EventPacketType.
                            system_endpoint_watermark_rx, args)
                # system_endpoint_watermark_tx
                elif packet_command == 3:
                    log.info("received packet system_endpoint_watermark_tx")
                    endpoint, data = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    args = {
                        'endpoint': endpoint, 'data': data
                    }
                    return (EventPacketType.
                            system_endpoint_watermark_tx, args)
                elif packet_command == 4:  # system_script_failure
                    log.info("received packet system_script_failure")
                    address, reason = unpack(
                        '<HH', bgapi_rx_payload[:4]
                    )
                    args = {
                        'address': address, 'reason': reason
                    }
                    return EventPacketType.system_script_failure, args
                elif packet_command == 5:  # system_no_license_key
                    log.info("received packet system_no_license_key")
                    return EventPacketType.system_no_license_key, {}
            elif packet_class == 1:
                if packet_command == 0:  # flash_ps_key
                    log.info("received packet flash_ps_key")
                    key, value_len = unpack(
                        '<HB', bgapi_rx_payload[:3]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'key': key, 'value': value_data
                    }
                    return EventPacketType.flash_ps_key, args
            elif packet_class == 2:
                if packet_command == 0:  # attributes_value
                    log.info("received packet attributes_value")
                    connection, reason, handle, offset, value_len = unpack(
                        '<BBHHB', bgapi_rx_payload[:7]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[7:]]
                    args = {
                        'connection': connection, 'reason': reason,
                        'handle': handle, 'offset': offset,
                        'value': value_data
                    }
                    return EventPacketType.attributes_value, args
                # attributes_user_read_request
                elif packet_command == 1:
                    log.info("received packet attributes_user_read_request")
                    connection, handle, offset, maxsize = unpack(
                        '<BHHB', bgapi_rx_payload[:6]
                    )
                    args = {
                        'connection': connection, 'handle': handle,
                        'offset': offset, 'maxsize': maxsize
                    }
                    return (EventPacketType.
                            attributes_user_read_request, args)
                elif packet_command == 2:  # attributes_status
                    log.info("received packet attributes_status")
                    handle, flags = unpack('<HB', bgapi_rx_payload[:3])
                    args = {
                        'handle': handle, 'flags': flags
                    }
                    return EventPacketType.attributes_status, args
            elif packet_class == 3:
                if packet_command == 0:  # connection_status
                    log.info("received packet connection_status")
                    data = unpack('<BB6sBHHHB', bgapi_rx_payload[:16])
                    address = [ord(b) for b in data[2]]
                    args = {
                        'connection': data[0], 'flags': data[1],
                        'address': address, 'address_type': data[3],
                        'conn_interval': data[4], 'timeout': data[5],
                        'latency': data[6], 'bonding': data[7]
                    }
                    return EventPacketType.connection_status, args
                elif packet_command == 1:  # connection_version_ind
                    log.info("received packet connection_version_ind")
                    connection, vers_nr, comp_id, sub_vers_nr = unpack(
                        '<BBHH', bgapi_rx_payload[:6]
                    )
                    args = {
                        'connection': connection, 'vers_nr': vers_nr,
                        'comp_id': comp_id, 'sub_vers_nr': sub_vers_nr
                    }
                    return EventPacketType.connection_version_ind, args
                elif packet_command == 2:  # connection_feature_ind
                    log.info("received packet connection_feature_ind")
                    connection, features_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    features_data =\
                        [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'features': features_data
                    }
                    return EventPacketType.connection_feature_ind, args
                elif packet_command == 3:  # connection_raw_rx
                    log.info("received packet connection_raw_rx")
                    connection, data_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'data': data_data
                    }
                    return EventPacketType.connection_raw_rx, args
                elif packet_command == 4:  # connection_disconnected
                    log.info("received packet connection_disconnected")
                    connection, reason = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'reason': reason
                    }
                    return EventPacketType.connection_disconnected, args
            elif packet_class == 4:
                if packet_command == 0:  # attclient_indicated
                    log.info("received packet attclient_indicated")
                    connection, attrhandle = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'connection': connection, 'attrhandle': attrhandle
                    }
                    return EventPacketType.attclient_indicated, args
                # attclient_procedure_completed
                elif packet_command == 1:
                    log.info("received packet attclient_procedure_completed")
                    connection, result, chrhandle = unpack(
                        '<BHH', bgapi_rx_payload[:5]
                    )
                    args = {
                        'connection': connection, 'result': result,
                        'chrhandle': chrhandle
                    }
                    return (EventPacketType.
                            attclient_procedure_completed, args)
                elif packet_command == 2:  # attclient_group_found
                    log.info("received packet attclient_group_found")
                    connection, start, end, uuid_len = unpack(
                        '<BHHB', bgapi_rx_payload[:6]
                    )
                    uuid_data = [ord(b) for b in bgapi_rx_payload[6:]]
                    args = {
                        'connection': connection, 'start': start,
                        'end': end, 'uuid': uuid_data
                    }
                    return EventPacketType.attclient_group_found, args
                # attclient_attribute_found
                elif packet_command == 3:
                    log.info("received packet attclient_attribute_found")
                    data = unpack('<BHHBB', bgapi_rx_payload[:7])
                    uuid_data = [ord(b) for b in bgapi_rx_payload[7:]]
                    args = {
                        'connection': data[0], 'chrdecl': data[1],
                        'value': data[2], 'properties': data[3],
                        'uuid': uuid_data
                    }
                    return (EventPacketType.attclient_attribute_found,
                            args)
                # attclient_find_information_found
                elif packet_command == 4:
                    log.info("received packet attclient_find_information_found")
                    connection, chrhandle, uuid_len = unpack(
                        '<BHB', bgapi_rx_payload[:4]
                    )
                    uuid_data = [ord(b) for b in bgapi_rx_payload[4:]]
                    args = {
                        'connection': connection, 'chrhandle': chrhandle,
                        'uuid': uuid_data
                    }
                    return (EventPacketType.
                            attclient_find_information_found, args)
                # attclient_attribute_value
                elif packet_command == 5:
                    log.info("received packet attclient_attribute_value")
                    connection, atthandle, type, value_len = unpack(
                        '<BHBB', bgapi_rx_payload[:5]
                    )
                    value_data = [ord(b) for b in bgapi_rx_payload[5:]]
                    args = {
                        'connection': connection, 'atthandle': atthandle,
                        'type': type, 'value': value_data
                    }
                    return (EventPacketType.attclient_attribute_value,
                            args)
                # attclient_read_multiple_response
                elif packet_command == 6:
                    log.info("received packet attclient_read_multiple_response")
                    connection, handles_len = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    handles_data =\
                        [ord(b) for b in bgapi_rx_payload[2:]]
                    args = {
                        'connection': connection, 'handles': handles_data
                    }
                    return (EventPacketType.
                            attclient_read_multiple_response, args)
            elif packet_class == 5:
                if packet_command == 0:  # sm_smp_data
                    log.info("received packet sm_smp_data")
                    handle, packet, data_len = unpack(
                        '<BBB', bgapi_rx_payload[:3]
                    )
                    data_data = [ord(b) for b in bgapi_rx_payload[3:]]
                    args = {
                        'handle': handle, 'packet': packet,
                        'data': data_data
                    }
                    return EventPacketType.sm_smp_data, args
                elif packet_command == 1:  # sm_bonding_fail
                    log.info("received packet sm_bonding_fail")
                    handle, result = unpack(
                        '<BH', bgapi_rx_payload[:3]
                    )
                    args = {
                        'handle': handle, 'result': result
                    }
                    return EventPacketType.sm_bonding_fail, args
                elif packet_command == 2:  # sm_passkey_display
                    log.info("received packet sm_passkey_display")
                    handle, passkey = unpack(
                        '<BI', bgapi_rx_payload[:5]
                    )
                    args = {
                        'handle': handle, 'passkey': passkey
                    }
                    return EventPacketType.sm_passkey_display, args
                elif packet_command == 3:  # sm_passkey_request
                    log.info("received packet sm_passkey_request")
                    handle = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'handle': handle
                    }
                    return EventPacketType.sm_passkey_request, args
                elif packet_command == 4:  # sm_bond_status
                    log.info("received packet sm_bond_status")
                    bond, keysize, mitm, keys = unpack(
                        '<BBBB', bgapi_rx_payload[:4]
                    )
                    args = {
                        'bond': bond, 'keysize': keysize, 'mitm': mitm,
                        'keys': keys
                    }
                    return EventPacketType.sm_bond_status, args
            elif packet_class == 6:
                if packet_command == 0:  # gap_scan_response
                    log.info("received packet gap_scan_response")
                    data = unpack('<bB6sBBB', bgapi_rx_payload[:11])
                    sender = [ord(b) for b in data[2]]
                    data_data = [ord(b) for b in bgapi_rx_payload[11:]]
                    args = {
                        'rssi': data[0], 'packet_type': data[1],
                        'sender': sender, 'address_type': data[3],
                        'bond': data[4], 'data': data_data
                    }
                    return EventPacketType.gap_scan_response, args
                elif packet_command == 1:  # gap_mode_changed
                    log.info("received packet gap_mode_changed")
                    discover, connect = unpack(
                        '<BB', bgapi_rx_payload[:2]
                    )
                    args = {
                        'discover': discover, 'connect': connect
                    }
                    return EventPacketType.gap_mode_changed, args
            elif packet_class == 7:
                if packet_command == 0:  # hardware_io_port_status
                    log.info("received packet hardware_io_port_status")
                    timestamp, port, irq, state = unpack(
                        '<IBBB', bgapi_rx_payload[:7]
                    )
                    args = {
                        'timestamp': timestamp, 'port': port, 'irq': irq,
                        'state': state
                    }
                    return EventPacketType.hardware_io_port_status, args
                elif packet_command == 1:  # hardware_soft_timer
                    log.info("received packet hardware_io_soft_timer")
                    handle = unpack('<B', bgapi_rx_payload[:1])[0]
                    args = {
                        'handle': handle
                    }
                    return EventPacketType.hardware_soft_timer, args
                elif packet_command == 2:  # hardware_adc_result
                    log.info("received packet hardware_adc_result")
                    input, value = unpack('<Bh', bgapi_rx_payload[:3])
                    args = {
                        'input': input, 'value': value
                    }
                    return EventPacketType.hardware_adc_result, args
