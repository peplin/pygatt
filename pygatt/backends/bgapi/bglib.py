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
from enum import Enum

log = logging.getLogger(__name__)


ResponsePacketType = Enum('ResponsePacketType', [
    'system_reset',
    'system_hello',
    'system_address_get',
    'system_reg_write',
    'system_reg_read',
    'system_get_counters',
    'system_get_connections',
    'system_read_memory',
    'system_get_info',
    'system_endpoint_tx',
    'system_whitelist_append',
    'system_whitelist_remove',
    'system_whitelist_clear',
    'system_endpoint_rx',
    'system_endpoint_set_watermarks',
    'flash_ps_defrag',
    'flash_ps_dump',
    'flash_ps_erase_all',
    'flash_ps_save',
    'flash_ps_load',
    'flash_ps_erase',
    'flash_erase_page',
    'flash_write_words',
    'attributes_write',
    'attributes_read',
    'attributes_read_type',
    'attributes_user_read_response',
    'attributes_user_write_response',
    'connection_disconnect',
    'connection_get_rssi',
    'connection_update',
    'connection_version_update',
    'connection_channel_map_get',
    'connection_channel_map_set',
    'connection_features_get',
    'connection_get_status',
    'connection_raw_tx',
    'attclient_find_by_type_value',
    'attclient_read_by_group_type',
    'attclient_read_by_type',
    'attclient_find_information',
    'attclient_read_by_handle',
    'attclient_attribute_write',
    'attclient_write_command',
    'attclient_indicate_confirm',
    'attclient_read_long',
    'attclient_prepare_write',
    'attclient_execute_write',
    'attclient_read_multiple',
    'sm_encrypt_start',
    'sm_set_bondable_mode',
    'sm_delete_bonding',
    'sm_set_parameters',
    'sm_passkey_entry',
    'sm_get_bonds',
    'sm_set_oob_data',
    'gap_set_privacy_flags',
    'gap_set_mode',
    'gap_discover',
    'gap_connect_direct',
    'gap_end_procedure',
    'gap_connect_selective',
    'gap_set_filtering',
    'gap_set_scan_parameters',
    'gap_set_adv_parameters',
    'gap_set_adv_data',
    'gap_set_directed_connectable_mode',
    'hardware_io_port_config_irq',
    'hardware_set_soft_timer',
    'hardware_adc_read',
    'hardware_io_port_config_direction',
    'hardware_io_port_config_function',
    'hardware_io_port_config_pull',
    'hardware_io_port_write',
    'hardware_io_port_read',
    'hardware_spi_config',
    'hardware_spi_transfer',
    'hardware_i2c_read',
    'hardware_i2c_write',
    'hardware_set_txpower',
    'hardware_timer_comparator',
    'test_phy_tx',
    'test_phy_rx',
    'test_phy_end',
    'test_phy_reset',
    'test_get_channel_map',
    'test_debug',
    ])


EventPacketType = Enum('EventPacketType', [
    'system_boot',
    'system_debug',
    'system_endpoint_watermark_rx',
    'system_endpoint_watermark_tx',
    'system_script_failure',
    'system_no_license_key',
    'flash_ps_key',
    'attributes_value',
    'attributes_user_read_request',
    'attributes_status',
    'connection_status',
    'connection_version_ind',
    'connection_feature_ind',
    'connection_raw_rx',
    'connection_disconnected',
    'attclient_indicated',
    'attclient_procedure_completed',
    'attclient_group_found',
    'attclient_attribute_found',
    'attclient_find_information_found',
    'attclient_attribute_value',
    'attclient_read_multiple_response',
    'sm_smp_data',
    'sm_bonding_fail',
    'sm_passkey_display',
    'sm_passkey_request',
    'sm_bond_status',
    'gap_scan_response',
    'gap_mode_changed',
    'hardware_io_port_status',
    'hardware_soft_timer',
    'hardware_adc_result',
    ])

# Map a tuple of (class, command) to an enum identifier for the packet
RESPONSE_PACKET_MAPPING = {
    (0, 0): ResponsePacketType.system_reset,
    (0, 1): ResponsePacketType.system_hello,
    (0, 2): ResponsePacketType.system_address_get,
    (0, 3): ResponsePacketType.system_reg_write,
    (0, 4): ResponsePacketType.system_reg_read,
    (0, 5): ResponsePacketType.system_get_counters,
    (0, 6): ResponsePacketType.system_get_connections,
    (0, 7): ResponsePacketType.system_read_memory,
    (0, 8): ResponsePacketType.system_get_info,
    (0, 9): ResponsePacketType.system_endpoint_tx,
    (0, 10): ResponsePacketType.system_whitelist_append,
    (0, 11): ResponsePacketType.system_whitelist_remove,
    (0, 12): ResponsePacketType.system_whitelist_clear,
    (0, 13): ResponsePacketType.system_endpoint_rx,
    (0, 14): ResponsePacketType.system_endpoint_set_watermarks,

    (1, 0): ResponsePacketType.flash_ps_defrag,
    (1, 1): ResponsePacketType.flash_ps_dump,
    (1, 2): ResponsePacketType.flash_ps_erase_all,
    (1, 3): ResponsePacketType.flash_ps_save,
    (1, 4): ResponsePacketType.flash_ps_load,
    (1, 5): ResponsePacketType.flash_ps_erase,
    (1, 6): ResponsePacketType.flash_erase_page,
    (1, 7): ResponsePacketType.flash_write_words,

    (2, 0): ResponsePacketType.attributes_write,
    (2, 1): ResponsePacketType.attributes_read,
    (2, 2): ResponsePacketType.attributes_read_type,
    (2, 3): ResponsePacketType.attributes_user_read_response,
    (2, 4): ResponsePacketType.attributes_user_write_response,

    (3, 0): ResponsePacketType.connection_disconnect,
    (3, 1): ResponsePacketType.connection_get_rssi,
    (3, 2): ResponsePacketType.connection_update,
    (3, 3): ResponsePacketType.connection_version_update,
    (3, 4): ResponsePacketType.connection_channel_map_get,
    (3, 5): ResponsePacketType.connection_channel_map_set,
    (3, 6): ResponsePacketType.connection_features_get,
    (3, 7): ResponsePacketType.connection_get_status,
    (3, 8): ResponsePacketType.connection_raw_tx,

    (4, 0): ResponsePacketType.attclient_find_by_type_value,
    (4, 1): ResponsePacketType.attclient_read_by_group_type,
    (4, 2): ResponsePacketType.attclient_read_by_type,
    (4, 3): ResponsePacketType.attclient_find_information,
    (4, 4): ResponsePacketType.attclient_read_by_handle,
    (4, 5): ResponsePacketType.attclient_attribute_write,
    (4, 6): ResponsePacketType.attclient_write_command,
    (4, 7): ResponsePacketType.attclient_indicate_confirm,
    (4, 8): ResponsePacketType.attclient_read_long,
    (4, 9): ResponsePacketType.attclient_prepare_write,
    (4, 10): ResponsePacketType.attclient_execute_write,
    (4, 10): ResponsePacketType.attclient_execute_write,

    (5, 0): ResponsePacketType.sm_encrypt_start,
    (5, 1): ResponsePacketType.sm_set_bondable_mode,
    (5, 2): ResponsePacketType.sm_delete_bonding,
    (5, 3): ResponsePacketType.sm_set_parameters,
    (5, 4): ResponsePacketType.sm_passkey_entry,
    (5, 5): ResponsePacketType.sm_get_bonds,
    (5, 6): ResponsePacketType.sm_set_oob_data,

    (6, 0): ResponsePacketType.gap_set_privacy_flags,
    (6, 1): ResponsePacketType.gap_set_mode,
    (6, 2): ResponsePacketType.gap_discover,
    (6, 3): ResponsePacketType.gap_connect_direct,
    (6, 4): ResponsePacketType.gap_end_procedure,
    (6, 5): ResponsePacketType.gap_connect_selective,
    (6, 6): ResponsePacketType.gap_set_filtering,
    (6, 7): ResponsePacketType.gap_set_scan_parameters,
    (6, 8): ResponsePacketType.gap_set_adv_parameters,
    (6, 9): ResponsePacketType.gap_set_adv_data,
    (6, 10): ResponsePacketType.gap_set_directed_connectable_mode,

    (7, 0): ResponsePacketType.hardware_io_port_config_irq,
    (7, 1): ResponsePacketType.hardware_set_soft_timer,
    (7, 2): ResponsePacketType.hardware_adc_read,
    (7, 3): ResponsePacketType.hardware_io_port_config_direction,
    (7, 4): ResponsePacketType.hardware_io_port_config_function,
    (7, 5): ResponsePacketType.hardware_io_port_config_pull,
    (7, 6): ResponsePacketType.hardware_io_port_write,
    (7, 7): ResponsePacketType.hardware_io_port_read,
    (7, 8): ResponsePacketType.hardware_spi_config,
    (7, 9): ResponsePacketType.hardware_spi_transfer,
    (7, 10): ResponsePacketType.hardware_i2c_read,
    (7, 11): ResponsePacketType.hardware_i2c_write,
    (7, 12): ResponsePacketType.hardware_set_txpower,
    (7, 13): ResponsePacketType.hardware_timer_comparator,

    (8, 0): ResponsePacketType.test_phy_tx,
    (8, 1): ResponsePacketType.test_phy_rx,
    (8, 2): ResponsePacketType.test_phy_reset,
    (8, 3): ResponsePacketType.test_get_channel_map,
    (8, 4): ResponsePacketType.test_debug,
}

# TODO instead of this, have a different enum for each message type + class, and
# then just index into it

EVENT_PACKET_MAPPING = {
    (0, 0): EventPacketType.system_boot,
    (0, 1): EventPacketType.system_debug,
    (0, 2): EventPacketType.system_endpoint_watermark_rx,
    (0, 3): EventPacketType.system_endpoint_watermark_tx,
    (0, 4): EventPacketType.system_script_failure,
    (0, 5): EventPacketType.system_no_license_key,

    (1, 0): EventPacketType.flash_ps_key,

    (2, 0): EventPacketType.attributes_value,
    (2, 1): EventPacketType.attributes_user_read_request,
    (2, 2): EventPacketType.attributes_status,

    (3, 0): EventPacketType.connection_status,
    (3, 1): EventPacketType.connection_version_ind,
    (3, 2): EventPacketType.connection_feature_ind,
    (3, 3): EventPacketType.connection_raw_rx,
    (3, 4): EventPacketType.connection_disconnected,

    (4, 0): EventPacketType.attclient_indicated,
    (4, 1): EventPacketType.attclient_procedure_completed,
    (4, 2): EventPacketType.attclient_group_found,
    (4, 3): EventPacketType.attclient_attribute_found,
    (4, 4): EventPacketType.attclient_find_information_found,
    (4, 5): EventPacketType.attclient_attribute_value,
    (4, 6): EventPacketType.attclient_read_multiple_response,

    (5, 0): EventPacketType.sm_smp_data,
    (5, 1): EventPacketType.sm_bonding_fail,
    (5, 2): EventPacketType.sm_passkey_display,
    (5, 3): EventPacketType.sm_passkey_request,
    (5, 4): EventPacketType.sm_bond_status,

    (6, 0): EventPacketType.gap_scan_response,
    (6, 1): EventPacketType.gap_mode_changed,

    (7, 0): EventPacketType.hardware_io_port_status,
    (7, 1): EventPacketType.hardware_soft_timer,
    (7, 2): EventPacketType.hardware_adc_result,
}


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
        self.buffer = []
        self.expected_length = 0
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
        if (len(self.buffer) == 0 and
            (byte == self._ble_event or byte == self._ble_response or
             byte == self._wifi_event or byte == self._wifi_response)):
            self.buffer.append(byte)
        elif len(self.buffer) == 1:
            self.buffer.append(byte)
            self.expected_length = 4 +\
                (self.buffer[0] & 0x07) + self.buffer[1]
        elif len(self.buffer) > 1:
            self.buffer.append(byte)

        if self.expected_length > 0 and\
           len(self.buffer) == self.expected_length:
            log.info("read complete packet")
            packet = self.buffer
            self.buffer = []
            return packet
        return None

    def _decode_response_packet(self, packet_class, packet_command, payload,
                                payload_length):
        packet_type = RESPONSE_PACKET_MAPPING.get(
            (packet_class, packet_command))
        if packet_type is None:
            # TODO unrecognized packet, log something?
            return

        log.info("Received response packet %s", packet_type)
        response = {}
        if packet_type == ResponsePacketType.system_address_get:
            address = unpack('<6s', payload[:6])[0]
            address = [ord(b) for b in address]
            response = {
                'address': address
            }
        elif packet_type == ResponsePacketType.system_reg_read:
            address, value =\
                unpack('<HB', payload[:3])
            response = {
                'address': address, 'value': value
            }
        elif packet_type == ResponsePacketType.system_get_counters:
            txok, txretry, rxok, rxfail, mbuf =\
                unpack('<BBBBB', payload[:5])
            response = {
                'txok': txok, 'txretry': txretry, 'rxok': rxok,
                'rxfail': rxfail, 'mbuf': mbuf
            }
        elif packet_type == ResponsePacketType.system_get_connections:
            maxconn = unpack('<B', payload[:1])[0]
            response = {
                'maxconn': maxconn
            }
        elif packet_type == ResponsePacketType.system_read_memory:
            address, data_len =\
                unpack('<IB', payload[:5])
            data_data = [ord(b) for b in payload[5:]]
            response = {
                'address': address, 'data': data_data
            }
        elif packet_type == ResponsePacketType.system_get_info:
            data = unpack('<HHHHHBB', payload[:12])
            response = {
                'major': data[0], 'minor': data[1],
                'patch': data[2], 'build': data[3],
                'll_version': data[4], 'protocol_version': data[5],
                'hw': data[6]
            }
        elif packet_type in [
                ResponsePacketType.system_endpoint_tx,
                ResponsePacketType.system_whitelist_append,
                ResponsePacketType.system_whitelist_remove,
                ResponsePacketType.system_endpoint_set_watermarks,
                ResponsePacketType.flash_ps_save,
                ResponsePacketType.flash_erase_page,
                ResponsePacketType.attributes_write,
                ResponsePacketType.system_reg_write,
                ResponsePacketType.attclient_indicate_confirm,
                ResponsePacketType.sm_delete_bonding,
                ResponsePacketType.sm_passkey_entry,
                ResponsePacketType.gap_set_mode,
                ResponsePacketType.gap_discover,
                ResponsePacketType.gap_end_procedure,
                ResponsePacketType.gap_set_filtering,
                ResponsePacketType.hardware_timer_comparator,
                ResponsePacketType.test_phy_end,
                ResponsePacketType.hardware_spi_config,
                ResponsePacketType.gap_set_scan_parameters,
                ResponsePacketType.gap_set_adv_parameters,
                ResponsePacketType.gap_set_adv_data,
                ResponsePacketType.gap_set_directed_connectable_mode,
                ResponsePacketType.hardware_io_port_config_irq,
                ResponsePacketType.hardware_set_soft_timer,
                ResponsePacketType.hardware_adc_read,
                ResponsePacketType.hardware_io_port_config_direction,
                ResponsePacketType.hardware_io_port_config_function,
                ResponsePacketType.hardware_io_port_config_pull,
                ResponsePacketType.hardware_io_port_write]:
            result = unpack('<H', payload[:2])[0]
            response = {
                'result': result
            }
        elif packet_type == ResponsePacketType.system_endpoint_rx:
            result, data_len =\
                unpack('<HB', payload[:3])
            data_data = [ord(b) for b in payload[3:]]
            response = {
                'result': result, 'data': data_data
            }
        elif packet_type == ResponsePacketType.flash_ps_load:
            result, value_len = unpack('<HB',
                                       payload[:3])
            value_data = [ord(b) for b in payload[3:]]
            response = {
                'result': result, 'value': value_data
            }
        elif packet_type == ResponsePacketType.attributes_read:
            handle, offset, result, value_len = unpack(
                '<HHHB', payload[:7]
            )
            value_data = [ord(b) for b in payload[7:]]
            response = {
                'handle': handle, 'offset': offset,
                'result': result, 'value': value_data
            }
        elif packet_type == ResponsePacketType.attributes_read_type:
            handle, result, value_len = unpack(
                '<HHB', payload[:5]
            )
            value_data = [ord(b) for b in payload[5:]]
            response = {
                'handle': handle, 'result': result,
                'value': value_data
            }
        elif packet_type in [
                ResponsePacketType.connection_disconnect,
                ResponsePacketType.connection_update,
                ResponsePacketType.connection_version_update,
                ResponsePacketType.connection_channel_map_set,
                ResponsePacketType.connection_features_get,
                ResponsePacketType.attclient_find_by_type_value,
                ResponsePacketType.attclient_read_by_group_type,
                ResponsePacketType.attclient_read_by_type,
                ResponsePacketType.attclient_find_information,
                ResponsePacketType.attclient_read_by_handle,
                ResponsePacketType.attclient_attribute_write,
                ResponsePacketType.attclient_write_command,
                ResponsePacketType.attclient_read_long,
                ResponsePacketType.attclient_prepare_write,
                ResponsePacketType.attclient_execute_write,
                ResponsePacketType.attclient_read_multiple,
                ]:
            connection, result = unpack(
                '<BH', payload[:3]
            )
            response = {
                'connection': connection, 'result': result
            }
        elif packet_type == ResponsePacketType.connection_get_rssi:
            connection, rssi = unpack(
                '<Bb', payload[:2]
            )
            response = {
                'connection': connection, 'rssi': rssi
            }
        elif packet_type == ResponsePacketType.connection_channel_map_get:
            connection, map_len = unpack(
                '<BB', payload[:2]
            )
            map_data = [ord(b) for b in payload[2:]]
            response = {
                'connection': connection, 'map': map_data
            }
        elif packet_type == ResponsePacketType.connection_get_status:
            connection = unpack('<B', payload[:1])[0]
            response = {
                'connection': connection
            }
        elif packet_type == ResponsePacketType.connection_raw_tx:
            connection = unpack('<B', payload[:1])[0]
            response = {
                'connection': connection
            }
        elif packet_type == ResponsePacketType.sm_encrypt_start:
            handle, result = unpack(
                '<BH', payload[:3]
            )
            response = {
                'handle': handle, 'result': result
            }
        elif packet_type == ResponsePacketType.sm_get_bonds:
            bonds = unpack('<B', payload[:1])[0]
            response = {
                'bonds': bonds
            }
        elif packet_type == ResponsePacketType.gap_connect_direct:
            result, connection_handle = unpack(
                '<HB', payload[:3]
            )
            response = {
                'result': result,
                'connection_handle': connection_handle
            }
        elif packet_type == ResponsePacketType.gap_connect_selective:
            result, connection_handle = unpack(
                '<HB', payload[:3]
            )
            response = {
                'result': result,
                'connection_handle': connection_handle
            }
        elif packet_type == ResponsePacketType.hardware_io_port_read:
            result, port, data = unpack(
                '<HBB', payload[:4]
            )
            response = {
                'result': result, 'port': port, 'data': data
            }
        elif packet_type == ResponsePacketType.hardware_spi_transfer:
            result, channel, data_len = unpack(
                '<HBB', payload[:4]
            )
            data_data = [ord(b) for b in payload[4:]]
            response = {
                'result': result, 'channel': channel,
                'data': data_data
            }
        elif packet_type == ResponsePacketType.hardware_i2c_read:
            result, data_len = unpack(
                '<HB', payload[:3]
            )
            data_data = [ord(b) for b in payload[3:]]
            response = {
                'result': result, 'data': data_data
            }
        elif packet_type == ResponsePacketType.hardware_i2c_write:
            written = unpack('<B', payload[:1])[0]
            response = {
                'written': written
            }
        elif packet_type == ResponsePacketType.test_get_channel_map:
            # channel_map_len = unpack(
            #    '<B', payload[:1]
            # )[0]
            channel_map_data =\
                [ord(b) for b in payload[1:]]
            response = {
                'channel_map': channel_map_data
            }
        elif packet_type == ResponsePacketType.test_debug:
            # output_len = unpack('<B',
            #                     payload[:1])[0]
            output_data =\
                [ord(b) for b in payload[1:]]
            response = {
                'output': output_data
            }

        return packet_type, response

    def _decode_event_packet(self, packet_class, packet_command, payload,
                             payload_length):
        packet_type = EVENT_PACKET_MAPPING.get((packet_class, packet_command))
        if packet_type is None:
            # TODO unrecognized packet, log something?
            return

        log.info("Received event packet %s", packet_type)
        response = {}
        if packet_type == EventPacketType.system_boot:
            data = unpack('<HHHHHBB', payload[:12])
            response = {
                'major': data[0], 'minor': data[1],
                'patch': data[2], 'build': data[3],
                'll_version': data[4], 'protocol_version': data[5],
                'hw': data[6]
            }
        elif packet_type == EventPacketType.system_debug:
            data_len = unpack('<B', payload[:1])[0]
            data_data = [ord(b) for b in payload[1:]]
            response = {
                'data': data_data
            }
        elif packet_type in [EventPacketType.system_endpoint_watermark_rx,
                             EventPacketType.system_endpoint_watermark_tx
                             ]:
            endpoint, data = unpack(
                '<BB', payload[:2]
            )
            response = {
                'endpoint': endpoint, 'data': data
            }
        elif packet_type == EventPacketType.system_script_failure:
            address, reason = unpack(
                '<HH', payload[:4]
            )
            response = {
                'address': address, 'reason': reason
            }
        elif packet_type == EventPacketType.flash_ps_key:
            key, value_len = unpack(
                '<HB', payload[:3]
            )
            value_data = [ord(b) for b in payload[3:]]
            response = {
                'key': key, 'value': value_data
            }
        elif packet_type == EventPacketType.attributes_value:
            connection, reason, handle, offset, value_len = unpack(
                '<BBHHB', payload[:7]
            )
            value_data = [ord(b) for b in payload[7:]]
            response = {
                'connection': connection, 'reason': reason,
                'handle': handle, 'offset': offset,
                'value': value_data
            }
        elif packet_type == EventPacketType.attributes_user_read_request:
            connection, handle, offset, maxsize = unpack(
                '<BHHB', payload[:6]
            )
            response = {
                'connection': connection, 'handle': handle,
                'offset': offset, 'maxsize': maxsize
            }
        elif packet_type == EventPacketType.attributes_status:
            handle, flags = unpack('<HB', payload[:3])
            response = {
                'handle': handle, 'flags': flags
            }
        elif packet_type == EventPacketType.connection_status:
            data = unpack('<BB6sBHHHB', payload[:16])
            address = [ord(b) for b in data[2]]
            response = {
                'connection': data[0], 'flags': data[1],
                'address': address, 'address_type': data[3],
                'conn_interval': data[4], 'timeout': data[5],
                'latency': data[6], 'bonding': data[7]
            }
        elif packet_type == EventPacketType.connection_version_ind:
            connection, vers_nr, comp_id, sub_vers_nr = unpack(
                '<BBHH', payload[:6]
            )
            response = {
                'connection': connection, 'vers_nr': vers_nr,
                'comp_id': comp_id, 'sub_vers_nr': sub_vers_nr
            }
        elif packet_type == EventPacketType.connection_feature_ind:
            connection, features_len = unpack(
                '<BB', payload[:2]
            )
            features_data =\
                [ord(b) for b in payload[2:]]
            response = {
                'connection': connection, 'features': features_data
            }
        elif packet_type == EventPacketType.connection_raw_rx:
            connection, data_len = unpack(
                '<BB', payload[:2]
            )
            data_data = [ord(b) for b in payload[2:]]
            response = {
                'connection': connection, 'data': data_data
            }
        elif packet_type == EventPacketType.connection_disconnected:
            connection, reason = unpack(
                '<BH', payload[:3]
            )
            response = {
                'connection': connection, 'reason': reason
            }
        elif packet_type == EventPacketType.attclient_indicated:
            connection, attrhandle = unpack(
                '<BH', payload[:3]
            )
            response = {
                'connection': connection, 'attrhandle': attrhandle
            }
        elif packet_type == EventPacketType.attclient_procedure_completed:
            connection, result, chrhandle = unpack(
                '<BHH', payload[:5]
            )
            response = {
                'connection': connection, 'result': result,
                'chrhandle': chrhandle
            }
        elif packet_type == EventPacketType.attclient_group_found:
            connection, start, end, uuid_len = unpack(
                '<BHHB', payload[:6]
            )
            uuid_data = [ord(b) for b in payload[6:]]
            response = {
                'connection': connection, 'start': start,
                'end': end, 'uuid': uuid_data
            }
        elif packet_type == EventPacketType.attclient_attribute_found:
            data = unpack('<BHHBB', payload[:7])
            uuid_data = [ord(b) for b in payload[7:]]
            response = {
                'connection': data[0], 'chrdecl': data[1],
                'value': data[2], 'properties': data[3],
                'uuid': uuid_data
            }
        elif packet_type == EventPacketType.attclient_find_information_found:
            connection, chrhandle, uuid_len = unpack(
                '<BHB', payload[:4]
            )
            uuid_data = [ord(b) for b in payload[4:]]
            response = {
                'connection': connection, 'chrhandle': chrhandle,
                'uuid': uuid_data
            }
        elif packet_type == EventPacketType.attclient_attribute_value:
            connection, atthandle, type, value_len = unpack(
                '<BHBB', payload[:5]
            )
            value_data = [ord(b) for b in payload[5:]]
            response = {
                'connection': connection, 'atthandle': atthandle,
                'type': type, 'value': value_data
            }
        elif packet_type == EventPacketType.attclient_read_multiple_response:
            connection, handles_len = unpack(
                '<BB', payload[:2]
            )
            handles_data =\
                [ord(b) for b in payload[2:]]
            response = {
                'connection': connection, 'handles': handles_data
            }
        elif packet_type == EventPacketType.sm_smp_data:
            handle, packet, data_len = unpack(
                '<BBB', payload[:3]
            )
            data_data = [ord(b) for b in payload[3:]]
            response = {
                'handle': handle, 'packet': packet,
                'data': data_data
            }
        elif packet_type == EventPacketType.sm_bonding_fail:
            handle, result = unpack(
                '<BH', payload[:3]
            )
            response = {
                'handle': handle, 'result': result
            }
        elif packet_type == EventPacketType.sm_passkey_display:
            handle, passkey = unpack(
                '<BI', payload[:5]
            )
            response = {
                'handle': handle, 'passkey': passkey
            }
        elif packet_type == EventPacketType.sm_passkey_request:
            handle = unpack('<B', payload[:1])[0]
            response = {
                'handle': handle
            }
        elif packet_type == EventPacketType.sm_bond_status:
            bond, keysize, mitm, keys = unpack(
                '<BBBB', payload[:4]
            )
            response = {
                'bond': bond, 'keysize': keysize, 'mitm': mitm,
                'keys': keys
            }
        elif packet_type == EventPacketType.gap_scan_response:
            data = unpack('<bB6sBBB', payload[:11])
            sender = [ord(b) for b in data[2]]
            data_data = [ord(b) for b in payload[11:]]
            response = {
                'rssi': data[0], 'packet_type': data[1],
                'sender': sender, 'address_type': data[3],
                'bond': data[4], 'data': data_data
            }
        elif packet_type == EventPacketType.gap_mode_changed:
            discover, connect = unpack(
                '<BB', payload[:2]
            )
            response = {
                'discover': discover, 'connect': connect
            }
        elif packet_type == EventPacketType.hardware_io_port_status:
            timestamp, port, irq, state = unpack(
                '<IBBB', payload[:7]
            )
            response = {
                'timestamp': timestamp, 'port': port, 'irq': irq,
                'state': state
            }
        elif packet_type == EventPacketType.hardware_io_soft_timer:
            handle = unpack('<B', payload[:1])[0]
            response = {
                'handle': handle
            }
        elif packet_type == EventPacketType.hardware_adc_result:
            input, value = unpack('<Bh', payload[:3])
            response = {
                'input': input, 'value': value
            }

        return packet_type, response

    def decode_packet(self, packet):
        """
        Decode the packet and call the appropriate handler for the packet type.

        packet -- a list of bytes in the packet to decode.

        Returns a tuple of (PacketType, dict response data)

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
        packet_id, payload_length, packet_class, packet_command = packet[:4]
        # TODO we are not parsing out the high bits of the payload length from
        # the first byte
        payload = b''.join(chr(i) for i in packet[4:])
        message_type = packet_id & 0x88
        if message_type == 0:
            return self._decode_response_packet(
                packet_class, packet_command, payload, payload_length)
        elif message_type == 0x80:
            return self._decode_event_packet(
                packet_class, packet_command, payload, payload_length)
