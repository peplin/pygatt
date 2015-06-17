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


class BGAPIEvent(object):

    def __init__(self, doc=None):
        self.__doc__ = doc

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return BGAPIEventHandler(self, obj)

    def __set__(self, obj, value):
        pass


class BGAPIEventHandler(object):
    def __init__(self, event, obj):
        self.event = event
        self.obj = obj

    def _getfunctionlist(self):
        """(internal use) """
        try:
            eventhandler = self.obj.__eventhandler__
        except AttributeError:
            eventhandler = self.obj.__eventhandler__ = {}
        return eventhandler.setdefault(self.event, [])

    def add(self, func):
        """
        Add new event handler function.

        Event handler function must be defined like func(sender, earg).
        You can add handler also by using '+=' operator.
        """
        self._getfunctionlist().append(func)
        return self

    def remove(self, func):
        """
        Remove existing event handler function.

        You can remove handler also by using '-=' operator.
        """
        self._getfunctionlist().remove(func)
        return self

    def fire(self, earg=None):
        """
        Fire event and call all handler functions

        You can call EventHandler object itself like e(earg) instead of
        e.fire(earg).
        """
        for func in self._getfunctionlist():
            func(self.obj, earg)

    __iadd__ = add
    __isub__ = remove
    __call__ = fire


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
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(loglevel)
        if loghandler is None:
            loghandler = logging.StreamHandler()  # prints to stderr
            formatter = logging.Formatter(
                '%(asctime)s %(name)s %(levelname)s - %(message)s')
            loghandler.setLevel(loglevel)
            loghandler.setFormatter(formatter)
        self._logger.addHandler(loghandler)

    def ble_cmd_system_reset(self, boot_in_dfu):
        self._logger.info("construct command ble_cmd_system_reset")
        return pack('<4BB', 0, 1, 0, 0, boot_in_dfu)

    def ble_cmd_system_hello(self):
        self._logger.info("construct command ble_cmd_system_hello")
        return pack('<4B', 0, 0, 0, 1)

    def ble_cmd_system_address_get(self):
        self._logger.info("construct command ble_cmd_system_address_get")
        return pack('<4B', 0, 0, 0, 2)

    def ble_cmd_system_reg_write(self, address, value):
        self._logger.info("construct command ble_cmd_system_reg_write")
        return pack('<4BHB', 0, 3, 0, 3, address, value)

    def ble_cmd_system_reg_read(self, address):
        self._logger.info("construct command ble_cmd_system_reg_read")
        return pack('<4BH', 0, 2, 0, 4, address)

    def ble_cmd_system_get_counters(self):
        self._logger.info("construct command ble_cmd_system_get_counters")
        return pack('<4B', 0, 0, 0, 5)

    def ble_cmd_system_get_connections(self):
        self._logger.info("construct command ble_cmd_system_get_connections")
        return pack('<4B', 0, 0, 0, 6)

    def ble_cmd_system_read_memory(self, address, length):
        self._logger.info("construct command ble_cmd_system_read_memory")
        return pack('<4BIB', 0, 5, 0, 7, address, length)

    def ble_cmd_system_get_info(self):
        self._logger.info("construct command ble_cmd_system_get_info")
        return pack('<4B', 0, 0, 0, 8)

    def ble_cmd_system_endpoint_tx(self, endpoint, data):
        self._logger.info("construct command ble_cmd_system_endpoint_tx")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 0, 9,
                    endpoint, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_system_whitelist_append(self, address, address_type):
        self._logger.info("construct command ble_cmd_system_whitelist_append")
        return pack('<4B6sB', 0, 7, 0, 10, b''.join(chr(i) for i in address),
                    address_type)

    def ble_cmd_system_whitelist_remove(self, address, address_type):
        self._logger.info("construct command ble_cmd_system_whitelist_remove")
        return pack('<4B6sB', 0, 7, 0, 11, b''.join(chr(i) for i in address),
                    address_type)

    def ble_cmd_system_whitelist_clear(self):
        self._logger.info("construct command ble_cmd_system_whitelist_clear")
        return pack('<4B', 0, 0, 0, 12)

    def ble_cmd_system_endpoint_rx(self, endpoint, size):
        self._logger.info("construct command ble_cmd_system_endpoint_rx")
        return pack('<4BBB', 0, 2, 0, 13, endpoint, size)

    def ble_cmd_system_endpoint_set_watermarks(self, endpoint, rx, tx):
        self._logger.info(
            "construct command ble_cmd_system_endpoint_set_watermarks")
        return pack('<4BBBB', 0, 3, 0, 14, endpoint, rx, tx)

    def ble_cmd_flash_ps_defrag(self):
        self._logger.info("construct command ble_cmd_flash_ps_defrag")
        return pack('<4B', 0, 0, 1, 0)

    def ble_cmd_flash_ps_dump(self):
        self._logger.info("construct command ble_cmd_flash_ps_dump")
        return pack('<4B', 0, 0, 1, 1)

    def ble_cmd_flash_ps_erase_all(self):
        self._logger.info("construct command ble_cmd_flash_ps_erase_all")
        return pack('<4B', 0, 0, 1, 2)

    def ble_cmd_flash_ps_save(self, key, value):
        self._logger.info("construct command ble_cmd_flash_ps_save")
        return pack('<4BHB' + str(len(value)) + 's', 0, 3 + len(value), 1, 3,
                    key, len(value), b''.join(chr(i) for i in value))

    def ble_cmd_flash_ps_load(self, key):
        self._logger.info("construct command ble_cmd_flash_ps_load")
        return pack('<4BH', 0, 2, 1, 4, key)

    def ble_cmd_flash_ps_erase(self, key):
        self._logger.info("construct command ble_cmd_flash_ps_erase")
        return pack('<4BH', 0, 2, 1, 5, key)

    def ble_cmd_flash_erase_page(self, page):
        self._logger.info("construct command ble_cmd_flash_ps_erase_page")
        return pack('<4BB', 0, 1, 1, 6, page)

    def ble_cmd_flash_write_words(self, address, words):
        self._logger.info("construct command ble_cmd_flash_write_words")
        return pack('<4BHB' + str(len(words)) + 's', 0, 3 + len(words), 1, 7,
                    address, len(words), b''.join(chr(i) for i in words))

    def ble_cmd_attributes_write(self, handle, offset, value):
        self._logger.info("construct command ble_cmd_attributes_write")
        return pack('<4BHBB' + str(len(value)) + 's', 0, 4 + len(value), 2, 0,
                    handle, offset, len(value), b''.join(chr(i) for i in value))

    def ble_cmd_attributes_read(self, handle, offset):
        self._logger.info("construct command ble_cmd_attributes_read")
        return pack('<4BHH', 0, 4, 2, 1, handle, offset)

    def ble_cmd_attributes_read_type(self, handle):
        self._logger.info("construct command ble_cmd_attributes_read_type")
        return pack('<4BH', 0, 2, 2, 2, handle)

    def ble_cmd_attributes_user_read_response(self, connection, att_error,
                                              value):
        self._logger.info(
            "construct command ble_cmd_attributes_user_read_response")
        return pack('<4BBBB' + str(len(value)) + 's', 0, 3 + len(value), 2, 3,
                    connection, att_error, len(value),
                    b''.join(chr(i) for i in value))

    def ble_cmd_attributes_user_write_response(self, connection, att_error):
        self._logger.info(
            "construct command ble_cmd_attributes_user_write_response")
        return pack('<4BBB', 0, 2, 2, 4, connection, att_error)

    def ble_cmd_connection_disconnect(self, connection):
        self._logger.info("construct command ble_cmd_connection_disconnnect")
        return pack('<4BB', 0, 1, 3, 0, connection)

    def ble_cmd_connection_get_rssi(self, connection):
        self._logger.info("construct command ble_cmd_connection_get_rssi")
        return pack('<4BB', 0, 1, 3, 1, connection)

    def ble_cmd_connection_update(self, connection, interval_min, interval_max,
                                  latency, timeout):
        self._logger.info("construct command ble_cmd_connection_update")
        return pack('<4BBHHHH', 0, 9, 3, 2, connection, interval_min,
                    interval_max, latency, timeout)

    def ble_cmd_connection_version_update(self, connection):
        self._logger.info("construct command ble_cmd_connection_version_update")
        return pack('<4BB', 0, 1, 3, 3, connection)

    def ble_cmd_connection_channel_map_get(self, connection):
        self._logger.info(
            "construct command ble_cmd_connection_channel_map_get")
        return pack('<4BB', 0, 1, 3, 4, connection)

    def ble_cmd_connection_channel_map_set(self, connection, map):
        self._logger.info(
            "construct command ble_cmd_connection_channel_map_set")
        return pack('<4BBB' + str(len(map)) + 's', 0, 2 + len(map), 3, 5,
                    connection, len(map), b''.join(chr(i) for i in map))

    def ble_cmd_connection_features_get(self, connection):
        self._logger.info("construct command ble_cmd_connection_features_get")
        return pack('<4BB', 0, 1, 3, 6, connection)

    def ble_cmd_connection_get_status(self, connection):
        self._logger.info("construct command ble_cmd_connection_get_status")
        return pack('<4BB', 0, 1, 3, 7, connection)

    def ble_cmd_connection_raw_tx(self, connection, data):
        self._logger.info("construct command ble_cmd_connection_raw_tx")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 3, 8,
                    connection, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_attclient_find_by_type_value(self, connection, start, end, uuid,
                                             value):
        self._logger.info(
            "construct command ble_cmd_attclient_find_by_type_value")
        return pack('<4BBHHHB' + str(len(value)) + 's', 0, 8 + len(value), 4, 0,
                    connection, start, end, uuid, len(value),
                    b''.join(chr(i) for i in value))

    def ble_cmd_attclient_read_by_group_type(self, connection, start, end,
                                             uuid):
        self._logger.info(
            "construct command ble_cmd_attclient_read_by_group_type")
        return pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 1,
                    connection, start, end, len(uuid),
                    b''.join(chr(i) for i in uuid))

    def ble_cmd_attclient_read_by_type(self, connection, start, end, uuid):
        self._logger.info("construct command ble_cmd_attclient_read_by_type")
        return pack('<4BBHHB' + str(len(uuid)) + 's', 0, 6 + len(uuid), 4, 2,
                    connection, start, end, len(uuid),
                    b''.join(chr(i) for i in uuid))

    def ble_cmd_attclient_find_information(self, connection, start, end):
        self._logger.info(
            "construct command ble_cmd_attclient_find_information")
        return pack('<4BBHH', 0, 5, 4, 3, connection, start, end)

    def ble_cmd_attclient_read_by_handle(self, connection, chrhandle):
        self._logger.info("construct command ble_cmd_attclient_read_by_handle")
        return pack('<4BBH', 0, 3, 4, 4, connection, chrhandle)

    def ble_cmd_attclient_attribute_write(self, connection, atthandle, data):
        self._logger.info("construct command ble_cmd_attclient_attribute_write")
        return pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 5,
                    connection, atthandle, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_write_command(self, connection, atthandle, data):
        self._logger.info("construct command ble_cmd_attclient_write_command")
        return pack('<4BBHB' + str(len(data)) + 's', 0, 4 + len(data), 4, 6,
                    connection, atthandle, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_indicate_confirm(self, connection):
        self._logger.info(
            "construct command ble_cmd_attclient_indicate_confirm")
        return pack('<4BB', 0, 1, 4, 7, connection)

    def ble_cmd_attclient_read_long(self, connection, chrhandle):
        self._logger.info("construct command ble_cmd_attclient_read_long")
        return pack('<4BBH', 0, 3, 4, 8, connection, chrhandle)

    def ble_cmd_attclient_prepare_write(self, connection, atthandle, offset,
                                        data):
        self._logger.info("construct command ble_cmd_attclient_prepare_write")
        return pack('<4BBHHB' + str(len(data)) + 's', 0, 6 + len(data), 4, 9,
                    connection, atthandle, offset, len(data),
                    b''.join(chr(i) for i in data))

    def ble_cmd_attclient_execute_write(self, connection, commit):
        self._logger.info("construct command ble_cmd_attclient_execute_write")
        return pack('<4BBB', 0, 2, 4, 10, connection, commit)

    def ble_cmd_attclient_read_multiple(self, connection, handles):
        self._logger.info("construct command ble_cmd_attclient_read_multiple")
        return pack('<4BBB' + str(len(handles)) + 's', 0, 2 + len(handles), 4,
                    11, connection, len(handles),
                    b''.join(chr(i) for i in handles))

    def ble_cmd_sm_encrypt_start(self, handle, bonding):
        self._logger.info("construct command ble_cmd_sm_encrypt_start")
        return pack('<4BBB', 0, 2, 5, 0, handle, bonding)

    def ble_cmd_sm_set_bondable_mode(self, bondable):
        self._logger.info("construct command ble_cmd_sm_set_bondable_mode")
        return pack('<4BB', 0, 1, 5, 1, bondable)

    def ble_cmd_sm_delete_bonding(self, handle):
        self._logger.info("construct command ble_cmd_sm_delete_bonding")
        return pack('<4BB', 0, 1, 5, 2, handle)

    def ble_cmd_sm_set_parameters(self, mitm, min_key_size, io_capabilities):
        self._logger.info("construct command ble_cmd_sm_set_parameters")
        return pack('<4BBBB', 0, 3, 5, 3, mitm, min_key_size, io_capabilities)

    def ble_cmd_sm_passkey_entry(self, handle, passkey):
        self._logger.info("construct command ble_cmd_sm_passkey_entry")
        return pack('<4BBI', 0, 5, 5, 4, handle, passkey)

    def ble_cmd_sm_get_bonds(self):
        self._logger.info("construct command ble_cmd_sm_get_bonds")
        return pack('<4B', 0, 0, 5, 5)

    def ble_cmd_sm_set_oob_data(self, oob):
        self._logger.info("construct command ble_cmd_sm_oob_data")
        return pack('<4BB' + str(len(oob)) + 's', 0, 1 + len(oob), 5, 6,
                    len(oob), b''.join(chr(i) for i in oob))

    def ble_cmd_gap_set_privacy_flags(self, peripheral_privacy,
                                      central_privacy):
        self._logger.info("construct command ble_cmd_gap_set_privacy_flags")
        return pack('<4BBB', 0, 2, 6, 0, peripheral_privacy, central_privacy)

    def ble_cmd_gap_set_mode(self, discover, connect):
        self._logger.info("construct command ble_cmd_gap_set_mode")
        return pack('<4BBB', 0, 2, 6, 1, discover, connect)

    def ble_cmd_gap_discover(self, mode):
        self._logger.info("construct command ble_cmd_gap_discover")
        return pack('<4BB', 0, 1, 6, 2, mode)

    def ble_cmd_gap_connect_direct(self, address, addr_type, conn_interval_min,
                                   conn_interval_max, timeout, latency):
        self._logger.info("construct command ble_cmd_gap_connect_direct")
        return pack('<4B6sBHHHH', 0, 15, 6, 3,
                    b''.join(chr(i) for i in address), addr_type,
                    conn_interval_min, conn_interval_max, timeout, latency)

    def ble_cmd_gap_end_procedure(self):
        self._logger.info("construct command ble_cmd_gap_end_procedure")
        return pack('<4B', 0, 0, 6, 4)

    def ble_cmd_gap_connect_selective(self, conn_interval_min,
                                      conn_interval_max, timeout, latency):
        self._logger.info("construct command ble_cmd_gap_connect_selective")
        return pack('<4BHHHH', 0, 8, 6, 5, conn_interval_min, conn_interval_max,
                    timeout, latency)

    def ble_cmd_gap_set_filtering(self, scan_policy, adv_policy,
                                  scan_duplicate_filtering):
        self._logger.info("construct command ble_cmd_gap_set_filtering")
        return pack('<4BBBB', 0, 3, 6, 6, scan_policy, adv_policy,
                    scan_duplicate_filtering)

    def ble_cmd_gap_set_scan_parameters(self, scan_interval, scan_window,
                                        active):
        self._logger.info("construct command ble_cmd_gap_set_scan_parameters")
        return pack('<4BHHB', 0, 5, 6, 7, scan_interval, scan_window, active)

    def ble_cmd_gap_set_adv_parameters(self, adv_interval_min,
                                       adv_interval_max, adv_channels):
        self._logger.info("construct command ble_cmd_gap_set_adv_parameters")
        return pack('<4BHHB', 0, 5, 6, 8, adv_interval_min, adv_interval_max,
                    adv_channels)

    def ble_cmd_gap_set_adv_data(self, set_scanrsp, adv_data):
        self._logger.info("construct command ble_cmd_gap_set_adv_data")
        return pack('<4BBB' + str(len(adv_data)) + 's', 0, 2 + len(adv_data), 6,
                    9, set_scanrsp, len(adv_data),
                    b''.join(chr(i) for i in adv_data))

    def ble_cmd_gap_set_directed_connectable_mode(self, address, addr_type):
        self._logger.info(
            "construct command ble_cmd_gap_set_directed_connectable_mode")
        return pack('<4B6sB', 0, 7, 6, 10, b''.join(chr(i) for i in address),
                    addr_type)

    def ble_cmd_hardware_io_port_config_irq(self, port, enable_bits,
                                            falling_edge):
        self._logger.info(
            "construct command ble_cmd_hardware_io_port_config_irq")
        return pack('<4BBBB', 0, 3, 7, 0, port, enable_bits, falling_edge)

    def ble_cmd_hardware_set_soft_timer(self, time, handle, single_shot):
        self._logger.info("construct command ble_cmd_hardware_set_soft_timer")
        return pack('<4BIBB', 0, 6, 7, 1, time, handle, single_shot)

    def ble_cmd_hardware_adc_read(self, input, decimation, reference_selection):
        self._logger.info("construct command ble_cmd_hardware_adc_read")
        return pack('<4BBBB', 0, 3, 7, 2, input, decimation,
                    reference_selection)

    def ble_cmd_hardware_io_port_config_direction(self, port, direction):
        self._logger.info(
            "construct command ble_cmd_hardware_io_port_config_direction")
        return pack('<4BBB', 0, 2, 7, 3, port, direction)

    def ble_cmd_hardware_io_port_config_function(self, port, function):
        self._logger.info(
            "construct command ble_cmd_hardware_io_port_config_function")
        return pack('<4BBB', 0, 2, 7, 4, port, function)

    def ble_cmd_hardware_io_port_config_pull(self, port, tristate_mask,
                                             pull_up):
        self._logger.info(
            "construct command ble_cmd_hardware_io_port_config_pull")
        return pack('<4BBBB', 0, 3, 7, 5, port, tristate_mask, pull_up)

    def ble_cmd_hardware_io_port_write(self, port, mask, data):
        self._logger.info("construct command ble_cmd_hardware_io_prot_write")
        return pack('<4BBBB', 0, 3, 7, 6, port, mask, data)

    def ble_cmd_hardware_io_port_read(self, port, mask):
        self._logger.info("construct command ble_cmd_hardware_io_port_read")
        return pack('<4BBB', 0, 2, 7, 7, port, mask)

    def ble_cmd_hardware_spi_config(self, channel, polarity, phase, bit_order,
                                    baud_e, baud_m):
        self._logger.info("construct command ble_cmd_hardware_spi_config")
        return pack('<4BBBBBBB', 0, 6, 7, 8, channel, polarity, phase,
                    bit_order, baud_e, baud_m)

    def ble_cmd_hardware_spi_transfer(self, channel, data):
        self._logger.info("construct command ble_cmd_hardware_spi_transfer")
        return pack('<4BBB' + str(len(data)) + 's', 0, 2 + len(data), 7, 9,
                    channel, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_hardware_i2c_read(self, address, stop, length):
        self._logger.info("construct command ble_cmd_hardware_i2c_read")
        return pack('<4BBBB', 0, 3, 7, 10, address, stop, length)

    def ble_cmd_hardware_i2c_write(self, address, stop, data):
        self._logger.info("construct command ble_cmd_hardware_i2c_write")
        return pack('<4BBBB' + str(len(data)) + 's', 0, 3 + len(data), 7, 11,
                    address, stop, len(data), b''.join(chr(i) for i in data))

    def ble_cmd_hardware_set_txpower(self, power):
        self._logger.info("construct command ble_cmd_hardware_set_txpower")
        return pack('<4BB', 0, 1, 7, 12, power)

    def ble_cmd_hardware_timer_comparator(self, timer, channel, mode,
                                          comparator_value):
        self._logger.info("construct command ble_cmd_hardware_timer_comparator")
        return pack('<4BBBBH', 0, 5, 7, 13, timer, channel, mode,
                    comparator_value)

    def ble_cmd_test_phy_tx(self, channel, length, type):
        self._logger.info("construct command ble_cmd_test_phy_tx")
        return pack('<4BBBB', 0, 3, 8, 0, channel, length, type)

    def ble_cmd_test_phy_rx(self, channel):
        self._logger.info("construct command ble_cmd_test_phy_rx")
        return pack('<4BB', 0, 1, 8, 1, channel)

    def ble_cmd_test_phy_end(self):
        self._logger.info("construct command ble_cmd_test_phy_end")
        return pack('<4B', 0, 0, 8, 2)

    def ble_cmd_test_phy_reset(self):
        self._logger.info("construct command ble_cmd_test_phy_reset")
        return pack('<4B', 0, 0, 8, 3)

    def ble_cmd_test_get_channel_map(self):
        self._logger.info("construct command ble_cmd_test_get_channel_map")
        return pack('<4B', 0, 0, 8, 4)

    def ble_cmd_test_debug(self, input):
        self._logger.info("construct command ble_cmd_test_debug")
        return pack('<4BB' + str(len(input)) + 's', 0, 1 + len(input), 8, 5,
                    len(input), b''.join(chr(i) for i in input))

    ble_rsp_system_reset = BGAPIEvent()
    ble_rsp_system_hello = BGAPIEvent()
    ble_rsp_system_address_get = BGAPIEvent()
    ble_rsp_system_reg_write = BGAPIEvent()
    ble_rsp_system_reg_read = BGAPIEvent()
    ble_rsp_system_get_counters = BGAPIEvent()
    ble_rsp_system_get_connections = BGAPIEvent()
    ble_rsp_system_read_memory = BGAPIEvent()
    ble_rsp_system_get_info = BGAPIEvent()
    ble_rsp_system_endpoint_tx = BGAPIEvent()
    ble_rsp_system_whitelist_append = BGAPIEvent()
    ble_rsp_system_whitelist_remove = BGAPIEvent()
    ble_rsp_system_whitelist_clear = BGAPIEvent()
    ble_rsp_system_endpoint_rx = BGAPIEvent()
    ble_rsp_system_endpoint_set_watermarks = BGAPIEvent()
    ble_rsp_flash_ps_defrag = BGAPIEvent()
    ble_rsp_flash_ps_dump = BGAPIEvent()
    ble_rsp_flash_ps_erase_all = BGAPIEvent()
    ble_rsp_flash_ps_save = BGAPIEvent()
    ble_rsp_flash_ps_load = BGAPIEvent()
    ble_rsp_flash_ps_erase = BGAPIEvent()
    ble_rsp_flash_erase_page = BGAPIEvent()
    ble_rsp_flash_write_words = BGAPIEvent()
    ble_rsp_attributes_write = BGAPIEvent()
    ble_rsp_attributes_read = BGAPIEvent()
    ble_rsp_attributes_read_type = BGAPIEvent()
    ble_rsp_attributes_user_read_response = BGAPIEvent()
    ble_rsp_attributes_user_write_response = BGAPIEvent()
    ble_rsp_connection_disconnect = BGAPIEvent()
    ble_rsp_connection_get_rssi = BGAPIEvent()
    ble_rsp_connection_update = BGAPIEvent()
    ble_rsp_connection_version_update = BGAPIEvent()
    ble_rsp_connection_channel_map_get = BGAPIEvent()
    ble_rsp_connection_channel_map_set = BGAPIEvent()
    ble_rsp_connection_features_get = BGAPIEvent()
    ble_rsp_connection_get_status = BGAPIEvent()
    ble_rsp_connection_raw_tx = BGAPIEvent()
    ble_rsp_attclient_find_by_type_value = BGAPIEvent()
    ble_rsp_attclient_read_by_group_type = BGAPIEvent()
    ble_rsp_attclient_read_by_type = BGAPIEvent()
    ble_rsp_attclient_find_information = BGAPIEvent()
    ble_rsp_attclient_read_by_handle = BGAPIEvent()
    ble_rsp_attclient_attribute_write = BGAPIEvent()
    ble_rsp_attclient_write_command = BGAPIEvent()
    ble_rsp_attclient_indicate_confirm = BGAPIEvent()
    ble_rsp_attclient_read_long = BGAPIEvent()
    ble_rsp_attclient_prepare_write = BGAPIEvent()
    ble_rsp_attclient_execute_write = BGAPIEvent()
    ble_rsp_attclient_read_multiple = BGAPIEvent()
    ble_rsp_sm_encrypt_start = BGAPIEvent()
    ble_rsp_sm_set_bondable_mode = BGAPIEvent()
    ble_rsp_sm_delete_bonding = BGAPIEvent()
    ble_rsp_sm_set_parameters = BGAPIEvent()
    ble_rsp_sm_passkey_entry = BGAPIEvent()
    ble_rsp_sm_get_bonds = BGAPIEvent()
    ble_rsp_sm_set_oob_data = BGAPIEvent()
    ble_rsp_gap_set_privacy_flags = BGAPIEvent()
    ble_rsp_gap_set_mode = BGAPIEvent()
    ble_rsp_gap_discover = BGAPIEvent()
    ble_rsp_gap_connect_direct = BGAPIEvent()
    ble_rsp_gap_end_procedure = BGAPIEvent()
    ble_rsp_gap_connect_selective = BGAPIEvent()
    ble_rsp_gap_set_filtering = BGAPIEvent()
    ble_rsp_gap_set_scan_parameters = BGAPIEvent()
    ble_rsp_gap_set_adv_parameters = BGAPIEvent()
    ble_rsp_gap_set_adv_data = BGAPIEvent()
    ble_rsp_gap_set_directed_connectable_mode = BGAPIEvent()
    ble_rsp_hardware_io_port_config_irq = BGAPIEvent()
    ble_rsp_hardware_set_soft_timer = BGAPIEvent()
    ble_rsp_hardware_adc_read = BGAPIEvent()
    ble_rsp_hardware_io_port_config_direction = BGAPIEvent()
    ble_rsp_hardware_io_port_config_function = BGAPIEvent()
    ble_rsp_hardware_io_port_config_pull = BGAPIEvent()
    ble_rsp_hardware_io_port_write = BGAPIEvent()
    ble_rsp_hardware_io_port_read = BGAPIEvent()
    ble_rsp_hardware_spi_config = BGAPIEvent()
    ble_rsp_hardware_spi_transfer = BGAPIEvent()
    ble_rsp_hardware_i2c_read = BGAPIEvent()
    ble_rsp_hardware_i2c_write = BGAPIEvent()
    ble_rsp_hardware_set_txpower = BGAPIEvent()
    ble_rsp_hardware_timer_comparator = BGAPIEvent()
    ble_rsp_test_phy_tx = BGAPIEvent()
    ble_rsp_test_phy_rx = BGAPIEvent()
    ble_rsp_test_phy_end = BGAPIEvent()
    ble_rsp_test_phy_reset = BGAPIEvent()
    ble_rsp_test_get_channel_map = BGAPIEvent()
    ble_rsp_test_debug = BGAPIEvent()

    ble_evt_system_boot = BGAPIEvent()
    ble_evt_system_debug = BGAPIEvent()
    ble_evt_system_endpoint_watermark_rx = BGAPIEvent()
    ble_evt_system_endpoint_watermark_tx = BGAPIEvent()
    ble_evt_system_script_failure = BGAPIEvent()
    ble_evt_system_no_license_key = BGAPIEvent()
    ble_evt_flash_ps_key = BGAPIEvent()
    ble_evt_attributes_value = BGAPIEvent()
    ble_evt_attributes_user_read_request = BGAPIEvent()
    ble_evt_attributes_status = BGAPIEvent()
    ble_evt_connection_status = BGAPIEvent()
    ble_evt_connection_version_ind = BGAPIEvent()
    ble_evt_connection_feature_ind = BGAPIEvent()
    ble_evt_connection_raw_rx = BGAPIEvent()
    ble_evt_connection_disconnected = BGAPIEvent()
    ble_evt_attclient_indicated = BGAPIEvent()
    ble_evt_attclient_procedure_completed = BGAPIEvent()
    ble_evt_attclient_group_found = BGAPIEvent()
    ble_evt_attclient_attribute_found = BGAPIEvent()
    ble_evt_attclient_find_information_found = BGAPIEvent()
    ble_evt_attclient_attribute_value = BGAPIEvent()
    ble_evt_attclient_read_multiple_response = BGAPIEvent()
    ble_evt_sm_smp_data = BGAPIEvent()
    ble_evt_sm_bonding_fail = BGAPIEvent()
    ble_evt_sm_passkey_display = BGAPIEvent()
    ble_evt_sm_passkey_request = BGAPIEvent()
    ble_evt_sm_bond_status = BGAPIEvent()
    ble_evt_gap_scan_response = BGAPIEvent()
    ble_evt_gap_mode_changed = BGAPIEvent()
    ble_evt_hardware_io_port_status = BGAPIEvent()
    ble_evt_hardware_soft_timer = BGAPIEvent()
    ble_evt_hardware_adc_result = BGAPIEvent()

    on_busy = BGAPIEvent()
    on_idle = BGAPIEvent()
    on_timeout = BGAPIEvent()
    on_before_tx_command = BGAPIEvent()
    on_tx_command_complete = BGAPIEvent()

    bgapi_rx_buffer = []
    bgapi_rx_expected_length = 0
    busy = False
    packet_mode = False
    debug = False

    def send_command(self, ser, packet):
        self._logger.info("Sending command")
        if self.packet_mode:
            packet = chr(len(packet) & 0xFF) + packet
        if self.debug:
            print('=>[ ' + ' '.join(['%02X' % ord(b) for b in packet]) + ' ]')
        self.on_before_tx_command()
        self.busy = True
        self.on_busy()
        ser.write(packet)
        self.on_tx_command_complete()

    def parse(self, byte):
        if len(self.bgapi_rx_buffer) == 0 and\
           (byte == 0x00 or byte == 0x80 or byte == 0x08 or byte == 0x88):
            self.bgapi_rx_buffer.append(byte)
        elif len(self.bgapi_rx_buffer) == 1:
            self.bgapi_rx_buffer.append(byte)
            self.bgapi_rx_expected_length = 4 +\
                (self.bgapi_rx_buffer[0] & 0x07) + self.bgapi_rx_buffer[1]
        elif len(self.bgapi_rx_buffer) > 1:
            self.bgapi_rx_buffer.append(byte)
        """
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
        # print('%02X: %d, %d' % (b, len(self.bgapi_rx_buffer),
        #       self.bgapi_rx_expected_length)
        if self.bgapi_rx_expected_length > 0 and\
           len(self.bgapi_rx_buffer) == self.bgapi_rx_expected_length:
            if self.debug:
                print('<=[ ' +
                      ' '.join(['%02X' % b for b in self.bgapi_rx_buffer]) +
                      ' ]')
            packet_type, payload_length, packet_class, packet_command =\
                self.bgapi_rx_buffer[:4]
            self.bgapi_rx_payload =\
                b''.join(chr(i) for i in self.bgapi_rx_buffer[4:])
            self.bgapi_rx_buffer = []
            if packet_type & 0x88 == 0x00:
                # 0x00 = BLE response packet
                if packet_class == 0:
                    if packet_command == 0:  # ble_rsp_system_reset
                        self._logger.info(
                            "received packet ble_rsp_system_reset")
                        self.ble_rsp_system_reset({})
                        self.busy = False
                        self.on_idle()
                    elif packet_command == 1:  # ble_rsp_system_hello
                        self._logger.info(
                            "received packet ble_rsp_system_hello")
                        self.ble_rsp_system_hello({})
                    elif packet_command == 2:  # ble_rsp_system_address_get
                        self._logger.info(
                            "received packet ble_rsp_system_address_get")
                        address = unpack('<6s', self.bgapi_rx_payload[:6])[0]
                        address = [ord(b) for b in address]
                        self.ble_rsp_system_address_get({
                            'address': address
                        })
                    elif packet_command == 3:  # ble_rsp_system_reg_write
                        self._logger.info(
                            "received packet ble_rsp_system_reg_write")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_system_reg_write({
                            'result': result
                        })
                    elif packet_command == 4:  # ble_rsp_system_reg_read
                        self._logger.info(
                            "received packet ble_rsp_system_reg_read")
                        address, value =\
                            unpack('<HB', self.bgapi_rx_payload[:3])
                        self.ble_rsp_system_reg_read({
                            'address': address, 'value': value
                        })
                    elif packet_command == 5:  # ble_rsp_system_get_counters
                        self._logger.info(
                            "received packet ble_rsp_system_get_counters")
                        txok, txretry, rxok, rxfail, mbuf =\
                            unpack('<BBBBB', self.bgapi_rx_payload[:5])
                        self.ble_rsp_system_get_counters({
                            'txok': txok, 'txretry': txretry, 'rxok': rxok,
                            'rxfail': rxfail, 'mbuf': mbuf
                        })
                    elif packet_command == 6:  # ble_rsp_system_get_connections
                        self._logger.info(
                            "received packet ble_rsp_system_get_connections")
                        maxconn = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_rsp_system_get_connections({
                            'maxconn': maxconn
                        })
                    elif packet_command == 7:  # ble_rsp_system_read_memory
                        self._logger.info(
                            "received packet ble_rsp_system_read_memory")
                        address, data_len =\
                            unpack('<IB', self.bgapi_rx_payload[:5])
                        data_data = [ord(b) for b in self.bgapi_rx_payload[5:]]
                        self.ble_rsp_system_read_memory({
                            'address': address, 'data': data_data
                        })
                    elif packet_command == 8:  # ble_rsp_system_get_info
                        self._logger.info(
                            "received packet ble_rsp_system_get_info")
                        data = unpack('<HHHHHBB', self.bgapi_rx_payload[:12])
                        self.ble_rsp_system_get_info({
                            'major': data[0], 'minor': data[1],
                            'patch': data[2], 'build': data[3],
                            'll_version': data[4], 'protocol_version': data[5],
                            'hw': data[6]
                        })
                    elif packet_command == 9:  # ble_rsp_system_endpoint_tx
                        self._logger.info(
                            "received packet ble_rsp_system_endpoint_tx")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_system_endpoint_tx({
                            'result': result
                        })
                    # ble_rsp_system_whitelist_append
                    elif packet_command == 10:
                        self._logger.info(
                            "received packet ble_rsp_system_whitelist_append")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_system_whitelist_append({
                            'result': result
                        })
                    # ble_rsp_system_whitelist_remove
                    elif packet_command == 11:
                        self._logger.info(
                            "received packet ble_rsp_system_whitelist_remove")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_system_whitelist_remove({
                            'result': result
                        })
                    elif packet_command == 12:  # ble_rsp_system_whitelist_clear
                        self._logger.info(
                            "received packet ble_rsp_system_whitelist_clear")
                        self.ble_rsp_system_whitelist_clear({})
                    elif packet_command == 13:  # ble_rsp_system_endpoint_rx
                        self._logger.info(
                            "received packet ble_rsp_system_endpoint_rx")
                        result, data_len =\
                            unpack('<HB', self.bgapi_rx_payload[:3])
                        data_data = [ord(b) for b in self.bgapi_rx_payload[3:]]
                        self.ble_rsp_system_endpoint_rx({
                            'result': result, 'data': data_data
                        })
                    # ble_rsp_system_endpoint_set_watermarks
                    elif packet_command == 14:
                        self._logger.info(
                            "received packet ble_rsp_system_endpoint_set_"
                            "watermarks")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_system_endpoint_set_watermarks({
                            'result': result
                        })
                elif packet_class == 1:
                    if packet_command == 0:  # ble_rsp_flash_ps_defrag
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_defrag")
                        self.ble_rsp_flash_ps_defrag({})
                    elif packet_command == 1:  # ble_rsp_flash_ps_dump
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_dump")
                        self.ble_rsp_flash_ps_dump({})
                    elif packet_command == 2:  # ble_rsp_flash_ps_erase_all
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_erase_all")
                        self.ble_rsp_flash_ps_erase_all({})
                    elif packet_command == 3:  # ble_rsp_flash_ps_save
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_save")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_flash_ps_save({
                            'result': result
                        })
                    elif packet_command == 4:  # ble_rsp_flash_ps_load
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_load")
                        result, value_len = unpack('<HB',
                                                   self.bgapi_rx_payload[:3])
                        value_data = [ord(b) for b in self.bgapi_rx_payload[3:]]
                        self.ble_rsp_flash_ps_load({
                            'result': result, 'value': value_data
                        })
                    elif packet_command == 5:  # ble_rsp_flash_ps_erase
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_erase")
                        self.ble_rsp_flash_ps_erase({})
                    elif packet_command == 6:  # ble_rsp_flash_ps_erase_page
                        self._logger.info(
                            "received packet ble_rsp_flash_ps_erase_page")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_flash_erase_page({
                            'result': result
                        })
                    elif packet_command == 7:  # ble_rsp_flash_write_words
                        self._logger.info(
                            "received packet ble_rsp_flash_write_words")
                        self.ble_rsp_flash_write_words({})
                elif packet_class == 2:
                    if packet_command == 0:  # ble_rsp_attributes_write
                        self._logger.info(
                            "received packet ble_rsp_attributes_write")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_attributes_write({
                            'result': result
                        })
                    elif packet_command == 1:  # ble_rsp_attributes_read
                        self._logger.info(
                            "received packet ble_rsp_attributes_read")
                        handle, offset, result, value_len = unpack(
                            '<HHHB', self.bgapi_rx_payload[:7]
                        )
                        value_data = [ord(b) for b in self.bgapi_rx_payload[7:]]
                        self.ble_rsp_attributes_read({
                            'handle': handle, 'offset': offset,
                            'result': result, 'value': value_data
                        })
                    elif packet_command == 2:  # ble_rsp_attributes_read_type
                        self._logger.info(
                            "received packet ble_rsp_attributes_read_type")
                        handle, result, value_len = unpack(
                            '<HHB', self.bgapi_rx_payload[:5]
                        )
                        value_data = [ord(b) for b in self.bgapi_rx_payload[5:]]
                        self.ble_rsp_attributes_read_type({
                            'handle': handle, 'result': result,
                            'value': value_data
                        })
                    # ble_rsp_attributes_user_read_response
                    elif packet_command == 3:
                        self._logger.info(
                            "received packet ble_rsp_attributes_user_read_"
                            "response")
                        self.ble_rsp_attributes_user_read_response({})
                    # ble_rsp_attributes_user_write_response
                    elif packet_command == 4:
                        self._logger.info(
                            "received packet ble_rsp_attributes_user_write_"
                            "response")
                        self.ble_rsp_attributes_user_write_response({})
                elif packet_class == 3:
                    if packet_command == 0:  # ble_rsp_connection_disconnect
                        self._logger.info(
                            "received packet ble_rsp_connection_disconnect")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_connection_disconnect({
                            'connection': connection, 'result': result
                        })
                    elif packet_command == 1:  # ble_rsp_connection_get_rssi
                        self._logger.info(
                            "received packet ble_rsp_connection_get_rssi")
                        connection, rssi = unpack(
                            '<Bb', self.bgapi_rx_payload[:2]
                        )
                        self.ble_rsp_connection_get_rssi({
                            'connection': connection, 'rssi': rssi
                        })
                    elif packet_command == 2:  # ble_rsp_connection_update
                        self._logger.info(
                            "received packet ble_rsp_connection_update")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_connection_update({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_connection_version_update
                    elif packet_command == 3:
                        self._logger.info(
                            "received packet ble_rsp_connection_version_update")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_connection_version_update({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_connection_channel_map_get
                    elif packet_command == 4:
                        self._logger.info(
                            "received packet ble_rsp_connection_channel_map_"
                            "get")
                        connection, map_len = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        map_data = [ord(b) for b in self.bgapi_rx_payload[2:]]
                        self.ble_rsp_connection_channel_map_get({
                            'connection': connection, 'map': map_data
                        })
                    # ble_rsp_connection_channel_map_set
                    elif packet_command == 5:
                        self._logger.info(
                            "received packet ble_rsp_connection_channel_map_"
                            "set")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_connection_channel_map_set({
                            'connection': connection, 'result': result
                        })
                    elif packet_command == 6:  # ble_rsp_connection_features_get
                        self._logger.info(
                            "received packet ble_rsp_connection_features_get")
                        connection, result = unpack('<BH',
                                                    self.bgapi_rx_payload[:3])
                        self.ble_rsp_connection_features_get({
                            'connection': connection, 'result': result
                        })
                    elif packet_command == 7:  # ble_rsp_connection_get_status
                        self._logger.info(
                            "received packet ble_rsp_connection_get_status")
                        connection = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_rsp_connection_get_status({
                            'connection': connection
                        })
                    elif packet_command == 8:  # ble_rsp_connection_raw_tx
                        self._logger.info(
                            "received packet ble_rsp_connection_raw_tx")
                        connection = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_rsp_connection_raw_tx({
                            'connection': connection
                        })
                elif packet_class == 4:
                    # ble_rsp_attclient_find_by_type_value
                    if packet_command == 0:
                        self._logger.info(
                            "received packet ble_rsp_attclient_find_by_type_"
                            "value")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_find_by_type_value({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_read_by_group_type
                    elif packet_command == 1:
                        self._logger.info(
                            "received packet ble_rsp_attclient_read_by_group_"
                            "type")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_read_by_group_type({
                            'connection': connection, 'result': result
                        })
                    elif packet_command == 2:  # ble_rsp_attclient_read_by_type
                        self._logger.info(
                            "received packet ble_rsp_attclient_read_by_type")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_read_by_type({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_find_information
                    elif packet_command == 3:
                        self._logger.info(
                            "received packet ble_rsp_attclient_find_"
                            "information")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_find_information({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_read_by_handle
                    elif packet_command == 4:
                        self._logger.info(
                            "received packet ble_rsp_attclient_read_by_handle")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_read_by_handle({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_attribute_write
                    elif packet_command == 5:
                        self._logger.info(
                            "received packet ble_rsp_attclient_")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_attribute_write({
                            'connection': connection, 'result': result
                        })
                    elif packet_command == 6:  # ble_rsp_attclient_write_command
                        self._logger.info(
                            "received packet ble_rsp_attclient_write_command")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_write_command({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_indicate_confirm
                    elif packet_command == 7:
                        self._logger.info(
                            "received packet ble_rsp_attclient_indicate_"
                            "confirm")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_attclient_indicate_confirm({
                            'result': result
                        })
                    elif packet_command == 8:  # ble_rsp_attclient_read_long
                        self._logger.info(
                            "received packet ble_rsp_attclient_read_long")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_read_long({
                            'connection': connection, 'result': result
                        })
                    elif packet_command == 9:  # ble_rsp_attclient_prepare_write
                        self._logger.info(
                            "received packet ble_rsp_attclient_prepare_write")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_prepare_write({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_execute_write
                    elif packet_command == 10:
                        self._logger.info(
                            "received packet ble_rsp_attclient_execute_write")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_execute_write({
                            'connection': connection, 'result': result
                        })
                    # ble_rsp_attclient_read_multiple
                    elif packet_command == 11:
                        self._logger.info(
                            "received packet ble_rsp_attclient_read_multiple")
                        connection, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_attclient_read_multiple({
                            'connection': connection, 'result': result
                        })
                elif packet_class == 5:
                    if packet_command == 0:  # ble_rsp_sm_encrypt_start
                        self._logger.info(
                            "received packet ble_rsp_sm_encrypt_start")
                        handle, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_sm_encrypt_start({
                            'handle': handle, 'result': result
                        })
                    elif packet_command == 1:  # ble_rsp_sm_set_bondable_mode
                        self._logger.info(
                            "received packet ble_rsp_sm_set_bondable_mode")
                        self.ble_rsp_sm_set_bondable_mode({})
                    elif packet_command == 2:  # ble_rsp_sm_delete_bonding
                        self._logger.info(
                            "received packet ble_rsp_sm_delete_bonding")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_sm_delete_bonding({
                            'result': result
                        })
                    elif packet_command == 3:  # ble_rsp_sm_set_parameters
                        self._logger.info(
                            "received packet ble_rsp_sm_set_parameters")
                        self.ble_rsp_sm_set_parameters({})
                    elif packet_command == 4:  # ble_rsp_sm_passkey_entry
                        self._logger.info(
                            "received packet ble_rsp_sm_passkey_entry")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_sm_passkey_entry({
                            'result': result
                        })
                    elif packet_command == 5:  # ble_rsp_sm_get_bonds
                        self._logger.info(
                            "received packet ble_rsp_sm_get_bonds")
                        bonds = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_rsp_sm_get_bonds({
                            'bonds': bonds
                        })
                    elif packet_command == 6:  # ble_rsp_sm_set_oob_data
                        self._logger.info(
                            "received packet ble_rsp_sm_set_oob_data")
                        self.ble_rsp_sm_set_oob_data({})
                elif packet_class == 6:
                    if packet_command == 0:  # ble_rsp_gap_set_privacy_flags
                        self._logger.info(
                            "received packet ble_rsp_gap_set_privacy_flags")
                        self.ble_rsp_gap_set_privacy_flags({})
                    elif packet_command == 1:  # ble_rsp_gap_set_mode
                        self._logger.info(
                            "received packet ble_rsp_gap_set_mode")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_set_mode({
                            'result': result
                        })
                    elif packet_command == 2:  # ble_rsp_gap_discover
                        self._logger.info(
                            "received packet ble_rsp_gap_discover")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_discover({
                            'result': result
                        })
                    elif packet_command == 3:  # ble_rsp_gap_connect_direct
                        self._logger.info(
                            "received packet ble_rsp_gap_connect_direct")
                        result, connection_handle = unpack(
                            '<HB', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_gap_connect_direct({
                            'result': result,
                            'connection_handle': connection_handle
                        })
                    elif packet_command == 4:  # ble_rsp_gap_end_procedure
                        self._logger.info(
                            "received packet ble_rsp_gap_end_procedure")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_end_procedure({
                            'result': result
                        })
                    elif packet_command == 5:  # ble_rsp_gap_connect_selective
                        self._logger.info(
                            "received packet ble_rsp_gap_connect_selective")
                        result, connection_handle = unpack(
                            '<HB', self.bgapi_rx_payload[:3]
                        )
                        self.ble_rsp_gap_connect_selective({
                            'result': result,
                            'connection_handle': connection_handle
                        })
                    elif packet_command == 6:  # ble_rsp_gap_set_filtering
                        self._logger.info(
                            "received packet ble_rsp_gap_set_filtering")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_set_filtering({
                            'result': result
                        })
                    elif packet_command == 7:  # ble_rsp_gap_set_scan_parameters
                        self._logger.info(
                            "received packet ble_rsp_gap_set_scan_parameters")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_set_scan_parameters({
                            'result': result
                        })
                    elif packet_command == 8:  # ble_rsp_gap_set_adv_parameters
                        self._logger.info(
                            "received packet ble_rsp_gap_set_adv_parameters")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_set_adv_parameters({
                            'result': result
                        })
                    elif packet_command == 9:  # ble_rsp_gap_set_adv_data
                        self._logger.info(
                            "received packet ble_rsp_gap_set_adv_data")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_set_adv_data({
                            'result': result
                        })
                    # ble_rsp_gap_set_directed_connectable_mode
                    elif packet_command == 10:
                        self._logger.info(
                            "received packet ble_rsp_gap_set_directed_"
                            "connectable_mode")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_gap_set_directed_connectable_mode({
                            'result': result
                        })
                elif packet_class == 7:
                    # ble_rsp_hardware_io_port_config_irq
                    if packet_command == 0:
                        self._logger.info(
                            "received packet ble_rsp_hardware_io_port_config_"
                            "irq")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_io_port_config_irq({
                            'result': result
                        })
                    elif packet_command == 1:  # ble_rsp_hardware_set_soft_timer
                        self._logger.info(
                            "received packet ble_rsp_hardware_set_soft_timer")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_set_soft_timer({
                            'result': result
                        })
                    elif packet_command == 2:  # ble_rsp_hardware_adc_read
                        self._logger.info(
                            "received packet ble_rsp_hardware_adc_read")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_adc_read({
                            'result': result
                        })
                    # ble_rsp_hardware_io_port_config_direction
                    elif packet_command == 3:
                        self._logger.info(
                            "received packet ble_rsp_hardware_io_port_config_"
                            "direction")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_io_port_config_direction({
                            'result': result
                        })
                    # ble_rsp_hardware_io_port_config_function
                    elif packet_command == 4:
                        self._logger.info(
                            "received packet ble_rsp_hardware_io_port_config_"
                            "function")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_io_port_config_function({
                            'result': result
                        })
                    # ble_rsp_hardware_io_port_config_pull
                    elif packet_command == 5:
                        self._logger.info(
                            "received packet ble_rsp_hardware_io_port_config_"
                            "pull")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_io_port_config_pull({
                            'result': result
                        })
                    elif packet_command == 6:  # ble_rsp_hardware_io_port_write
                        self._logger.info(
                            "received packet ble_rsp_hardware_io_port_write")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_io_port_write({
                            'result': result
                        })
                    elif packet_command == 7:  # ble_rsp_hardware_io_port_read
                        self._logger.info(
                            "received packet ble_rsp_hardware_io_port_read")
                        result, port, data = unpack(
                            '<HBB', self.bgapi_rx_payload[:4]
                        )
                        self.ble_rsp_hardware_io_port_read({
                            'result': result, 'port': port, 'data': data
                        })
                    elif packet_command == 8:  # ble_rsp_hardware_spi_config
                        self._logger.info(
                            "received packet ble_rsp_hardware_spi_config")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_spi_config({
                            'result': result
                        })
                    elif packet_command == 9:  # ble_rsp_hardware_spi_transfer
                        self._logger.info(
                            "received packet ble_rsp_hardware_spi_transfer")
                        result, channel, data_len = unpack(
                            '<HBB', self.bgapi_rx_payload[:4]
                        )
                        data_data = [ord(b) for b in self.bgapi_rx_payload[4:]]
                        self.ble_rsp_hardware_spi_transfer({
                            'result': result, 'channel': channel,
                            'data': data_data
                        })
                    elif packet_command == 10:  # ble_rsp_hardware_i2c_read
                        self._logger.info(
                            "received packet ble_rsp_hardware_i2c_read")
                        result, data_len = unpack(
                            '<HB', self.bgapi_rx_payload[:3]
                        )
                        data_data = [ord(b) for b in self.bgapi_rx_payload[3:]]
                        self.ble_rsp_hardware_i2c_read({
                            'result': result, 'data': data_data
                        })
                    elif packet_command == 11:  # ble_rsp_hardware_i2c_write
                        self._logger.info(
                            "received packet ble_rsp_hardware_i2c_write")
                        written = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_rsp_hardware_i2c_write({
                            'written': written
                        })
                    elif packet_command == 12:  # ble_rsp_hardware_set_txpower
                        self._logger.info(
                            "received packet ble_rsp_hardware_set_txpower")
                        self.ble_rsp_hardware_set_txpower({})
                    # ble_rsp_hardware_timer_comparator
                    elif packet_command == 13:
                        self._logger.info(
                            "received packet ble_rsp_hardware_timer_comparator")
                        result = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_hardware_timer_comparator({
                            'result': result
                        })
                elif packet_class == 8:
                    if packet_command == 0:  # ble_rsp_test_phy_tx
                        self._logger.info(
                            "received packet ble_rsp_test_phy_tx")
                        self.ble_rsp_test_phy_tx({})
                    elif packet_command == 1:  # ble_rsp_test_phy_rx
                        self._logger.info(
                            "received packet ble_rsp_test_phy_rx")
                        self.ble_rsp_test_phy_rx({})
                    elif packet_command == 2:  # ble_rsp_test_phy_end
                        self._logger.info(
                            "received packet ble_rsp_test_phy_end")
                        counter = unpack('<H', self.bgapi_rx_payload[:2])[0]
                        self.ble_rsp_test_phy_end({
                            'counter': counter
                        })
                    elif packet_command == 3:  # ble_rsp_test_phy_reset
                        self._logger.info(
                            "received packet ble_rsp_test_phy_reset")
                        self.ble_rsp_test_phy_reset({})
                    elif packet_command == 4:  # ble_rsp_test_get_channel_map
                        self._logger.info(
                            "received packet ble_rsp_test_get_channel_map")
                        # channel_map_len = unpack(
                        #    '<B', self.bgapi_rx_payload[:1]
                        # )[0]
                        channel_map_data =\
                            [ord(b) for b in self.bgapi_rx_payload[1:]]
                        self.ble_rsp_test_get_channel_map({
                            'channel_map': channel_map_data
                        })
                    elif packet_command == 5:  # ble_rsp_test_debug
                        self._logger.info(
                            "received packet ble_rsp_test_debug")
                        # output_len = unpack('<B',
                        #                     self.bgapi_rx_payload[:1])[0]
                        output_data =\
                            [ord(b) for b in self.bgapi_rx_payload[1:]]
                        self.ble_rsp_test_debug({
                            'output': output_data
                        })
                self.busy = False
                self.on_idle()
            elif packet_type & 0x88 == 0x80:
                # 0x80 = BLE event packet
                if packet_class == 0:
                    if packet_command == 0:  # ble_evt_system_boot
                        self._logger.info(
                            "received packet ble_evt_system_boot")
                        data = unpack('<HHHHHBB', self.bgapi_rx_payload[:12])
                        self.ble_evt_system_boot({
                            'major': data[0], 'minor': data[1],
                            'patch': data[2], 'build': data[3],
                            'll_version': data[4], 'protocol_version': data[5],
                            'hw': data[6]
                        })
                        self.busy = False
                        self.on_idle()
                    elif packet_command == 1:  # ble_evt_system_debug
                        self._logger.info(
                            "received packet ble_evt_system_debug")
                        data_len = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        data_data = [ord(b) for b in self.bgapi_rx_payload[1:]]
                        self.ble_evt_system_debug({
                            'data': data_data
                        })
                    # ble_evt_system_endpoint_watermark_rx
                    elif packet_command == 2:
                        self._logger.info(
                            "received packet ble_evt_system_endpoint_"
                            "watermark_rx")
                        endpoint, data = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        self.ble_evt_system_endpoint_watermark_rx({
                            'endpoint': endpoint, 'data': data
                        })
                    # ble_evt_system_endpoint_watermark_tx
                    elif packet_command == 3:
                        self._logger.info(
                            "received packet ble_evt_system_endpoint_"
                            "watermark_tx")
                        endpoint, data = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        self.ble_evt_system_endpoint_watermark_tx({
                            'endpoint': endpoint, 'data': data
                        })
                    elif packet_command == 4:  # ble_evt_system_script_failure
                        self._logger.info(
                            "received packet ble_evt_system_script_failure")
                        address, reason = unpack(
                            '<HH', self.bgapi_rx_payload[:4]
                        )
                        self.ble_evt_system_script_failure({
                            'address': address, 'reason': reason
                        })
                    elif packet_command == 5:  # ble_evt_system_no_license_key
                        self._logger.info(
                            "received packet ble_evt_system_no_license_key")
                        self.ble_evt_system_no_license_key({})
                elif packet_class == 1:
                    if packet_command == 0:  # ble_evt_flash_ps_key
                        self._logger.info(
                            "received packet ble_evt_flash_ps_key")
                        key, value_len = unpack(
                            '<HB', self.bgapi_rx_payload[:3]
                        )
                        value_data = [ord(b) for b in self.bgapi_rx_payload[3:]]
                        self.ble_evt_flash_ps_key({
                            'key': key, 'value': value_data
                        })
                elif packet_class == 2:
                    if packet_command == 0:  # ble_evt_attributes_value
                        self._logger.info(
                            "received packet ble_evt_attributes_value")
                        connection, reason, handle, offset, value_len = unpack(
                            '<BBHHB', self.bgapi_rx_payload[:7]
                        )
                        value_data = [ord(b) for b in self.bgapi_rx_payload[7:]]
                        self.ble_evt_attributes_value({
                            'connection': connection, 'reason': reason,
                            'handle': handle, 'offset': offset,
                            'value': value_data
                        })
                    # ble_evt_attributes_user_read_request
                    elif packet_command == 1:
                        self._logger.info(
                            "received packet ble_evt_attributes_user_read_"
                            "request")
                        connection, handle, offset, maxsize = unpack(
                            '<BHHB', self.bgapi_rx_payload[:6]
                        )
                        self.ble_evt_attributes_user_read_request({
                            'connection': connection, 'handle': handle,
                            'offset': offset, 'maxsize': maxsize
                        })
                    elif packet_command == 2:  # ble_evt_attributes_status
                        self._logger.info(
                            "received packet ble_evt_attributes_status")
                        handle, flags = unpack('<HB', self.bgapi_rx_payload[:3])
                        self.ble_evt_attributes_status({
                            'handle': handle, 'flags': flags
                        })
                elif packet_class == 3:
                    if packet_command == 0:  # ble_evt_connection_status
                        self._logger.info(
                            "received packet ble_evt_connection_status")
                        data = unpack('<BB6sBHHHB', self.bgapi_rx_payload[:16])
                        address = [ord(b) for b in data[2]]
                        self.ble_evt_connection_status({
                            'connection': data[0], 'flags': data[1],
                            'address': address, 'address_type': data[3],
                            'conn_interval': data[4], 'timeout': data[5],
                            'latency': data[6], 'bonding': data[7]
                        })
                    elif packet_command == 1:  # ble_evt_connection_version_ind
                        self._logger.info(
                            "received packet ble_evt_connection_version_ind")
                        connection, vers_nr, comp_id, sub_vers_nr = unpack(
                            '<BBHH', self.bgapi_rx_payload[:6]
                        )
                        self.ble_evt_connection_version_ind({
                            'connection': connection, 'vers_nr': vers_nr,
                            'comp_id': comp_id, 'sub_vers_nr': sub_vers_nr
                        })
                    elif packet_command == 2:  # ble_evt_connection_feature_ind
                        self._logger.info(
                            "received packet ble_evt_connection_feature_ind")
                        connection, features_len = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        features_data =\
                            [ord(b) for b in self.bgapi_rx_payload[2:]]
                        self.ble_evt_connection_feature_ind({
                            'connection': connection, 'features': features_data
                        })
                    elif packet_command == 3:  # ble_evt_connection_raw_rx
                        self._logger.info(
                            "received packet ble_evt_connection_raw_rx")
                        connection, data_len = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        data_data = [ord(b) for b in self.bgapi_rx_payload[2:]]
                        self.ble_evt_connection_raw_rx({
                            'connection': connection, 'data': data_data
                        })
                    elif packet_command == 4:  # ble_evt_connection_disconnected
                        self._logger.info(
                            "received packet ble_evt_connection_disconnected")
                        connection, reason = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_evt_connection_disconnected({
                            'connection': connection, 'reason': reason
                        })
                elif packet_class == 4:
                    if packet_command == 0:  # ble_evt_attclient_indicated
                        self._logger.info(
                            "received packet ble_evt_attclient_indicated")
                        connection, attrhandle = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_evt_attclient_indicated({
                            'connection': connection, 'attrhandle': attrhandle
                        })
                    # ble_evt_attclient_procedure_completed
                    elif packet_command == 1:
                        self._logger.info(
                            "received packet ble_evt_attclient_procedure_"
                            "completed")
                        connection, result, chrhandle = unpack(
                            '<BHH', self.bgapi_rx_payload[:5]
                        )
                        self.ble_evt_attclient_procedure_completed({
                            'connection': connection, 'result': result,
                            'chrhandle': chrhandle
                        })
                    elif packet_command == 2:  # ble_evt_attclient_group_found
                        self._logger.info(
                            "received packet ble_evt_attclient_group_found")
                        connection, start, end, uuid_len = unpack(
                            '<BHHB', self.bgapi_rx_payload[:6]
                        )
                        uuid_data = [ord(b) for b in self.bgapi_rx_payload[6:]]
                        self.ble_evt_attclient_group_found({
                            'connection': connection, 'start': start,
                            'end': end, 'uuid': uuid_data
                        })
                    # ble_evt_attclient_attribute_found
                    elif packet_command == 3:
                        self._logger.info(
                            "received packet ble_evt_attclient_attribute_found")
                        data = unpack('<BHHBB', self.bgapi_rx_payload[:7])
                        uuid_data = [ord(b) for b in self.bgapi_rx_payload[7:]]
                        self.ble_evt_attclient_attribute_found({
                            'connection': data[0], 'chrdecl': data[1],
                            'value': data[2], 'properties': data[3],
                            'uuid': uuid_data
                        })
                    # ble_evt_attclient_find_information_found
                    elif packet_command == 4:
                        self._logger.info(
                            "received packet ble_evt_attclient_find_"
                            "information_found")
                        connection, chrhandle, uuid_len = unpack(
                            '<BHB', self.bgapi_rx_payload[:4]
                        )
                        uuid_data = [ord(b) for b in self.bgapi_rx_payload[4:]]
                        self.ble_evt_attclient_find_information_found({
                            'connection': connection, 'chrhandle': chrhandle,
                            'uuid': uuid_data
                        })
                    # ble_evt_attclient_attribute_value
                    elif packet_command == 5:
                        self._logger.info(
                            "received packet ble_evt_attclient_attribute_value")
                        connection, atthandle, type, value_len = unpack(
                            '<BHBB', self.bgapi_rx_payload[:5]
                        )
                        value_data = [ord(b) for b in self.bgapi_rx_payload[5:]]
                        self.ble_evt_attclient_attribute_value({
                            'connection': connection, 'atthandle': atthandle,
                            'type': type, 'value': value_data
                        })
                    # ble_evt_attclient_read_multiple_response
                    elif packet_command == 6:
                        self._logger.info(
                            "received packet ble_evt_attclient_read_multiple_"
                            "response")
                        connection, handles_len = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        handles_data =\
                            [ord(b) for b in self.bgapi_rx_payload[2:]]
                        self.ble_evt_attclient_read_multiple_response({
                            'connection': connection, 'handles': handles_data
                        })
                elif packet_class == 5:
                    if packet_command == 0:  # ble_evt_sm_smp_data
                        self._logger.info(
                            "received packet ble_evt_sm_smp_data")
                        handle, packet, data_len = unpack(
                            '<BBB', self.bgapi_rx_payload[:3]
                        )
                        data_data = [ord(b) for b in self.bgapi_rx_payload[3:]]
                        self.ble_evt_sm_smp_data({
                            'handle': handle, 'packet': packet,
                            'data': data_data
                        })
                    elif packet_command == 1:  # ble_evt_sm_bonding_fail
                        self._logger.info(
                            "received packet ble_evt_sm_bonding_fail")
                        handle, result = unpack(
                            '<BH', self.bgapi_rx_payload[:3]
                        )
                        self.ble_evt_sm_bonding_fail({
                            'handle': handle, 'result': result
                        })
                    elif packet_command == 2:  # ble_evt_sm_passkey_display
                        self._logger.info(
                            "received packet ble_evt_sm_passkey_display")
                        handle, passkey = unpack(
                            '<BI', self.bgapi_rx_payload[:5]
                        )
                        self.ble_evt_sm_passkey_display({
                            'handle': handle, 'passkey': passkey
                        })
                    elif packet_command == 3:  # ble_evt_sm_passkey_request
                        self._logger.info(
                            "received packet ble_evt_sm_passkey_request")
                        handle = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_evt_sm_passkey_request({
                            'handle': handle
                        })
                    elif packet_command == 4:  # ble_evt_sm_bond_status
                        self._logger.info(
                            "received packet ble_evt_sm_bond_status")
                        bond, keysize, mitm, keys = unpack(
                            '<BBBB', self.bgapi_rx_payload[:4]
                        )
                        self.ble_evt_sm_bond_status({
                            'bond': bond, 'keysize': keysize, 'mitm': mitm,
                            'keys': keys
                        })
                elif packet_class == 6:
                    if packet_command == 0:  # ble_evt_gap_scan_response
                        self._logger.info(
                            "received packet ble_evt_gap_scan_response")
                        data = unpack('<bB6sBBB', self.bgapi_rx_payload[:11])
                        sender = [ord(b) for b in data[2]]
                        data_data = [ord(b) for b in self.bgapi_rx_payload[11:]]
                        self.ble_evt_gap_scan_response({
                            'rssi': data[0], 'packet_type': data[1],
                            'sender': sender, 'address_type': data[3],
                            'bond': data[4], 'data': data_data
                        })
                    elif packet_command == 1:  # ble_evt_gap_mode_changed
                        self._logger.info(
                            "received packet ble_evt_gap_mode_changed")
                        discover, connect = unpack(
                            '<BB', self.bgapi_rx_payload[:2]
                        )
                        self.ble_evt_gap_mode_changed({
                            'discover': discover, 'connect': connect
                        })
                elif packet_class == 7:
                    if packet_command == 0:  # ble_evt_hardware_io_port_status
                        self._logger.info(
                            "received packet ble_evt_hardware_io_port_status")
                        timestamp, port, irq, state = unpack(
                            '<IBBB', self.bgapi_rx_payload[:7]
                        )
                        self.ble_evt_hardware_io_port_status({
                            'timestamp': timestamp, 'port': port, 'irq': irq,
                            'state': state
                        })
                    elif packet_command == 1:  # ble_evt_hardware_soft_timer
                        self._logger.info(
                            "received packet ble_evt_hardware_io_soft_timer")
                        handle = unpack('<B', self.bgapi_rx_payload[:1])[0]
                        self.ble_evt_hardware_soft_timer({
                            'handle': handle
                        })
                    elif packet_command == 2:  # ble_evt_hardware_adc_result
                        self._logger.info(
                            "received packet ble_evt_hardware_adc_result")
                        input, value = unpack('<Bh', self.bgapi_rx_payload[:3])
                        self.ble_evt_hardware_adc_result({
                            'input': input, 'value': value
                        })
