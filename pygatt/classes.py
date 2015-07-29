#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pygatt Class Definitions"""

__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs, Inc.'


import logging
import logging.handlers
import re
import string
import time
import thread
import threading

from collections import defaultdict

import pexpect

import pygatt.constants
import pygatt.exceptions
import pygatt.util


class BluetoothLEDevice(object):

    """BluetoothLEDevice Object."""

    logger = logging.getLogger(__name__)
    logger.setLevel(pygatt.constants.LOG_LEVEL)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(pygatt.constants.LOG_LEVEL)
    formatter = logging.Formatter(pygatt.constants.LOG_FORMAT)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.propagate = False

    def __init__(self, mac_address, hci_device='hci0', app_options=''):
        self.handles = {}
        self.subscribed_handlers = {}

        self.running = True

        self.lock = threading.Lock()

        self.connection_lock = threading.RLock()

        gatttool_cmd = ' '.join(filter(None, [
            'gatttool',
            app_options,
            '-b',
            mac_address,
            '-i',
            hci_device,
            '-I'
        ]))

        self.logger.debug('gatttool_cmd=%s', gatttool_cmd)
        self.con = pexpect.spawn(gatttool_cmd)

        self.con.expect(r'\[LE\]>', timeout=1)

        self.callbacks = defaultdict(set)

        self.thread = thread.start_new_thread(self.run, ())

    def __del__(self):
        if self.running:
            self.stop()
            self.thread.join()

        if self.con.isalive():
            self.con.sendline('exit')
            while 1:
                if not self.con.isalive():
                    break
                time.sleep(0.1)

    def bond(self):
        """Securely Bonds to the BLE device."""
        self.logger.info('Bonding.')
        self.con.sendline('sec-level medium')

    def connect(self, timeout=pygatt.constants.DEFAULT_CONNECT_TIMEOUT_S):
        """Connect to the device."""
        self.logger.info('Connecting with timeout=%s', timeout)
        try:
            with self.connection_lock:
                self.con.sendline('connect')
                self.con.expect(r'Connection successful.*\[LE\]>', timeout)
        except pexpect.TIMEOUT:
            raise pygatt.exceptions.BluetoothLEError(
                "Timed-out connecting to device after %s seconds." % timeout)

    def disconnect(self):
        """Send gatttool disconnect command"""
        self.logger.info('Disconnecting...')
        self.con.sendline('disconnect')

    def get_handle(self, uuid):
        """
        Look up and return the handle for an attribute by its UUID.

        :param uuid: The UUID of the characteristic.
        :type uuid: str
        :return: None if the UUID was not found.
        """
        if uuid not in self.handles:
            with self.connection_lock:
                self.con.sendline('characteristics')
                try:
                    self.con.expect(uuid, timeout=5)
                except pexpect.TIMEOUT:
                    raise pygatt.exceptions.BluetoothLEError(self.con.before)
                else:
                    # FIXME The last line of the output will be the one
                    #       matching our uuid (because it was the filter
                    #       for the call to 'expect' above. Take that and
                    #       pull out the leftmost handle value.
                    #       ...just split on ':'!
                    matching_line = self.con.before.splitlines(True)[-1]

                    self.handles[uuid] = int(
                        re.search(
                            "handle: 0x([a-fA-F0-9]{4})",
                            matching_line
                        ).group(1),
                        16
                    )
        return self.handles.get(uuid)

    def _expect(self, expected, timeout=pygatt.constants.DEFAULT_TIMEOUT_S):
        """We may (and often do) get an indication/notification before a
        write completes, and so it can be lost if we "expect()"'d something
        that came after it in the output, e.g.:

        > char-write-req 0x1 0x2
        Notification handle: xxx
        Write completed successfully.
        >

        Anytime we expect something we have to expect noti/indication first for
        a short time.
        """
        with self.connection_lock:
            patterns = [
                expected,
                'Notification handle = .*? \r',
                'Indication   handle = .*? \r',
            ]
            while 1:
                try:
                    matched_pattern_index = self.con.expect(patterns, timeout)
                    if matched_pattern_index == 0:
                        break
                    elif (matched_pattern_index == 1 or
                          matched_pattern_index == 2):
                        self._handle_notification(self.con.after)
                except pexpect.TIMEOUT:
                    raise pygatt.exceptions.BluetoothLEError(self.con.before)

    def char_write(self, handle, value, wait_for_response=False):
        """
        Writes a value to a given characteristic handle.

        :param handle:
        :param value:
        :param wait_for_response:
        """
        with self.connection_lock:
            hexstring = ''.join('%02x' % byte for byte in value)

            if wait_for_response:
                cmd = 'req'
            else:
                cmd = 'cmd'

            cmd = 'char-write-%s 0x%02x %s' % (cmd, handle, hexstring)

            self.logger.debug('Sending cmd=%s', cmd)
            self.con.sendline(cmd)

            if wait_for_response:
                self._expect('Characteristic value was written successfully')

            self.logger.debug('Sent cmd=%s', cmd)

    def char_read_uuid(self, uuid, timeout=pygatt.constants.DEFAULT_TIMEOUT_S):
        """
        Reads a Characteristic by UUID.

        :param uuid: UUID of Characteristic to read.
        :type uuid: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        with self.connection_lock:
            self.con.sendline('char-read-uuid %s' % uuid)
            self._expect('value: .*? \r', timeout)

            rval = self.con.after.split()[1:]

            return bytearray([int(x, 16) for x in rval])

    def char_read_hnd(self, handle,
                      timeout=pygatt.constants.DEFAULT_TIMEOUT_S):
        """
        Reads a Characteristic by Handle.

        :param handle: Handle of Characteristic to read.
        :type handle: str
        :return:
        :rtype:
        """
        with self.connection_lock:
            self.con.sendline('char-read-hnd 0x%02x' % handle)
            self._expect('descriptor: .*?\r', timeout)

            rval = self.con.after.split()[1:]

            return [int(n, 16) for n in rval]

    def subscribe(self, uuid, callback=None, indication=False):
        """
        Enables subscription to a Characteristic with ability to call callback.

        :param uuid:
        :param callback:
        :param indication:
        :return:
        :rtype:
        """
        self.logger.info(
            'Subscribing to uuid=%s with callback=%s and indication=%s',
            uuid, callback, indication)
        definition_handle = self.get_handle(uuid)
        # Expect notifications on the value handle...
        value_handle = definition_handle + 1
        # but write to the characteristic config to enable notifications
        characteristic_config_handle = value_handle + 1

        if indication:
            properties = bytearray([0x02, 0x00])
        else:
            properties = bytearray([0x01, 0x00])

        self.logger.debug(locals())
        try:
            self.lock.acquire()

            if callback is not None:
                self.callbacks[value_handle].add(callback)

            if self.subscribed_handlers.get(value_handle, None) != properties:
                self.char_write(
                    characteristic_config_handle,
                    properties,
                    wait_for_response=False
                )
                self.subscribed_handlers[value_handle] = properties
        finally:
            self.lock.release()

    def _handle_notification(self, msg):
        """
        Handles notification?
        """
        self.logger.debug('Handling notification msg=%s', msg)
        handle, _, value = string.split(msg.strip(), maxsplit=5)[3:]
        handle = int(handle, 16)
        value = bytearray.fromhex(value)

        try:
            self.lock.acquire()

            if handle in self.callbacks:
                for callback in self.callbacks[handle]:
                    callback(handle, value)
        finally:
            self.lock.release()

    def stop(self):
        """Stops?"""
        self.logger.info('Stopping')
        self.running = False

    def run(self):
        """Runs...?"""
        self.logger.info('Running...')
        while self.running:
            with self.connection_lock:
                try:
                    self._expect("fooooooo", timeout=.1)
                except pygatt.exceptions.BluetoothLEError:
                    pass
            # TODO need some delay to avoid aggresively grabbing the lock,
            # blocking out the others. worst case is 1 second delay for async
            # not received as a part of another request
            time.sleep(.001)
