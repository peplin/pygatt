#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pygatt Class Definitions"""

__author__ = 'Greg Albrecht <gba@orionlabs.co>'
__license__ = 'Apache License, Version 2.0'
__copyright__ = 'Copyright 2015 Orion Labs'


import logging
import logging.handlers
import string
import time
import threading

from collections import defaultdict

import pexpect

import pygatt.constants
import pygatt.exceptions
import pygatt.util


class BluetoothLEDevice(object):
    logger = logging.getLogger('pygatt')
    logger.setLevel(pygatt.constants.LOG_LEVEL)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(pygatt.constants.LOG_LEVEL)
    formatter = logging.Formatter(pygatt.constants.LOG_FORMAT)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    GATTTOOL_PROMPT = r".*> "

    def __init__(self, mac_address, hci_device='hci0', logfile=None):
        self.handles = {}
        self.subscribed_handlers = {}
        self.address = mac_address

        self.running = True

        self.lock = threading.Lock()

        self.connection_lock = threading.RLock()

        gatttool_cmd = ' '.join([
            'gatttool',
            '-b',
            self.address,
            '-i',
            hci_device,
            '-I'
        ])

        self.logger.debug('gatttool_cmd=%s', gatttool_cmd)
        self.con = pexpect.spawn(gatttool_cmd, logfile=logfile)

        self.con.expect(r'\[LE\]>', timeout=1)

        self.callbacks = defaultdict(set)

        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

    def bond(self):
        """Securely Bonds to the BLE device."""
        self.logger.info('Bonding')
        self.con.sendline('sec-level medium')
        self.con.expect(self.GATTTOOL_PROMPT, timeout=1)

    def connect(self, timeout=pygatt.constants.DEFAULT_CONNECT_TIMEOUT_S):
        """Connect to the device."""
        self.logger.info('Connecting with timeout=%s', timeout)
        try:
            with self.connection_lock:
                self.con.sendline('connect')
                self.con.expect(r'Connection successful.*\[LE\]>', timeout)
        except pexpect.TIMEOUT:
            message = ("Timed out connecting to %s after %s seconds."
                       % (self.address, timeout))
            self.logger.error(message)
            raise pygatt.exceptions.NotConnectedError(message)

    def get_handle(self, uuid):
        """
        Look up and return the handle for an attribute by its UUID.

        :param uuid: The UUID of the characteristic.
        :type uuid: str
        :return: None if the UUID was not found.
        """
        if uuid not in self.handles:
            self.logger.debug("Looking up handle for characteristic %s", uuid)
            with self.connection_lock:
                self.con.sendline('characteristics')

                timeout = 2
                while True:
                    try:
                        self.con.expect(
                            r"handle: 0x([a-fA-F0-9]{4}), "
                            "char properties: 0x[a-fA-F0-9]{2}, "
                            "char value handle: 0x[a-fA-F0-9]{4}, "
                            "uuid: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\r\n",  # noqa
                            timeout=timeout)
                    except pexpect.TIMEOUT:
                        break
                    except pexpect.EOF:
                        break
                    else:
                        try:
                            handle = int(self.con.match.group(1), 16)
                            char_uuid = self.con.match.group(2).strip()
                            self.handles[char_uuid] = handle
                            self.logger.debug(
                                "Found characteristic %s, handle: %d",
                                char_uuid,
                                handle)

                            # The characteristics all print at once, so after
                            # waiting 1-2 seconds for them to all fetch, you can
                            # load the rest without much delay at all.
                            timeout = .01
                        except AttributeError:
                            pass

        if len(self.handles) == 0:
            raise pygatt.exceptions.BluetoothLEError(
                "No characteristics found - disconnected unexpectedly?")

        handle = self.handles.get(uuid)
        if handle is None:
            message = "No characteristic found matching %s" % uuid
            self.logger.warn(message)
            raise pygatt.exceptions.BluetoothLEError(message)

        self.logger.debug(
            "Characteristic %s, handle: %d", uuid, handle)
        return handle

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
                '.*Invalid file descriptor.*',
                '.*Disconnected\r',
            ]
            while True:
                try:
                    matched_pattern_index = self.con.expect(patterns, timeout)
                    if matched_pattern_index == 0:
                        break
                    elif matched_pattern_index in [1, 2]:
                        self._handle_notification(self.con.after)
                    elif matched_pattern_index in [3, 4]:
                        message = ""
                        if self.running:
                            message = ("Unexpectedly disconnected - do you "
                                       "need to clear bonds?")
                            self.logger.error(message)
                            self.running = False
                        raise pygatt.exceptions.NotConnectedError(message)
                except pexpect.TIMEOUT:
                    raise pygatt.exceptions.NotificationTimeout(
                        "Timed out waiting for a notification")

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
                try:
                    self._expect('Characteristic value written successfully')
                except pygatt.exceptions.NoResponseError:
                    self.logger.error("No response received", exc_info=True)
                    raise

            self.logger.info('Sent cmd=%s', cmd)

    def char_read_uuid(self, uuid):
        """
        Reads a Characteristic by UUID.

        :param uuid: UUID of Characteristic to read.
        :type uuid: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        with self.connection_lock:
            self.con.sendline('char-read-uuid %s' % uuid)
            self._expect('value: .*? \r')

            rval = self.con.after.split()[1:]

            return bytearray([int(x, 16) for x in rval])

    def char_read_hnd(self, handle):
        """
        Reads a Characteristic by Handle.

        :param handle: Handle of Characteristic to read.
        :type handle: str
        :return:
        :rtype:
        """
        with self.connection_lock:
            self.con.sendline('char-read-hnd 0x%02x' % handle)
            self._expect('descriptor: .*?\r')

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
                self.logger.debug("Subscribed to uuid=%s", uuid)
                self.subscribed_handlers[value_handle] = properties
            else:
                self.logger.debug("Already subscribed to uuid=%s", uuid)
        finally:
            self.lock.release()

    def _handle_notification(self, msg):
        """
        Receive a notification from the connected device and propagate the value
        to all registered callbacks.
        """
        hex_handle, _, hex_value = string.split(msg.strip(), maxsplit=5)[3:]
        handle = int(hex_handle, 16)
        value = bytearray.fromhex(hex_value)

        self.logger.info('Received notification on handle=%s, value=%s',
                         hex_handle, hex_value)
        try:
            self.lock.acquire()

            if handle in self.callbacks:
                for callback in self.callbacks[handle]:
                    callback(handle, value)
        finally:
            self.lock.release()

    def stop(self):
        """Stop the backgroud notification handler in preparation for a
        disconnect.
        """
        self.logger.info('Stopping')
        self.running = False

        if self.con.isalive():
            self.con.sendline('exit')
            while True:
                if not self.con.isalive():
                    break
                time.sleep(0.1)
            self.con.close()

    def run(self):
        """Run a background thread to listen for notifications.
        """
        self.logger.info('Running...')
        while self.running:
            with self.connection_lock:
                try:
                    self._expect("fooooooo", timeout=.1)
                except pygatt.exceptions.NotificationTimeout:
                    pass
                except (pygatt.exceptions.NotConnectedError, pexpect.EOF):
                    break
            # TODO need some delay to avoid aggresively grabbing the lock,
            # blocking out the others. worst case is 1 second delay for async
            # not received as a part of another request
            time.sleep(.01)
        self.logger.info("Listener thread finished")
