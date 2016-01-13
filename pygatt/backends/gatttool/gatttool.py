from __future__ import print_function

import re
import logging
import platform
import sys
import time
import threading
import subprocess
from uuid import UUID
try:
    import pexpect
except Exception as e:
    if platform.system() != 'Windows':
        print("WARNING:", e, file=sys.stderr)

from pygatt.exceptions import (NotConnectedError, NotificationTimeout, BLEError,
                               NoResponseError)
from pygatt.backends import BLEBackend, Characteristic
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from .device import GATTToolBLEDevice

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 0.5


def at_most_one_device(func):
    """Every connection-specific function on the backend takes an instance of
    GATTToolBLEDevice as the first argument - this decorator will raise an
    exception if that device is not what the backend thinks is the currently
    connected device.
    """
    def wrapper(self, connected_device, *args, **kwargs):
        if connected_device != self._connected_device:
            raise NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class GATTToolBackend(BLEBackend):
    """
    Backend to pygatt that uses BlueZ's interactive gatttool CLI prompt.
    """
    _GATTTOOL_PROMPT = r".*> "

    def __init__(self, hci_device='hci0', gatttool_logfile=None,
                 cli_options=None):
        """
        Initialize.

        hci_device -- the hci_device to use with GATTTool.
        gatttool_logfile -- an optional filename to store raw gatttool
                input and output.
        """
        self._hci_device = hci_device
        self._cli_options = cli_options
        self._connected_device = None
        self._gatttool_logfile = gatttool_logfile
        self._receiver = None  # background notification receiving thread
        self._con = None  # gatttool interactive session

    def supports_unbonded(self):
        return False

    def start(self, reset_on_start=True):
        if self._con and self._running.is_set():
            self.stop()

        self._running = threading.Event()
        self._running.set()
        self._connection_lock = threading.RLock()

        if reset_on_start:
            # Without restarting, sometimes when trying to bond with the
            # GATTTool backend, the entire computer will lock up.
            self.reset()

        # Start gatttool interactive session for device
        gatttool_cmd = ' '.join(filter(None, [
            'gatttool',
            self._cli_options,
            '-i',
            self._hci_device,
            '-I'
        ]))
        log.debug('gatttool_cmd=%s', gatttool_cmd)
        self._con = pexpect.spawn(gatttool_cmd, logfile=self._gatttool_logfile)
        # Wait for response
        self._con.expect(r'\[LE\]>', timeout=1)

        # Start the notification receiving thread
        self._receiver = threading.Thread(target=self._receive)
        self._receiver.daemon = True
        self._receiver.start()

    def stop(self):
        """
        Disconnects any connected device, stops the backgroud receiving thread
        and closes the spawned gatttool process.
        disconnect.
        """
        self.disconnect(self._connected_device)
        if self._running.is_set():
            log.info('Stopping')
        self._running.clear()

        if self._receiver:
            self._receiver.join()
            self._receiver = None

        if self._con and self._con.isalive():
            self._con.sendline('exit')
            while True:
                if not self._con.isalive():
                    break
                time.sleep(0.1)
            self._con.close()
            self._con = None

    def scan(self, timeout=10, run_as_root=False):
        """
        By default, scanning with gatttool requires root privileges.
        If you don't want to require root, you must add a few
        'capabilities' to your system. If you have libcap installed, run this to
        enable normal users to perform LE scanning:
            setcap 'cap_net_raw,cap_net_admin+eip' `which hcitool`

        If you do use root, the hcitool subprocess becomes more difficult to
        terminate cleanly, and may leave your Bluetooth adapter in a bad state.
        """

        cmd = 'hcitool lescan'
        if run_as_root:
            cmd = 'sudo %s' % cmd

        log.info("Starting BLE scan")
        scan = pexpect.spawn(cmd)
        # "lescan" doesn't exit, so we're forcing a timeout here:
        try:
            scan.expect('foooooo', timeout=timeout)
        except pexpect.EOF:
            message = "Unexpected error when scanning"
            if "No such device" in scan.before.decode('utf-8'):
                message = "No BLE adapter found"
            log.error(message)
            raise BLEError(message)
        except pexpect.TIMEOUT:
            devices = {}
            for line in scan.before.decode('utf-8').split('\r\n'):
                match = re.match(
                    r'(([0-9A-Fa-f][0-9A-Fa-f]:?){6}) (\(?[\w]+\)?)', line)

                if match is not None:
                    address = match.group(1)
                    name = match.group(3)
                    if name == "(unknown)":
                        name = None

                    if address in devices:
                        if (devices[address]['name'] is None) and (name is not
                                                                   None):
                            log.info("Discovered name of %s as %s",
                                     address, name)
                            devices[address]['name'] = name
                    else:
                        log.info("Discovered %s (%s)", address, name)
                        devices[address] = {
                            'address': address,
                            'name': name
                        }
            log.info("Found %d BLE devices", len(devices))
            return [device for device in devices.values()]
        return []

    def connect(self, address, timeout=DEFAULT_CONNECT_TIMEOUT_S,
                address_type='public'):
        log.info('Connecting with timeout=%s', timeout)
        self._con.sendline('sec-level low')
        self._address = address
        try:
            with self._connection_lock:
                cmd = 'connect %s %s' % (self._address, address_type)
                self._con.sendline(cmd)
                self._con.expect(b'Connection successful.*\[LE\]>', timeout)
        except pexpect.TIMEOUT:
            message = ("Timed out connecting to %s after %s seconds."
                       % (self._address, timeout))
            log.error(message)
            raise NotConnectedError(message)

        self._connected_device = GATTToolBLEDevice(address, self)
        return self._connected_device

    def clear_bond(self, address=None):
        """Use the 'bluetoothctl' program to erase a stored BLE bond.
        """
        con = pexpect.spawn('sudo bluetoothctl')
        con.expect("bluetooth", timeout=1)

        log.info("Clearing bond for %s", address)
        con.sendline("remove " + address.upper())
        try:
            con.expect(["Device has been removed",
                        "# "
                        ],
                       timeout=.5)
        except pexpect.TIMEOUT:
            log.error("Unable to remove bonds for %s: %s",
                      address, con.before)
        log.info("Removed bonds for %s", address)

    @at_most_one_device
    def disconnect(self):
        with self._connection_lock:
            # TODO with gattool from bluez 5.35, gatttol consumes 100% CPU after
            # sending "disconnect". If you let the remote device do the
            # disconnect, it doesn't. Leaving it commented out for now.
            # self._con.sendline('disconnect')
            pass
        self._connected_device = None
        # TODO make call a disconnected callback on the device, so the device
        # knows if it was async disconnected?

    @at_most_one_device
    def bond(self, *args, **kwargs):
        log.info('Bonding')
        self._con.sendline('sec-level medium')
        self._con.expect(self._GATTTOOL_PROMPT, timeout=1)

    @at_most_one_device
    def discover_characteristics(self):
        characteristics = {}
        with self._connection_lock:
            self._con.sendline('characteristics')

            timeout = 6
            while True:
                try:
                    self._con.expect(
                        r"handle: 0x([a-fA-F0-9]{4}), "
                        "char properties: 0x[a-fA-F0-9]{2}, "
                        "char value handle: 0x([a-fA-F0-9]{4}), "
                        "uuid: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\r\n",  # noqa
                        timeout=timeout)
                except pexpect.TIMEOUT:
                    break
                except pexpect.EOF:
                    break
                else:
                    try:
                        value_handle = int(self._con.match.group(2), 16)
                        char_uuid = (
                            self._con.match.group(3).strip().decode('ascii'))
                        characteristics[UUID(char_uuid)] = Characteristic(
                            char_uuid, value_handle)
                        log.debug(
                            "Found characteristic %s, value handle: 0x%x",
                            char_uuid,
                            value_handle)

                        # The characteristics all print at once, so after
                        # waiting 1-2 seconds for them to all fetch, you can
                        # load the rest without much delay at all.
                        timeout = .01
                    except AttributeError:
                        pass
        return characteristics

    def _expect(self, expected, timeout=DEFAULT_TIMEOUT_S):
        """
        We may (and often do) get an indication/notification before a
        write completes, and so it can be lost if we "expect()"'d something
        that came after it in the output, e.g.:
        > char-write-req 0x1 0x2
        Notification handle: xxx
        Write completed successfully.
        >
        Anytime we expect something we have to expect noti/indication first for
        a short time.
        """
        with self._connection_lock:
            patterns = [
                expected,
                'Notification handle = .*? \r',
                'Indication   handle = .*? \r',
                '.*Invalid file descriptor.*',
                '.*Disconnected\r',
            ]
            while True:
                try:
                    matched_pattern_index = self._con.expect(patterns, timeout)
                    if matched_pattern_index == 0:
                        break
                    elif matched_pattern_index in [1, 2]:
                        self._handle_notification_string(self._con.after)
                    elif matched_pattern_index == 3:
                        if self._running.is_set():
                            log.info("Disconnected")
                except pexpect.TIMEOUT:
                    raise NotificationTimeout(
                        "Timed out waiting for a notification")

    def _handle_notification_string(self, msg):
        hex_handle, _, hex_value = msg.strip().split()[3:]
        handle = int(hex_handle, 16)
        value = bytearray(hex_value)
        if self._connected_device is not None:
            self._connected_device.receive_notification(handle, value)

    @at_most_one_device
    def char_write_handle(self, handle, value, wait_for_response=False):
        """
        Writes a value to a given characteristic handle.
        :param handle:
        :param value:
        :param wait_for_response:
        """
        with self._connection_lock:
            hexstring = ''.join('%02x' % byte for byte in value)

            if wait_for_response:
                cmd = 'req'
            else:
                cmd = 'cmd'

            cmd = 'char-write-%s 0x%02x %s' % (cmd, handle, hexstring)

            log.debug('Sending cmd=%s', cmd)
            self._con.sendline(cmd)

            if wait_for_response:
                try:
                    self._expect('Characteristic value written successfully')
                except NoResponseError:
                    log.error("No response received", exc_info=True)
                    raise

            log.info('Sent cmd=%s', cmd)

    @at_most_one_device
    def char_read(self, uuid):
        """
        Reads a Characteristic by uuid.
        :param uuid: UUID of Characteristic to read.
        :type uuid: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        with self._connection_lock:
            self._con.sendline('char-read-uuid %s' % uuid)
            self._expect('value: .*? \r')

            rval = self._con.after.split()[1:]

            return bytearray([int(x, 16) for x in rval])

    def _receive(self):
        """
        Run a background thread to listen for notifications.
        """
        log.info('Running...')
        while self._running.is_set():
            try:
                self._expect("fooooooo", timeout=.1)
            except NotificationTimeout:
                pass
            except (NotConnectedError, pexpect.EOF):
                break
            # TODO need some delay to avoid aggresively grabbing the lock,
            # blocking out the others. worst case is 1 second delay for async
            # not received as a part of another request
            time.sleep(.01)
        log.info("Listener thread finished")

    def reset(self):
        subprocess.Popen(["sudo", "systemctl", "restart", "bluetooth"]).wait()
        subprocess.Popen([
            "sudo", "hciconfig", self._hci_device, "reset"]).wait()
