from __future__ import print_function

import functools
import re
import logging
import platform
import sys
import time
import threading
import subprocess
from uuid import UUID
from contextlib import contextmanager
try:
    import pexpect
except Exception as err:
    if platform.system() != 'Windows':
        print("WARNING:", err, file=sys.stderr)

from pygatt.exceptions import NotConnectedError, BLEError, NotificationTimeout
from pygatt.backends import BLEBackend, Characteristic
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from .device import GATTToolBLEDevice

log = logging.getLogger(__name__)


def at_most_one_device(func):
    """Every connection-specific function on the backend takes an instance of
    GATTToolBLEDevice as the first argument - this decorator will raise an
    exception if that device is not what the backend thinks is the currently
    connected device.
    """
    @functools.wraps(func)
    def wrapper(self, connected_device, *args, **kwargs):
        if connected_device != self._connected_device:
            raise NotConnectedError()
        return func(self, *args, **kwargs)
    return wrapper


class GATTToolReceiver(threading.Thread):
    """
    Observe pygatttool stdout in seperate thread and dispatch events /
    callbacks.
    """

    def __init__(self, connection, parent_aliveness):
        super(GATTToolReceiver, self).__init__()
        self.daemon = True
        self._connection = connection
        self._parent_aliveness = parent_aliveness
        self._event_vector = {
            'notification': {
                'pattern': r'Notification handle = .*? \r',
            },
            'indication': {
                'pattern': r'Indication   handle = .*? \r',
            },
            'disconnected': {
                'pattern': r'.*Disconnected\r',
            },
            'char_written': {
                'pattern': r'Characteristic value (was )?written successfully',
            },
            'value': {
                'pattern': r'value: .*? \r',
            },
            'discover': {
                'pattern':
                    r'handle: 0x([a-fA-F0-9]{4}), '
                    'char properties: 0x[a-fA-F0-9]{2}, '
                    'char value handle: 0x([a-fA-F0-9]{4}), '
                    'uuid: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]'
                    '{4}-[0-9a-f]{12})\r\n',  # noqa
            },
            'connect': {
                'pattern': r'Connection successful.*\[LE\]>',
            },
        }

        for event in self._event_vector.values():
            event["event"] = threading.Event()
            event["before"] = None
            event["after"] = None
            event["match"] = None
            event["callback"] = None

    def run(self):
        items = sorted([
            (event["pattern"], event)
            for event in self._event_vector.values()
        ])
        patterns = [item[0] for item in items]
        events = [item[1] for item in items]

        log.info('Running...')
        while self._parent_aliveness.is_set():
            try:
                event_index = self._connection.expect(patterns, timeout=.5)
            except pexpect.TIMEOUT:
                continue
            except (NotConnectedError, pexpect.EOF):
                self._event_vector["disconnected"]["event"].set()
                break
            event = events[event_index]
            event["before"] = self._connection.before
            event["after"] = self._connection.after
            event["match"] = self._connection.match
            event["event"].set()
            if event["callback"]:
                event["callback"](event)
        log.info("Listener thread finished")

    def clear(self, event):
        """
        Clear event
        """
        self._event_vector[event]["event"].clear()

    def is_set(self, event):
        return self._event_vector[event]["event"].is_set()

    def wait(self, event, timeout=None):
        """
        Wait for event to be trigerred
        """
        if not self._event_vector[event]["event"].wait(timeout):
            raise NotificationTimeout()

    def register_callback(self, event, callback):
        """
        Call the callback function when event happens. Event wrapper
        is passed as argument.
        """
        self._event_vector[event]["callback"] = callback

    def last_value(self, event, value_type):
        """
        Retrieve last value that saved by the event
        """
        return self._event_vector[event][value_type]

    @contextmanager
    def event(self, event, timeout=None):
        """
        Clear an event, execute context and then wait for event

        >>> with gtr.event("connect", 10):
        >>>     gtb.send(connect_command)

        """
        self.clear(event)
        yield
        self.wait(event, timeout)


class GATTToolBackend(BLEBackend):
    """
    Backend to pygatt that uses BlueZ's interactive gatttool CLI prompt.
    """

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
        self._receiver = None
        self._con = None  # gatttool interactive session
        self._characteristics = {}
        self._running = threading.Event()
        self._address = None
        self._send_lock = threading.Lock()

    def sendline(self, command):
        """
        send a raw command to gatttool
        """
        with self._send_lock:
            self._con.sendline(command)

    def supports_unbonded(self):
        return False

    def start(self, reset_on_start=True):
        if self._con and self._running.is_set():
            self.stop()

        self._running.set()

        if reset_on_start:
            # Without restarting, sometimes when trying to bond with the
            # GATTTool backend, the entire computer will lock up.
            self.reset()

        # Start gatttool interactive session for device
        args = [
            'gatttool',
            self._cli_options,
            '-i',
            self._hci_device,
            '-I'
        ]
        gatttool_cmd = ' '.join([arg for arg in args if arg])
        log.debug('gatttool_cmd=%s', gatttool_cmd)
        self._con = pexpect.spawn(gatttool_cmd, logfile=self._gatttool_logfile)
        # Wait for response
        self._con.expect(r'\[LE\]>', timeout=1)

        # Start the notification receiving thread
        self._receiver = GATTToolReceiver(self._con, self._running)
        self._receiver.daemon = True
        self._receiver.register_callback("disconnected", self._disconnect)
        for event in ["notification", "indication"]:
            self._receiver.register_callback(
                event,
                self._handle_notification_string
            )
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

        if self._con and self._con.isalive():
            while True:
                if not self._con.isalive():
                    break
                self.sendline('exit')
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
        self.sendline('sec-level low')
        self._address = address

        try:
            cmd = 'connect {0} {1}'.format(self._address, address_type)
            with self._receiver.event("connect", timeout):
                self.sendline(cmd)
        except NotificationTimeout:
            message = "Timed out connecting to {0} after {1} seconds.".format(
                self._address, timeout
            )
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
            con.expect(
                ["Device has been removed", "# "],
                timeout=.5
            )
        except pexpect.TIMEOUT:
            log.error("Unable to remove bonds for %s: %s",
                      address, con.before)
        log.info("Removed bonds for %s", address)

    def _disconnect(self, event):
        try:
            self.disconnect(self._connected_device)
        except NotConnectedError:
            pass

    @at_most_one_device
    def disconnect(self, *args, **kwargs):
        if not self._receiver.is_set("disconnected"):
            self.sendline('disconnect')
        self._connected_device = None
        # TODO maybe call a disconnected callback on the device instance, so the
        # device knows if it was asynchronously disconnected?

    @at_most_one_device
    def bond(self, *args, **kwargs):
        log.info('Bonding')
        self.sendline('sec-level medium')

    def _save_charecteristic_callback(self, event):
        match = event["match"]
        try:
            value_handle = int(match.group(2), 16)
            char_uuid = match.group(3).strip().decode('ascii')
            self._characteristics[UUID(char_uuid)] = Characteristic(
                char_uuid, value_handle
            )
            log.debug(
                "Found characteristic %s, value handle: 0x%x",
                char_uuid,
                value_handle
            )
        except AttributeError:
            pass

    @at_most_one_device
    def discover_characteristics(self):
        self._characteristics = {}
        self._receiver.register_callback(
            "discover",
            self._save_charecteristic_callback,
        )
        self.sendline('characteristics')

        max_time = time.time() + 5
        while not self._characteristics and time.time() < max_time:
            time.sleep(.5)

        # Sleep one extra second in case we caught characteristic
        # in the middle
        time.sleep(1)

        if not self._characteristics:
            raise NotConnectedError("Characteristic discovery failed")

        return self._characteristics

    def _handle_notification_string(self, event):
        msg = event["after"]
        if not msg:
            log.warn("Blank message received in notification, ignored")
            return

        split_msg = msg.strip().split(None, 5)
        if len(split_msg) < 6:
            log.warn("Unable to parse notification string, ignoring: %s", msg)
            return

        hex_handle, _, hex_values = split_msg[3:]
        handle = int(hex_handle, 16)
        values = bytearray(hex_values.replace(" ", "").decode("hex"))
        if self._connected_device is not None:
            self._connected_device.receive_notification(handle, values)

    @at_most_one_device
    def char_write_handle(self, handle, value, wait_for_response=False,
                          timeout=1):
        """
        Writes a value to a given characteristic handle.
        :param handle:
        :param value:
        :param wait_for_response:
        """
        cmd = 'char-write-{0} 0x{1:02x} {2}'.format(
            'req' if wait_for_response else 'cmd',
            handle,
            ''.join("{0:02x}".format(byte) for byte in value),
        )

        log.debug('Sending cmd=%s', cmd)
        if wait_for_response:
            try:
                with self._receiver.event("char_written", timeout=timeout):
                    self.sendline(cmd)
            except NotificationTimeout:
                log.error("No response received", exc_info=True)
                raise
        else:
            self.sendline(cmd)

        log.info('Sent cmd=%s', cmd)

    @at_most_one_device
    def char_read(self, uuid, timeout=1):
        """
        Reads a Characteristic by uuid.
        :param uuid: UUID of Characteristic to read.
        :type uuid: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        with self._receiver.event("value", timeout=timeout):
            self.sendline('char-read-uuid %s' % uuid)
        rval = self._receiver.last_value("value", "after").split()[1:]
        return bytearray([int(x, 16) for x in rval])

    def reset(self):
        subprocess.Popen(["sudo", "systemctl", "restart", "bluetooth"]).wait()
        subprocess.Popen([
            "sudo", "hciconfig", self._hci_device, "reset"]).wait()
