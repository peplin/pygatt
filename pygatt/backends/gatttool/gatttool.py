from __future__ import print_function

import functools
import itertools
import re
import logging
import platform
import signal
import sys
import time
import threading
import subprocess
from uuid import UUID
from contextlib import contextmanager

from pygatt.exceptions import NotConnectedError, BLEError, NotificationTimeout
from pygatt.backends import BLEBackend, Characteristic, BLEAddressType
from pygatt.backends.backend import DEFAULT_CONNECT_TIMEOUT_S
from .device import GATTToolBLEDevice

DEFAULT_RECONNECT_DELAY = 1.0

log = logging.getLogger(__name__)


def _hex_value_parser(x):
    return bytearray.fromhex(x)


def is_windows():
    return platform.system() == 'Windows'

try:
    import pexpect
except Exception as err:
    if not is_windows():
        print("WARNING:", err, file=sys.stderr)


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
    Observe pygatttool stdout in separate thread and dispatch events /
    callbacks.
    """

    def __init__(self, connection, parent_aliveness):
        super(GATTToolReceiver, self).__init__()
        self.daemon = True
        self._connection = connection
        self._parent_aliveness = parent_aliveness
        self._event_vector = {
            'notification': {
                'patterns': [r'Notification handle = .*? \r'],
            },
            'indication': {
                'patterns': [r'Indication   handle = .*? \r'],
            },
            'disconnected': {
                'patterns': [
                    r'.*Disconnected',
                    r'.*Invalid file descriptor',
                ]
            },
            'char_written': {
                'patterns': [
                    r'Characteristic value (was )?written successfully',
                    r'Characteristic Write Request failed: A timeout occured',
                ]
            },
            'value': {
                'patterns': [r'value: .*? \r']
            },
            'value/descriptor': {
                'patterns': [r'value/descriptor: .*? \r']
            },
            'discover': {
                'patterns': [
                    r'handle: 0x([a-fA-F0-9]{4}), '
                    'char properties: 0x[a-fA-F0-9]{2}, '
                    'char value handle: 0x([a-fA-F0-9]{4}), '
                    'uuid: ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]'
                    '{4}-[0-9a-f]{12})\r\n',  # noqa
                ]
            },
            'connect': {
                'patterns': [r'Connection successful.*\[LE\]>']
            },
            'mtu': {
                'patterns': [
                    r'MTU was exchanged successfully: (\d+)'
                ]
            }
        }

        for event in self._event_vector.values():
            event["event"] = threading.Event()
            event["before"] = None
            event["after"] = None
            event["match"] = None
            event["callback"] = []

    def run(self):
        items = sorted(itertools.chain.from_iterable(
            [[(pattern, event)
              for pattern in event["patterns"]]
             for event in self._event_vector.values()])
        )
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
            for clb in event["callback"]:
                clb(event)
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
        self._event_vector[event]["callback"].append(callback)

    def remove_callback(self, event, callback):
        """
        Remove a registered callback, so it is no longer called when an
        event happens.
        """
        if callback in self._event_vector[event]["callback"]:
            self._event_vector[event]["callback"].remove(callback)

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
                 cli_options=None, search_window_size=None, max_read=None):
        """
        Initialize.

        hci_device -- the hci_device to use with GATTTool.
        gatttool_logfile -- an optional filename to store raw gatttool
                input and output.
        search_window_size -- integer (optional); size in bytes of the
                search window that is used by `pexpect.expect`. This value
                should not exceed max_read
        max_read -- integer; number of bytes to read into gatt buffer at
                a time. Defaults to ~2000
        """

        if is_windows():
            raise BLEError("The GATTToolBackend requires BlueZ, "
                           "which is not available in Windows")

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
        self._auto_reconnect = False
        self._reconnecting = False
        self._search_window_size = search_window_size
        self._scan = None
        self._max_read = max_read

    def sendline(self, command):
        """
        send a raw command to gatttool
        """
        with self._send_lock:
            self._con.sendline(command)

    def supports_unbonded(self):
        return False

    def start(self, reset_on_start=True, initialization_timeout=3):
        """
        Run gatttool to prepare for sending commands and monitoring the CLI tool
        output.

        :param bool reset_on_start: Perhaps due to a bug in gatttol or pygatt,
            but if the bluez backend isn't restarted, it can sometimes lock up
            the computer when trying to make a connection to HCI device.
        :param int initialization_timeout: Seconds to wait for the gatttool
            prompt. This should appear almost instantly, but on some HCI devices
            it may take longer to start up.
        """
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
        if self._max_read:
            self._con = pexpect.spawn(
                gatttool_cmd, logfile=self._gatttool_logfile,
                searchwindowsize=self._search_window_size,
                maxread=self._max_read
            )
        else:
            self._con = pexpect.spawn(
                gatttool_cmd, logfile=self._gatttool_logfile,
                searchwindowsize=self._search_window_size,
            )

        # Wait for the interactive prompt
        self._con.expect(r'\[LE\]>', timeout=initialization_timeout)

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
        Disconnects any connected device, stops the background receiving thread
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

        cmd = 'hcitool -i %s lescan' % self._hci_device
        if run_as_root:
            cmd = 'sudo %s' % cmd

        log.info("Starting BLE scan")
        self._scan = scan = pexpect.spawn(cmd)
        # "lescan" doesn't exit, so we're forcing a timeout here:
        try:
            scan.expect('foooooo', timeout=timeout)
        except pexpect.EOF:
            before_eof = scan.before.decode('utf-8', 'replace')
            if "No such device" in before_eof:
                message = "No BLE adapter found"
            elif "Set scan parameters failed: Input/output error" in before_eof:
                message = ("BLE adapter requires reset after a scan as root"
                           "- call adapter.reset()")
            else:
                message = "Unexpected error when scanning: %s" % before_eof
            log.error(message)
            raise BLEError(message)
        except pexpect.TIMEOUT:
            devices = {}
            for line in scan.before.decode('utf-8', 'replace').split('\r\n'):
                if 'sudo' in line:
                    raise BLEError("Enable passwordless sudo for 'hcitool' "
                                   "before scanning")
                match = re.match(
                    r'(([0-9A-Fa-f][0-9A-Fa-f]:?){6}) (\(?.+\)?)', line)

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
        finally:
            self.kill()
        return []

    def kill(self):
        if self._scan is None:
            return
        # Wait for lescan to exit cleanly, otherwise it leaves the BLE
        # adapter in a bad state and the device must be reset through BlueZ.
        # This will not work if run_as_root was used, since this process
        # itself doesn't have permission to terminate a process running as
        # root (hcitool itself). We recommend using the setcap tool to allow
        # scanning as a non-root user:
        #
        #    $ sudo setcap 'cap_net_raw,cap_net_admin+eip' `which hcitool`
        try:
            self._scan.kill(signal.SIGINT)
            self._scan.wait()
        except OSError:
            log.error("Unable to gracefully stop the scan - "
                      "BLE adapter may need to be reset.")

    def connect(self, address, timeout=DEFAULT_CONNECT_TIMEOUT_S,
                address_type=BLEAddressType.public, auto_reconnect=False):
        log.info('Connecting to %s with timeout=%s', address, timeout)
        self.sendline('sec-level low')
        self._address = address
        self._auto_reconnect = auto_reconnect

        try:
            cmd = 'connect {0} {1}'.format(self._address, address_type.name)
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
        con = pexpect.spawn('bluetoothctl')

        try:
            con.expect("bluetooth", timeout=1)
            log.info("Clearing bond for %s", address)
            con.sendline("remove " + address.upper())
            con.expect(
                ["Device has been removed", "# "],
                timeout=.5
            )
        except pexpect.TIMEOUT:
            log.error("Unable to remove bonds for %s: %s",
                      address, con.before)
        finally:
            con.close(True)
        log.info("Removed bonds for %s", address)

    def _disconnect(self, event):
        if self._connected_device is not None and self._auto_reconnect:

            # this is called as a callback from the pexpect thread
            # the reconnection process has to be started in parallel, otherwise
            # the call is never finished
            log.info("Connection to %s lost. Reconnecting...", self._address)
            reconnect_thread = threading.Thread(target=self.reconnect,
                                                args=(self._connected_device, ))
            reconnect_thread.start()
        else:
            try:
                self.disconnect(self._connected_device)
            except NotConnectedError:
                pass

    @at_most_one_device
    def reconnect(self, timeout=DEFAULT_CONNECT_TIMEOUT_S):
        while self._auto_reconnect:
            log.info("Connecting to %s with timeout=%s", self._address,
                     timeout)
            try:
                cmd = "connect"
                with self._receiver.event("connect", timeout):
                    self.sendline(cmd)
                # reenable all notifications
                self._connected_device.resubscribe_all()
                log.info("Connection to %s reestablished.")
                break  # finished reconnecting
            except NotificationTimeout:
                message = ("Timed out connecting to {0} after {1} seconds. "
                           "Retrying in {2} seconds".format(
                                self._address, timeout,
                                DEFAULT_RECONNECT_DELAY))
                log.info(message)
                time.sleep(DEFAULT_RECONNECT_DELAY)

    @at_most_one_device
    def disconnect(self, *args, **kwargs):
        self._auto_reconnect = False  # disables any running reconnection
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
    def discover_characteristics(self, timeout=5):
        self._characteristics = {}
        self._receiver.register_callback(
            "discover",
            self._save_charecteristic_callback,
        )
        self.sendline('characteristics')

        max_time = time.time() + timeout
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

        match_obj = re.match(r'.* handle = (0x[0-9a-f]+) value:(.*)',
                             msg.decode('utf-8'))
        if match_obj is None:
            log.warn("Unable to parse notification string, ignoring: %s", msg)
            return

        handle = int(match_obj.group(1), 16)
        values = _hex_value_parser(match_obj.group(2).strip())
        if self._connected_device is not None:
            self._connected_device.receive_notification(handle, values)

    @at_most_one_device
    def char_write_handle(self, handle, value, wait_for_response=True,
                          timeout=30):
        """
        Writes a value to a given characteristic handle.

        :param handle:
        :param value:
        :param wait_for_response: If true, performs an attribute write. If
            false, sends a command and expects no acknowledgement from the
            device.
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

    @at_most_one_device
    def char_read_handle(self, handle, timeout=4):
        """
        Reads a Characteristic by handle.
        :param handle: handle of Characteristic to read.
        :type handle: str
        :return: bytearray of result.
        :rtype: bytearray
        """
        with self._receiver.event("value/descriptor", timeout=timeout):
            self.sendline('char-read-hnd %s' % handle)
        rval = self._receiver.last_value("value/descriptor", "after"
                                         ).split()[1:]
        return bytearray([int(x, 16) for x in rval])

    @at_most_one_device
    def exchange_mtu(self, mtu, timeout=1):
        cmd = 'mtu {}'.format(mtu)

        log.debug('Requesting MTU: {}'.format(mtu))

        with self._receiver.event('mtu', timeout=timeout):
            self.sendline(cmd)
        try:
            rval = self._receiver.last_value("mtu", "after").split()[-1]
        except ValueError:
            log.error('MTU exchange failed: "{}"'.format(rval))
            raise

        log.debug('MTU exhange successful: {}'.format(rval))

        return rval

    def reset(self):
        subprocess.Popen(["sudo", "systemctl", "restart", "bluetooth"]).wait()
        subprocess.Popen([
            "sudo", "hciconfig", self._hci_device, "reset"]).wait()
