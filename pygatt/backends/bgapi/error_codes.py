from __future__ import print_function

from enum import Enum


class ErrorCode(Enum):
    insufficient_authentication = 0x0405


return_codes = {
    0: "Success",
    # BGAPI errors
    0x0180: "Invalid parameter",
    0x0181: "Device in wrong state",
    0x0182: "Out of memory",
    0x0183: "Feature not implemented",
    0x0184: "Command not recognized",
    0x0185: "Timeout",
    0x0186: "Not connected",
    0x0187: "Overflow/underflow",
    0x0188: "User attribute",
    0x0189: "Invalid liscense key",
    0x018A: "Command too long",
    0x018B: "Out of bounds",
    # Bluetooth errors
    0x0205: "Authentication failure",
    0x0206: "Pin or key missing",
    0x0207: "Memory capacity exceeded",
    0x0208: "Connection timeout",
    0x0209: "Connection limit exceeded",
    0x020C: "Command disallowed",
    0x0212: "Invalid command parameters",
    0x0213: "Remote user terminated connection",
    0x0216: "Connection terminated by local host",
    0x0222: "Link layer reponse timeout",
    0x0228: "Link layer instance passed",
    0x023A: "Controller busy",
    0x023B: "Unacceptable connection interval",
    0x023C: "Directed advertising timeout",
    0x023D: "MIC failure",
    0x023E: "Connection failed to be established",
    # Security manager protocol errors
    0x0301: "Passkey entry failed",
    0x0302: "OOB data is not available",
    0x0303: "Authentication requirements",
    0x0304: "Confirm value failed",
    0x0305: "Pairing not supported",
    0x0306: "Encryption key size",
    0x0307: "Command not supported",
    0x0308: "Unspecified reason",
    0x0309: "Repeated attempts",
    0x030A: "Invalid parameters",
    # Attribute protocol errors
    0x0401: "Invalid handle",
    0x0402: "Read not permitted",
    0x0403: "Write not permitted",
    0x0404: "Invalid PDU",
    ErrorCode.insufficient_authentication.value: "Insufficient authentication",
    0x0406: "Request not supported",
    0x0407: "Invalid offset",
    0x0408: "Insufficient authorization",
    0x0409: "Prepare queue full",
    0x040A: "Attribute not found",
    0x040B: "Attribute not long",
    0x040C: "Insufficient encryption key size",
    0x040D: "Invalid attribute value length",
    0x040E: "Unlikely error",
    0x040F: "Insufficient encryption",
    0x0410: "Unsupported group type",
    0x0411: "Insufficient resources",
    0x0480: "Application error codes",
}


def get_return_message(return_code):
    try:
        return return_codes[return_code]
    except KeyError:
        return "Unknown return code %04x" % return_code
