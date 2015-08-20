from enum import Enum
import logging


log = logging.getLogger(__name__)


class BgapiErrorEnum(Enum):
    invalid_parameter = 0x0180
    device_in_wrong_state = 0x0181
    out_of_memory = 0x0182
    feature_not_implemented = 0x0183
    command_not_recognized = 0x0184
    timeout = 0x0185
    not_connected = 0x0186
    overflow_underflow = 0x0187
    user_attribute = 0x0188
    invalid_license_key = 0x0189
    command_too_long = 0x018A
    out_of_bounds = 0x018B


class BluetoothErrorEnum(Enum):
    authentication_failure = 0x0205
    pin_or_key_missing = 0x0206
    memory_capacity_exceeded = 0x0207
    connection_timeout = 0x0208
    connection_limit_exceeded = 0x0209
    command_disallowed = 0x020C
    invalid_command_parameters = 0x0212
    remote_user_terminated_connection = 0x0213
    connection_terminated_by_local_host = 0x0216
    link_layer_response_timeout = 0x0222
    link_layer_instance_passed = 0x0228
    controller_busy = 0x023A
    unacceptable_connection_interval = 0x023B
    directed_advertising_timeout = 0x023C
    message_integrity_check_failure = 0x023D
    connection_failed_to_be_established = 0x023E


class SecurityManagerProtocolErrorEnum(Enum):
    passkey_entry_failed = 0x0301
    out_of_band_data_is_not_available = 0x0302
    authentication_requirements = 0x0303
    confirm_value_failed = 0x0304
    pairing_not_supported = 0x0305
    encryption_key_size = 0x0306
    command_not_supported = 0x0307
    unspecified_reason = 0x0308
    repeated_attempts = 0x0309
    invalid_parameters = 0x030A


class AttributeProtocolErrorEnum(Enum):
    invalid_handle = 0x0401
    read_not_permitted = 0x0402
    write_not_permitted = 0x0403
    invalid_protocol_data_unit = 0x0404
    insufficient_authenticiation = 0x0405
    request_not_supported = 0x0406
    invalid_offset = 0x0407
    insufficient_authorization = 0x0408
    prepare_queue_full = 0x0409
    attribute_not_found = 0x040A
    attribute_not_long = 0x040B
    insufficient_encryption_key_size = 0x040C
    invalid_attribute_value_length = 0x040D
    unlikely_error = 0x040E
    insufficient_encryption = 0x040F
    unsupported_group_type = 0x0410
    insufficient_resources = 0x0411
    application_error_codes = 0x0480


def get_return_message(return_code):
    log.debug("Getting message for return code %04x", return_code)
    msg = ('unknown return code %04x' % return_code)
    if return_code == 0:
        msg = 'success'
        log.debug("message: %s", msg)
        return msg
    for e in BgapiErrorEnum:
        if e.value == return_code:
            msg = e.name.replace('_', ' ')
            log.debug("message: %s", msg)
            return msg
    for e in BluetoothErrorEnum:
        if e.value == return_code:
            msg = e.name.replace('_', ' ')
            log.debug("message: %s", msg)
            return msg
    for e in SecurityManagerProtocolErrorEnum:
        if e.value == return_code:
            msg = e.name.replace('_', ' ')
            log.debug("message: %s", msg)
            return msg
    for e in AttributeProtocolErrorEnum:
        if e.value == return_code:
            msg = e.name.replace('_', ' ')
            log.debug("message: %s", msg)
            return msg
    log.warning(msg)
    return msg
