from binascii import unhexlify
from enum import Enum


class Uuid(object):
    def __init__(self, uuid_string):
        # Trim prefix
        if (len(uuid_string) > 2) and (uuid_string[:2] == '0x'):
            uuid_string = uuid_string[2:]
        self.string = uuid_string
        self.bytearray = unhexlify(self.string.replace('-', ''))

    def __cmp__(self, other):
        return cmp(self.string, other.string)


class GattServices(Enum):
    generic_access_profile = Uuid('0x1800')
    generic_attribute_profile = Uuid('0x1801')


class Service(object):
    """GATT protocol service."""
    uuid = None  # a GattServices object
    handle = None
    characteristics = []  # GattCharacteristic objects


class GattAttributeType(Enum):
    primary_service = Uuid('0x2800')
    secondary_service = Uuid('0x2801')
    include = Uuid('0x2802')
    characteristic = Uuid('0x2803')


class GattCharacteristicType(Enum):
    device_name = Uuid('0x2A00')
    appearance = Uuid('0x2A01')
    peripheral_privacy_flag = Uuid('0x2A02')
    reconnection_address = Uuid('0x2A03')
    peripheral_connection_parameters = Uuid('0x2A04')
    service_changed = Uuid('0x2A05')


class GattCharacteristic(object):
    """GATT protocol characteristic."""
    uuid = None
    handle = None
    characteristic_type = None
    descriptors = []


class GattCharacteristicDescriptor(Enum):
    characteristic_extended_properties = Uuid('0x2900')
    characteristic_user_description = Uuid('0x2901')
    client_characteristic_configuration = Uuid('0x2902')
    server_characteristic_configuration = Uuid('0x2903')
    characteristic_format = Uuid('0x2904')
    characteristic_aggregate_format = Uuid('0x2905')


class GattDescriptor(object):
    """GATT protocol descriptor."""
    uuid = None
    handle = None
    descriptor_type = None
