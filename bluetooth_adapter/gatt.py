from binascii import unhexlify
from enum import Enum


# TODO: The abastractions here could be cleaned up to have a GattAttribute
#       base class and maybe not format the gatt uuids as enums. This is just
#       a first attempt so far.
# NOTE: what I am thinking right now is having a GattAttribute parent class that
#       has a Uuid and a handle, then subclasses for descs, chars, and servs.
#       The GATT constants should be enums and then there should be hash table
#       that goes from the enum member to the Uuid and perhaps another one that
#       goes from Uuid to enum member so we can have O(1) lookup.


class Uuid(object):
    def __init__(self, uuid_string):
        # Trim prefix
        if (len(uuid_string) > 2) and (uuid_string[:2] == '0x'):
            uuid_string = uuid_string[2:]
        self.string = uuid_string.replace('-', '')
        self.bytearray = unhexlify(self.string)

    def __cmp__(self, other):
        return cmp(self.string.lower(), other.string.lower())

    def __str__(self):
        return '0x' + self.string

    def __repr__(self):
        return ("<{0}.{1} object at {2}: 0x{3}"
                .format(self.__module__, self.__class__.__name__, id(self),
                        self.string))


# TODO: not sure if this will be used anywhere
class GattServices(Enum):
    generic_access_profile = Uuid('0x1800')
    generic_attribute_profile = Uuid('0x1801')


# TODO: clean up
class GattService(object):
    """GATT protocol service."""
    def __init__(self, handle, gatt_attribute_type):
        self.handle = handle
        self.service_type = gatt_attribute_type  # a GattAttributeType object
        self.characteristics = []  # GattCharacteristic objects

    def __repr__(self):
        return ('<{0}.{1} object at {2}: handle={3} attribute_type={4}>'
                .format(self.__module__, self.__class__.__name__,
                        hex(id(self)), '0x' + format(self.handle, '04x'),
                        self.service_type))


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
    def __init__(self, handle, custom_128_bit_uuid=None):
        self.handle = handle
        self.characteristic_type = None
        self.custom_128_bit_uuid = custom_128_bit_uuid
        self.descriptors = []

    def __repr__(self):
        return ('<{0}.{1} object at {2}: handle={3} characteristic_type={4} '
                'custom_128_bit_uuid={5}>'
                .format(self.__module__, self.__class__.__name__,
                        hex(id(self)), '0x' + format(self.handle, '04x'),
                        self.characteristic_type, self.custom_128_bit_uuid))


class GattCharacteristicDescriptor(Enum):
    characteristic_extended_properties = Uuid('0x2900')
    characteristic_user_description = Uuid('0x2901')
    client_characteristic_configuration = Uuid('0x2902')
    server_characteristic_configuration = Uuid('0x2903')
    characteristic_format = Uuid('0x2904')
    characteristic_aggregate_format = Uuid('0x2905')


class GattDescriptor(object):
    """GATT protocol descriptor."""
    def __init__(self, handle, descriptor_type):
        self.handle = handle
        self.descriptor_type = descriptor_type

    def __repr__(self):
        return ('<{0}.{1} object at {2}: handle={3} descriptor_type={4}>'
                .format(self.__module__, self.__class__.__name__,
                        hex(id(self)), '0x' + format(self.handle, '04x'),
                        self.descriptor_type))
