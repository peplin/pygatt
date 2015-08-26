from binascii import unhexlify
from enum import Enum


class Uuid(object):
    def __init__(self, uuid_string):
        # Trim prefix
        if (len(uuid_string) > 2) and (uuid_string[:2] == '0x'):
            uuid_string = uuid_string[2:]
        self._string = uuid_string.replace('-', '').upper()
        self._bytearray = unhexlify(self._string)

    def __cmp__(self, other):
        return cmp(str(self), str(other))

    def __str__(self):
        return '0x' + self._string

    def __repr__(self):
        return ("<{0}.{1} object at {2}: 0x{3}>"
                .format(self.__module__, self.__class__.__name__, id(self),
                        self._string))

    def __len__(self):
        return len(self._string) * 4

    def to_bytearray(self):
        return unhexlify(self._string)


class GattAttribute(object):

    def __init__(self, attribute_type, handle, uuid=None):
        self.attribute_type = attribute_type
        self.uuid = uuid
        self.handle = handle

    def __repr__(self):
        return ("<{0}.{1} object at {2}: attribute_type={3} handle={4} "
                "uuid={5}>"
                .format(self.__module__, self.__class__.__name__, id(self),
                        self.attribute_type, self.handle, self.uuid))


class Service(GattAttribute):

    def __init__(self, handle, uuid=None, secondary=False):
        att_type = (AttributeType.secondary_service if secondary
                    else AttributeType.primary_service)
        super(Service, self).__init__(att_type, handle, uuid=uuid)
        self.characteristics = []


class Characteristic(GattAttribute):

    def __init__(self, handle, uuid=None, characteristic_type=None,
                 custom=False):
        super(Characteristic, self).__init__(
            None if custom else AttributeType.characteristic, handle, uuid=uuid)
        self.characteristic_type = characteristic_type
        self.descriptors = []


class Descriptor(GattAttribute):

    def __init__(self, handle, uuid=None, descriptor_type=None):
        super(Descriptor, self).__init__(None, handle, uuid=uuid)
        self.descriptor_type = descriptor_type


AttributeType = Enum('AttributeType', [
    'primary_service',
    'secondary_service',
    'include',
    'characteristic',
])


ATTRIBUTE_TYPE_NAME_TO_UUID = {
    AttributeType.primary_service.name: Uuid('0x2800'),
    AttributeType.secondary_service.name: Uuid('0x2801'),
    AttributeType.include.name: Uuid('0x2802'),
    AttributeType.characteristic.name: Uuid('0x2803'),
}


UUID_STRING_TO_ATTRIBUTE_TYPE = {
    str(Uuid('0x2800')): AttributeType.primary_service,
    str(Uuid('0x2801')): AttributeType.secondary_service,
    str(Uuid('0x2802')): AttributeType.include,
    str(Uuid('0x2803')): AttributeType.characteristic,
}


CharacteristicType = Enum('CharacteristicType', [
    'device_name',
    'appearance',
    'peripheral_privacy_flag',
    'reconnection_address',
    'peripheral_connection_parameters',
    'service_changed',
])


CHARACTERISTIC_TYPE_NAME_TO_UUID = {
    CharacteristicType.device_name.name: Uuid('0x2A00'),
    CharacteristicType.appearance.name: Uuid('0x2A01'),
    CharacteristicType.peripheral_privacy_flag.name: Uuid('0x2A02'),
    CharacteristicType.reconnection_address.name: Uuid('0x2A03'),
    CharacteristicType.peripheral_connection_parameters.name: Uuid('0x2A04'),
    CharacteristicType.service_changed.name: Uuid('0x2A05'),
}


UUID_STRING_TO_CHARACTERISTIC_TYPE = {
    str(Uuid('0x2A00')): CharacteristicType.device_name,
    str(Uuid('0x2A01')): CharacteristicType.appearance,
    str(Uuid('0x2A02')): CharacteristicType.peripheral_privacy_flag,
    str(Uuid('0x2A03')): CharacteristicType.reconnection_address,
    str(Uuid('0x2A04')): CharacteristicType.peripheral_connection_parameters,
    str(Uuid('0x2A05')): CharacteristicType.service_changed,
}


DescriptorType = Enum('DescriptorType', [
    'characteristic_extended_properties',
    'characteristic_user_description',
    'client_characteristic_configuration',
    'server_characteristic_configuration',
    'characteristic_format',
    'characteristic_aggregate_format',
])


DESCRIPTOR_TYPE_NAME_TO_UUID = {
    DescriptorType.characteristic_extended_properties.name: Uuid('0x2900'),
    DescriptorType.characteristic_user_description.name: Uuid('0x2901'),
    DescriptorType.client_characteristic_configuration.name: Uuid('0x2902'),
    DescriptorType.server_characteristic_configuration.name: Uuid('0x2903'),
    DescriptorType.characteristic_format.name: Uuid('0x2904'),
    DescriptorType.characteristic_aggregate_format.name: Uuid('0x2905'),
}

UUID_STRING_TO_DESCRIPTOR_TYPE = {
    str(Uuid('0x2900')): DescriptorType.characteristic_extended_properties,
    str(Uuid('0x2901')): DescriptorType.characteristic_user_description,
    str(Uuid('0x2902')): DescriptorType.client_characteristic_configuration,
    str(Uuid('0x2903')): DescriptorType.server_characteristic_configuration,
    str(Uuid('0x2904')): DescriptorType.characteristic_format,
    str(Uuid('0x2905')): DescriptorType.characteristic_aggregate_format,
}
