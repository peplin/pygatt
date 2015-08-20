from enum import Enum


class BleAddressType(Enum):
    gap_address_type_public = 0
    gap_address_type_random = 1


class GapDiscoverableMode(Enum):
    non_discoverable = 0x00
    limited_discoverable = 0x01
    general_discoverable = 0x02
    broadcast = 0x03
    user_data = 0x04
    enhanced_broadcasting = 0x80


class GapConnectableMode(Enum):
    non_connectable = 0x00
    directed_connectable = 0x01
    undirected_connectable = 0x02
    scannable_non_connectable = 0x03


class GapDiscoverMode(Enum):
    limited = 0x00
    generic = 0x01
    observation = 0x02


class Bonding(Enum):
    do_not_create_bonding = 0x00
    create_bonding = 0x01


class Bondable(Enum):
    no = 0x00
    yes = 0x01


class ConnectionStatusFlag(Enum):
    connected = 0x01
    encrypted = 0x02
    completed = 0x04
    parameters_change = 0x08


class ScanResponsePacketType(Enum):
    connectable_advertisement_packet = 0x00
    non_connectable_advertisement_packet = 0x02
    scan_response_packet = 0x04
    discoverable_advertisement_packet = 0x06


class ScanResponseDataType(Enum):
    flags = 0x01
    incomplete_list_16_bit_service_class_uuids = 0x02
    complete_list_16_bit_service_class_uuids = 0x03
    incomplete_list_32_bit_service_class_uuids = 0x04
    complete_list_32_bit_service_class_uuids = 0x05
    incomplete_list_128_bit_service_class_uuids = 0x06
    complete_list_128_bit_service_class_uuids = 0x07
    shortened_local_name = 0x08
    complete_local_name = 0x09
    tx_power_level = 0x0A
    class_of_device = 0x0D
    simple_pairing_hash_cc_192 = 0x0E
    simple_pairing_randomizer_rr_192 = 0x0F
    device_id_security_manager_tk_value = 0x10
    security_manager_out_of_band_flags = 0x11
    slave_connection_interval_range = 0x12
    list_of_16_bit_service_solicitation_uuids = 0x14
    list_of_32_bit_service_solicitation_uuids = 0x1F
    list_of_128_bit_service_solicitation_uuids = 0x15
    service_data_service_data_16_bit_uuid = 0x16
    service_data_32_bit_uuid = 0x20
    service_data_128_bit_uuid = 0x21
    le_secure_connections_confirmation_value = 0x22
    le_secure_connections_random_value = 0x23
    public_target_address = 0x17
    random_target_address = 0x18
    appearance = 0x19
    advertising_interval = 0x1A
    le_bluetooth_device_address = 0x1B
    le_role = 0x1C
    simple_pairing_hash_c_256 = 0x1D
    simple_pairing_randomizer_r_256 = 0x1E
    information_data_3d = 0x3D
    manufacturer_specific_data = 0xFF
