ble_address_type = {
    'gap_address_type_public': 0,
    'gap_address_type_random': 1
}
gap_discoverable_mode = {
    'non_discoverable': 0x00,
    'limited_discoverable': 0x01,
    'general_discoverable': 0x02,
    'broadcast': 0x03,
    'user_data': 0x04,
    'enhanced_broadcasting': 0x80
}
gap_connectable_mode = {
    'non_connectable': 0x00,
    'directed_connectable': 0x01,
    'undirected_connectable': 0x02,
    'scannable_non_connectable': 0x03,
}
gap_discover_mode = {
    'limited': 0x00,
    'generic': 0x01,
    'observation': 0x02,
}
bonding = {  # create bonding if devices not already bonded
    'do_not_create_bonding': 0x00,
    'create_bonding': 0x01,
}
bondable = {
    'no': 0x00,
    'yes': 0x01,
}
connection_status_flag = {
    'connected': 0x01,
    'encrypted': 0x02,
    'completed': 0x04,
    'parameters_change': 0x08,
}
scan_response_packet_type = {
    0x00: 'connectable_advertisement_packet',
    0x02: 'non-connectable_advertisement_packet',
    0x04: 'scan_response_packet',
    0x06: 'discoverable_advertisement_packet',
}
scan_response_data_type = {
    0x01: 'flags',
    0x02: 'incomplete_list_16-bit_service_class_uuids',
    0x03: 'complete_list_16-bit_service_class_uuids',
    0x04: 'incomplete_list_32-bit_service_class_uuids',
    0x05: 'complete_list_32-bit_service_class_uuids',
    0x06: 'incomplete_list_128-bit_service_class_uuids',
    0x07: 'complete_list_128-bit_service_class_uuids',
    0x08: 'shortened_local_name',
    0x09: 'complete_local_name',
    0x0A: 'tx_power_level',
    0x0D: 'class_of_device',
    0x0E: 'simple_pairing_hash_c/c-192',
    0x0F: 'simple_pairing_randomizer_r/r-192',
    0x10: 'device_id/security_manager_tk_value',
    0x11: 'security_manager_out_of_band_flags',
    0x12: 'slave_connection_interval_range',
    0x14: 'list_of_16-bit_service_solicitation_uuids',
    0x1F: 'list_of_32-bit_service_solicitation_uuids',
    0x15: 'list_of_128-bit_service_solicitation_uuids',
    0x16: 'service_data/service_data-16-bit_uuid',
    0x20: 'service_data-32-bit_uuid',
    0x21: 'service_data-128-bit_uuid',
    0x22: 'LE_secure_connections_confirmation_value',
    0x23: 'LE_secure_connections_random_value',
    0x17: 'public_target_address',
    0x18: 'random_target_address',
    0x19: 'appearance',
    0x1A: 'advertising_interval',
    0x1B: 'LE_bluetooth_device_address',
    0x1C: 'LE_role',
    0x1D: 'simple_pairing_hash_c-256',
    0x1E: 'simple_pairing_randomizer_r-256',
    0x3D: '3D_information_data',
    0xFF: 'manufacturer_specific_data',
}

# GATT
gatt_service_uuid = {
    'generic_access_profile': bytearray([0x18, 0x00]),
    'generic_attribute_profile': bytearray([0x18, 0x01]),
}
gatt_attribute_type_uuid = {
    'primary_service': bytearray([0x28, 0x00]),
    'secondary_service': bytearray([0x28, 0x01]),
    'include': bytearray([0x28, 0x02]),
    'characteristic': bytearray([0x28, 0x03]),
}
gatt_characteristic_descriptor_uuid = {
    'characteristic_extended_properties': bytearray([0x29, 0x00]),
    'characteristic_user_description': bytearray([0x29, 0x01]),
    'client_characteristic_configuration': bytearray([0x29, 0x02]),
    'server_characteristic_configuration': bytearray([0x29, 0x03]),
    'characteristic_format': bytearray([0x29, 0x04]),
    'characteristic_aggregate_format': bytearray([0x29, 0x05]),
}
gatt_characteristic_type_uuid = {
    'device_name': bytearray([0x2A, 0x00]),
    'appearance': bytearray([0x2A, 0x01]),
    'peripheral_privacy_flag': bytearray([0x2A, 0x02]),
    'reconnection_address': bytearray([0x2A, 0x03]),
    'peripheral_preferred_connection_parameters': bytearray([0x2A, 0x04]),
    'service_changed': bytearray([0x2A, 0x05]),
}
