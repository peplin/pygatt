# BGLib
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
