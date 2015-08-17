from binascii import unhexlify


def uuid_to_bytearray(uuid_str):
    """Convert a UUID string to a bytearray."""
    return unhexlify(uuid_str.replace('-', ''))
