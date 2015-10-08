from uuid import UUID


def uuid16_to_uuid(uuid16):
    return UUID("0000%04x-0000-1000-8000-00805F9B34FB" % uuid16)
