import struct


def unsigned_short(value):
    return struct.pack('!H', value)


def unsigned_char(value):
    return struct.pack('!B', value)


def Bool(value):
    return struct.pack('!?', value)
