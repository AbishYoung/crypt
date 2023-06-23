# File format
#
# 1. 4 bytes: magic number (00-03)
# 2. 4 bytes: version number (04-07)
# 3. 16 bytes: iv (08-23)
# 4. 16 bytes: tag (24-39)
# 5. 16 bytes: salt (40-55)
# 5. variable: encrypted data (56-EOF)

import struct


def generate_header(iv: bytes, tag: bytes, salt) -> bytes:
    """Generate header for archive file"""
    return struct.pack("!4s4s16s16s16s", b"CRYP", b"0001", iv, tag, salt)


def generate_body(data: bytes) -> bytes:
    """Generate body for archive file"""
    return struct.pack(f"!{len(data)}s", data)


def generate_archive(iv: bytes, tag: bytes, salt: bytes, data: bytes) -> bytes:
    """Generate archive file"""
    return generate_header(iv, tag, salt) + generate_body(data)


def parse_header(header: bytes) -> tuple[bytes, bytes, bytes]:
    """Parse header of archive file"""
    data = struct.unpack("!4s4s16s16s16s", header)
    return data[2], data[3], data[4]


def parse_body(body: bytes) -> bytes:
    """Parse body of archive file"""
    return struct.unpack(f"!{len(body)}s", body)[0]


def parse_archive(archive: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Parse archive file"""
    header: bytes = archive[:56]
    body: bytes = archive[56:]
    header: tuple[bytes, bytes, bytes] = parse_header(header)
    body: bytes = parse_body(body)
    iv: bytes = header[0]
    tag: bytes = header[1]
    salt: bytes = header[2]
    return iv, tag, salt, body
