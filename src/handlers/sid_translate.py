import struct

def binary_sid_to_string(sid):
    revision, sub_authority_count = struct.unpack_from("BB", sid, 0)
    identifier_authority = struct.unpack_from(">Q", b"\x00\x00" + sid[2:8])[0]
    sub_authorities = struct.unpack_from(f"<{sub_authority_count}I", sid, 8)

    sid_string = f"S-{revision}-{identifier_authority}"
    for sub_authority in sub_authorities:
        sid_string += f"-{sub_authority}"

    return sid_string