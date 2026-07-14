import struct
from enum import Enum
from typing import NamedTuple, Tuple

HEADER_FORMAT = ">Q B H H"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class PACKET_TYPE(Enum):
    REQUEST = 1
    RESPONSE = 2
    RETRY = 3
    NACK = 4


class Header(NamedTuple):
    id: int
    packet_type: int
    fec_block_id: int
    payload_len: int


def pack_frame(id: int, packet_type: int, fec_block_id: int, payload: bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, id, packet_type, fec_block_id, len(payload))
    return header + payload


def unpack_frame(frame: bytes) -> Tuple[Header, bytes]:
    if len(frame) < HEADER_SIZE:
        raise ValueError("Invalid packet: Size is smaller than header")

    header_section = frame[:HEADER_SIZE]
    payload_section = frame[HEADER_SIZE:]

    unpacked_header = struct.unpack(HEADER_FORMAT, header_section)
    header = Header(
        id=unpacked_header[0],
        packet_type=header[1],
        fec_block_id=header[2],
        payload_len=header[3],
    )

    return header, payload_section[: header.payload_len]
