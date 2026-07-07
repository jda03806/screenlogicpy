import struct
from datetime import datetime, timezone

import pytest

from screenlogicpy.requests.utility import (
    decodeMessageTime,
    encodeMessageBytes,
    encodeMessageString,
    encodeMessageTime,
)


def test_encode_decode_time():
    time = datetime(2023, 11, 19, 18, 15, 36, 175759, tzinfo=timezone.utc)
    data = encodeMessageTime(time)
    assert data == b"\xe7\x07\x0b\x00\x06\x00\x13\x00\x12\x00\x0f\x00\x00\x00\xaf\x00"
    assert decodeMessageTime(data) == datetime(
        2023, 11, 19, 18, 15, 0, 175000, tzinfo=timezone.utc
    )


def test_encode_message_bytes_length_header():
    """Length field in the 4-byte header matches the raw data length."""
    data = b"\x01\x02\x03\x04"
    result = encodeMessageBytes(data)
    (length,) = struct.unpack_from("<I", result)
    assert length == 4


def test_encode_message_bytes_no_padding_needed():
    """Input already a multiple of 4 — no padding bytes added."""
    data = b"A" * 16
    result = encodeMessageBytes(data)
    # 4-byte header + 16 bytes data + 0 padding
    assert len(result) == 20


def test_encode_message_bytes_padding_added():
    """Input not a multiple of 4 — padded up to next multiple."""
    data = b"A" * 14
    result = encodeMessageBytes(data)
    # 4-byte header + 14 bytes data + 2 bytes padding = 20
    assert len(result) == 20
    # Padding bytes are zero
    assert result[-2:] == b"\x00\x00"


def test_encode_message_bytes_one_byte_input():
    """Single byte input is padded to 4 bytes."""
    result = encodeMessageBytes(b"X")
    assert len(result) == 8
    assert result[-3:] == b"\x00\x00\x00"


def test_encode_message_bytes_empty():
    """Empty input produces only the 4-byte length header (length=0)."""
    result = encodeMessageBytes(b"")
    assert len(result) == 4
    (length,) = struct.unpack_from("<I", result)
    assert length == 0


def test_encode_message_bytes_matches_encode_message_string():
    """encodeMessageBytes on UTF-8 encoded text must match encodeMessageString."""
    for text in ("Android", "node-screenlogic", "Pentair: 12-AB-34"):
        assert encodeMessageBytes(text.encode()) == encodeMessageString(text), (
            f"mismatch for {text!r}"
        )
