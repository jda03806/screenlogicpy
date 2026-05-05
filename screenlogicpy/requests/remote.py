"""Remote dispatcher support for Pentair ScreenLogic."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import struct

from ..const.common import ScreenLogicConnectionError


DISPATCHER_HOST = "screenlogicserver.pentair.com"
DISPATCHER_PORT = 500

ACTION_GATEWAY_REQUEST = 18003
ACTION_GATEWAY_RESPONSE = 18004


@dataclass(slots=True)
class RemoteGatewayInfo:
    """Remote dispatcher response."""

    gateway_found: bool
    license_ok: bool
    ip_addr: str
    port: int
    port_open: bool
    relay_on: bool


def _slack_for_alignment(length: int) -> int:
    """Return ScreenLogic padding for 4-byte alignment."""
    return (4 - length % 4) % 4


def _sl_string(value: str) -> bytes:
    """Encode a ScreenLogic string."""
    data = value.encode("latin-1")
    return struct.pack("<i", len(data)) + data + (b"\x00" * _slack_for_alignment(len(data)))


def _read_sl_string(payload: bytes, offset: int) -> tuple[str, int]:
    """Decode a ScreenLogic string from payload at offset."""
    (length,) = struct.unpack_from("<i", payload, offset)
    offset += 4
    value = payload[offset : offset + length].decode("latin-1")
    offset += length + _slack_for_alignment(length)
    return value, offset


def _make_message(action: int, payload: bytes = b"", sender_id: int = 0) -> bytes:
    """Create a ScreenLogic protocol message."""
    return struct.pack("<HHi", sender_id, action, len(payload)) + payload


async def _read_exact(reader: asyncio.StreamReader, length: int) -> bytes:
    """Read exactly length bytes."""
    return await reader.readexactly(length)


async def _read_message(reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
    """Read one ScreenLogic protocol message."""
    header = await _read_exact(reader, 8)
    sender_id, action, payload_len = struct.unpack("<HHi", header)
    payload = await _read_exact(reader, payload_len) if payload_len else b""
    return sender_id, action, payload


async def async_resolve_remote_gateway(system_name: str) -> RemoteGatewayInfo:
    """Resolve a ScreenLogic system name through Pentair's remote dispatcher.

    Example system name format: "Pentair: 12-AB-34".
    """
    try:
        reader, writer = await asyncio.open_connection(DISPATCHER_HOST, DISPATCHER_PORT)
    except OSError as ex:
        raise ScreenLogicConnectionError(
            f"Failed to connect to remote dispatcher at {DISPATCHER_HOST}:{DISPATCHER_PORT}"
        ) from ex

    try:
        payload = _sl_string(system_name) + _sl_string(system_name)
        writer.write(_make_message(ACTION_GATEWAY_REQUEST, payload))
        await writer.drain()

        _sender_id, action, response = await _read_message(reader)
        if action != ACTION_GATEWAY_RESPONSE:
            raise ScreenLogicConnectionError(
                f"Unexpected remote dispatcher response action {action}"
            )

        offset = 0
        gateway_found = response[offset] != 0
        offset += 1
        license_ok = response[offset] != 0
        offset += 1
        ip_addr, offset = _read_sl_string(response, offset)
        (port,) = struct.unpack_from("<H", response, offset)
        offset += 2
        port_open = response[offset] != 0
        offset += 1
        relay_on = response[offset] != 0

        return RemoteGatewayInfo(
            gateway_found=gateway_found,
            license_ok=license_ok,
            ip_addr=ip_addr,
            port=port,
            port_open=port_open,
            relay_on=relay_on,
        )
    except (asyncio.IncompleteReadError, OSError) as ex:
        raise ScreenLogicConnectionError("Failed to read remote dispatcher response") from ex
    finally:
        writer.close()
        await writer.wait_closed()
