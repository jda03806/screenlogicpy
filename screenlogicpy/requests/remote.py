"""Remote dispatcher support for Pentair ScreenLogic."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import struct

from ..const.common import ScreenLogicConnectionError
from ..const.msg import HEADER_FORMAT, HEADER_LENGTH
from .utility import encodeMessageString, getString, makeMessage


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


async def _read_message(reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
    """Read one ScreenLogic protocol message."""
    header = await reader.readexactly(HEADER_LENGTH)
    sender_id, action, payload_len = struct.unpack_from(HEADER_FORMAT, header)
    payload = await reader.readexactly(payload_len) if payload_len else b""
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
        payload = encodeMessageString(system_name) + encodeMessageString(system_name)
        writer.write(makeMessage(0, ACTION_GATEWAY_REQUEST, payload))
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
        ip_addr, offset = getString(response, offset)
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
