"""Remote dispatcher support for Pentair ScreenLogic."""

from __future__ import annotations

from dataclasses import dataclass

from ..const.common import ScreenLogicConnectionError
from ..const.msg import CODE, COM_MAX_RETRIES
from .login import async_create_connection
from .protocol import ScreenLogicProtocol
from .request import async_make_request
from .utility import encodeMessageString, getSome, getString


DISPATCHER_HOST = "screenlogicserver.pentair.com"
DISPATCHER_PORT = 500


@dataclass(slots=True)
class RemoteGatewayInfo:
    """Remote dispatcher response."""

    gateway_found: bool
    license_ok: bool
    ip_addr: str
    port: int
    port_open: bool
    relay_on: bool


async def async_request_remote_gateway(
    protocol: ScreenLogicProtocol, system_name: str, max_retries: int
) -> bytes:
    """Send a gateway-data request to the remote dispatcher and return raw response bytes.

    The dispatcher request payload contains the system name twice, once as the
    gatewayType field and once as the gatewayName field, matching the wire format
    expected by Pentair's remote dispatcher.

    Example system name format: "Pentair: 12-AB-34".
    """
    payload = encodeMessageString(system_name) + encodeMessageString(system_name)
    return await async_make_request(
        protocol, CODE.GATEWAYDATA_QUERY, payload, max_retries
    )


def decode_remote_gateway(buff: bytes) -> RemoteGatewayInfo:
    """Decode a raw dispatcher response buffer into a RemoteGatewayInfo.

    Dispatcher response wire layout:
      1 byte  - gateway_found (bool)
      1 byte  - license_ok (bool)
      string  - ip_addr (ScreenLogic length-prefixed, 4-byte aligned)
      2 bytes - port (uint16, little-endian)
      1 byte  - port_open (bool)
      1 byte  - relay_on (bool)
    """
    gateway_found, offset = getSome("B", buff, 0)
    license_ok, offset = getSome("B", buff, offset)
    ip_addr, offset = getString(buff, offset)
    port, offset = getSome("H", buff, offset)
    port_open, offset = getSome("B", buff, offset)
    relay_on, offset = getSome("B", buff, offset)

    return RemoteGatewayInfo(
        gateway_found=bool(gateway_found),
        license_ok=bool(license_ok),
        ip_addr=ip_addr,
        port=port,
        port_open=bool(port_open),
        relay_on=bool(relay_on),
    )


async def async_resolve_remote_gateway(
    system_name: str, max_retries: int = COM_MAX_RETRIES
) -> RemoteGatewayInfo:
    """Resolve a ScreenLogic system name through Pentair's remote dispatcher.

    Connects to the Pentair remote dispatcher, sends a GATEWAYDATA_QUERY for
    the given system name, and returns the parsed RemoteGatewayInfo. The
    dispatcher uses the same ScreenLogic binary message protocol as the pool
    gateway, so the standard ScreenLogicProtocol and async_make_request
    machinery are used directly.

    Example system name format: "Pentair: 12-AB-34".
    """
    transport, protocol = await async_create_connection(DISPATCHER_HOST, DISPATCHER_PORT)
    try:
        result = await async_request_remote_gateway(protocol, system_name, max_retries)
        if result is None:
            raise ScreenLogicConnectionError(
                "No response from remote dispatcher"
            )
        return decode_remote_gateway(result)
    finally:
        if transport and not transport.is_closing():
            transport.close()
