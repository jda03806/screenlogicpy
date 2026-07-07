"""Tests for screenlogicpy/requests/remote.py."""

import struct

import pytest

from screenlogicpy.requests.remote import RemoteGatewayInfo, decode_remote_gateway
from screenlogicpy.requests.utility import encodeMessageString


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_dispatcher_response(
    gateway_found: bool,
    license_ok: bool,
    ip_addr: str,
    port: int,
    port_open: bool,
    relay_on: bool,
) -> bytes:
    """Construct a synthetic dispatcher response buffer matching the wire format."""
    buf = struct.pack("BB", int(gateway_found), int(license_ok))
    buf += encodeMessageString(ip_addr)
    buf += struct.pack("<HBB", port, int(port_open), int(relay_on))
    return buf


# ---------------------------------------------------------------------------
# decode_remote_gateway tests
# ---------------------------------------------------------------------------

def test_decode_remote_gateway_found():
    """Successful gateway lookup populates all fields correctly."""
    buf = _build_dispatcher_response(
        gateway_found=True,
        license_ok=True,
        ip_addr="192.168.1.50",
        port=80,
        port_open=True,
        relay_on=False,
    )
    info = decode_remote_gateway(buf)
    assert isinstance(info, RemoteGatewayInfo)
    assert info.gateway_found is True
    assert info.license_ok is True
    assert info.ip_addr == "192.168.1.50"
    assert info.port == 80
    assert info.port_open is True
    assert info.relay_on is False


def test_decode_remote_gateway_not_found():
    """Dispatcher reports gateway not found — all flags false, port zero."""
    buf = _build_dispatcher_response(
        gateway_found=False,
        license_ok=False,
        ip_addr="0.0.0.0",
        port=0,
        port_open=False,
        relay_on=False,
    )
    info = decode_remote_gateway(buf)
    assert info.gateway_found is False
    assert info.license_ok is False
    assert info.port == 0


def test_decode_remote_gateway_relay_on():
    """relay_on flag is decoded correctly when set."""
    buf = _build_dispatcher_response(
        gateway_found=True,
        license_ok=True,
        ip_addr="10.0.0.1",
        port=8080,
        port_open=True,
        relay_on=True,
    )
    info = decode_remote_gateway(buf)
    assert info.relay_on is True
    assert info.port == 8080


def test_decode_remote_gateway_non_standard_port():
    """Non-standard port values round-trip correctly."""
    for port in (443, 1024, 65535):
        buf = _build_dispatcher_response(True, True, "1.2.3.4", port, True, False)
        info = decode_remote_gateway(buf)
        assert info.port == port, f"port {port} did not round-trip"


def test_decode_remote_gateway_returns_bools():
    """Boolean fields are Python bools, not raw ints."""
    buf = _build_dispatcher_response(True, True, "1.2.3.4", 80, True, False)
    info = decode_remote_gateway(buf)
    assert type(info.gateway_found) is bool
    assert type(info.license_ok) is bool
    assert type(info.port_open) is bool
    assert type(info.relay_on) is bool


def test_decode_remote_gateway_long_ip():
    """IP address strings of normal length parse correctly."""
    buf = _build_dispatcher_response(True, True, "255.255.255.255", 80, True, False)
    info = decode_remote_gateway(buf)
    assert info.ip_addr == "255.255.255.255"
