import asyncio
import logging
import struct
from typing import Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..const.common import ScreenLogicConnectionError
from ..const.msg import CODE, COM_MAX_RETRIES, COM_TIMEOUT
from .protocol import ScreenLogicProtocol
from .request import async_make_request
from .utility import asyncio_timeout, decodeMessageString, encodeMessageString

_LOGGER = logging.getLogger(__name__)


def _slack_for_alignment(length: int) -> int:
    """Return ScreenLogic padding for 4-byte alignment."""
    return (4 - length % 4) % 4


def _encode_sl_array(value: bytes) -> bytes:
    """Encode a ScreenLogic byte array."""
    return struct.pack("<i", len(value)) + value + (b"\x00" * _slack_for_alignment(len(value)))


def _zero_pad_to_block(value: str) -> bytes:
    """Zero-pad a string to an AES block boundary."""
    raw = value.encode("latin-1")
    blocks = ((len(raw) // 16) + (1 if len(raw) % 16 else 0)) * 16
    if blocks == 0:
        blocks = 16
    return raw + (b"\x00" * (blocks - len(raw)))


def _encrypt_password_first_block(password: str, challenge: str) -> bytes:
    """Encrypt the remote password challenge.

    ScreenLogic remote login matches node-screenlogic behavior:
    AES-ECB with a zero-padded password key and zero-padded challenge plaintext,
    with only the first encrypted block sent in the login message.
    """
    key = _zero_pad_to_block(password)
    plaintext = _zero_pad_to_block(challenge)

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encrypted = encryptor.update(plaintext) + encryptor.finalize()
    return encrypted[:16]


def create_login_message(
    password: str | None = None, challenge: str | None = None
) -> bytes:
    # these constants are only for this message.
    schema = 348
    connectionType = 0
    clientVersion = encodeMessageString(
        "node-screenlogic" if password is not None and challenge is not None else "Android"
    )
    pid = 2

    if password is not None and challenge is not None:
        passwd = _encode_sl_array(_encrypt_password_first_block(password, challenge))
    else:
        local_password = "0000000000000000"  # passwd must be <= 16 chars. empty is not OK.
        passwd = encodeMessageString(local_password)

    fmt = f"<II{len(clientVersion)}s{len(passwd)}sxI"
    return struct.pack(fmt, schema, connectionType, clientVersion, passwd, pid)


async def async_get_mac_address(
    gateway_ip: str, gateway_port: int, max_retries: int = COM_MAX_RETRIES
) -> str:
    """Connect to a screenlogic gateway and return the mac address only."""
    transport, protocol = await async_create_connection(gateway_ip, gateway_port)
    mac = await async_gateway_connect(transport, protocol, max_retries)
    if transport and not transport.is_closing():
        transport.close()
    return mac


async def async_create_connection(
    gateway_ip: str, gateway_port: int, connection_lost_callback: Callable = None
) -> tuple[asyncio.Transport, ScreenLogicProtocol]:
    try:
        loop = asyncio.get_running_loop()

        # on_con_lost = loop.create_future()
        _LOGGER.debug("Creating connection")
        async with asyncio_timeout(COM_TIMEOUT):
            return await loop.create_connection(
                lambda: ScreenLogicProtocol(loop, connection_lost_callback),
                gateway_ip,
                gateway_port,
            )
    except asyncio.TimeoutError as to_ex:
        _LOGGER.debug("Timeout attempting to connect to host")
        raise ScreenLogicConnectionError(
            f"Failed to connect to host at {gateway_ip}:{gateway_port}"
        ) from to_ex
    except OSError as os_ex:
        _LOGGER.debug(f"Error attempting to connect to host: {str(os_ex)}")
        raise ScreenLogicConnectionError(
            f"Failed to connect to host at {gateway_ip}:{gateway_port}"
        ) from os_ex


async def async_gateway_connect(
    transport: asyncio.Transport, protocol: ScreenLogicProtocol, max_retries: int
) -> str:
    connectString = b"CONNECTSERVERHOST\r\n\r\n"  # as bytes, not string
    try:
        # Connect ping
        _LOGGER.debug("Pinging protocol adapter")
        transport.write(connectString)
    except Exception as ex:
        raise ScreenLogicConnectionError("Error sending connect ping") from ex

    await asyncio.sleep(0.25)
    if not protocol.is_connected:
        raise ScreenLogicConnectionError("Host unexpectedly disconnected.")

    _LOGGER.debug("Sending challenge")
    # mac address
    return decodeMessageString(
        await async_make_request(
            protocol, CODE.CHALLENGE_QUERY, max_retries=max_retries
        )
    )


async def async_gateway_login(
    protocol: ScreenLogicProtocol,
    max_retries: int,
    password: str | None = None,
    challenge: str | None = None,
) -> bool:
    _LOGGER.debug("Logging in")
    return (
        await async_make_request(
            protocol,
            CODE.LOCALLOGIN_QUERY,
            create_login_message(password, challenge),
            max_retries,
        )
        is not None
    )


async def async_connect_to_gateway(
    gateway_ip,
    gateway_port,
    connection_lost_callback: Callable = None,
    max_retries: int = COM_MAX_RETRIES,
    password: str | None = None,
    remote: bool = False,
) -> tuple[asyncio.Transport, ScreenLogicProtocol, str] | None:
    transport, protocol = await async_create_connection(
        gateway_ip, gateway_port, connection_lost_callback
    )
    mac_address = await async_gateway_connect(transport, protocol, max_retries)
    challenge = mac_address if remote else None

    if await async_gateway_login(protocol, max_retries, password, challenge):
        return transport, protocol, mac_address

    if transport and not transport.is_closing():
        transport.close()
    return None
