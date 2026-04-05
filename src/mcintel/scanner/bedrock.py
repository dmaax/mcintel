"""
mcintel.scanner.bedrock
~~~~~~~~~~~~~~~~~~~~~~~
Minecraft Bedrock Edition server ping via the RakNet Unconnected Ping protocol.

Protocol reference
------------------
  https://wiki.vg/Raknet_Protocol#Unconnected_Ping
  https://wiki.vg/Bedrock_Protocol

Packet flow
-----------
  C → S  0x01  Unconnected Ping
               ┌─────────────────────────────────────────────────────────┐
               │ 0x01 (1B) │ timestamp int64 (8B) │ magic (16B) │ GUID (8B) │
               └─────────────────────────────────────────────────────────┘

  S → C  0x1C  Unconnected Pong
               ┌─────────────────────────────────────────────────────────────────┐
               │ 0x1C (1B) │ timestamp int64 (8B) │ server GUID int64 (8B)        │
               │ magic (16B) │ string length uint16 (2B) │ MOTD string (N bytes)  │
               └─────────────────────────────────────────────────────────────────┘

  The MOTD string (Bedrock advertisement) is semicolon-delimited:
    MCPE;<motd>;<protocol>;<version>;<online>;<max>;<guid>;<sub_motd>;<gamemode>;<gamemode_int>;<port_v4>;<port_v6>

Usage
-----
    from mcintel.scanner.bedrock import ping_bedrock

    result = await ping_bedrock("play.example.com", port=19132, timeout=5.0)
    if result.success:
        print(result.motd_clean, result.players_online, result.version_name)
    else:
        print("offline:", result.error)
"""

from __future__ import annotations

import asyncio
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from mcintel.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default Bedrock port
DEFAULT_PORT: int = 19132

# Default timeout (seconds)
_DEFAULT_TIMEOUT: float = 5.0

# Maximum UDP datagram size we will accept for the pong (32 KB is generous)
_MAX_DATAGRAM_SIZE: int = 32 * 1024

# RakNet "offline message data ID" — the 16-byte magic that identifies
# unconnected RakNet messages.
_RAKNET_MAGIC: bytes = bytes(
    [
        0x00,
        0xFF,
        0xFF,
        0x00,
        0xFE,
        0xFE,
        0xFE,
        0xFE,
        0xFD,
        0xFD,
        0xFD,
        0xFD,
        0x12,
        0x34,
        0x56,
        0x78,
    ]
)

# Packet IDs
_PKT_UNCONNECTED_PING: int = 0x01
_PKT_UNCONNECTED_PING_OPEN: int = 0x02  # same format, open-connections variant
_PKT_UNCONNECTED_PONG: int = 0x1C

# Advertisement prefix used by Bedrock servers
_BEDROCK_PREFIX: str = "MCPE"
# Pocket Edition servers also use "MCEE" (Education Edition)
_BEDROCK_PREFIXES: frozenset[str] = frozenset({"MCPE", "MCEE"})

# Well-known Bedrock game mode strings
_GAMEMODE_MAP: dict[str, str] = {
    "0": "Survival",
    "1": "Creative",
    "2": "Adventure",
    "3": "Spectator",
    "Survival": "Survival",
    "Creative": "Creative",
    "Adventure": "Adventure",
    "Spectator": "Spectator",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class BedrockResult:
    """
    The result of a Bedrock Edition server ping.

    ``success`` is True if the server responded with a valid pong.
    All other fields are None / empty on failure.
    """

    host: str
    port: int

    # ── Status ───────────────────────────────────────────────────────────────
    success: bool = False
    latency_ms: float | None = None
    error: str | None = None

    # ── Version ───────────────────────────────────────────────────────────────
    version_name: str | None = None  # e.g. "1.21.50"
    version_protocol: int | None = None  # protocol number

    # ── Players ───────────────────────────────────────────────────────────────
    players_online: int | None = None
    players_max: int | None = None

    # ── MOTD (two lines on Bedrock) ───────────────────────────────────────────
    motd_raw: str | None = None  # raw advertisement string
    motd_clean: str | None = None  # first line, stripped
    motd_sub: str | None = None  # second MOTD line (sub-title)

    # ── Server info ───────────────────────────────────────────────────────────
    server_guid: int | None = None
    gamemode: str | None = None  # "Survival", "Creative", etc.
    ipv4_port: int | None = None
    ipv6_port: int | None = None
    # "bedrock" or "education"
    edition: str = "bedrock"

    # ── Address helper ────────────────────────────────────────────────────────
    @property
    def address(self) -> str:
        if self.port == DEFAULT_PORT:
            return self.host
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict suitable for JSON or DB storage."""
        return {
            "host": self.host,
            "port": self.port,
            "success": self.success,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "edition": self.edition,
            "version_name": self.version_name,
            "version_protocol": self.version_protocol,
            "players_online": self.players_online,
            "players_max": self.players_max,
            "motd_clean": self.motd_clean,
            "motd_sub": self.motd_sub,
            "motd_raw": self.motd_raw,
            "server_guid": self.server_guid,
            "gamemode": self.gamemode,
            "ipv4_port": self.ipv4_port,
            "ipv6_port": self.ipv6_port,
        }


# ---------------------------------------------------------------------------
# Packet builders
# ---------------------------------------------------------------------------


def _build_unconnected_ping(timestamp_ms: int, client_guid: int) -> bytes:
    """
    Build a RakNet Unconnected Ping datagram.

      Byte 0    : 0x01 (packet ID)
      Bytes 1–8 : timestamp (int64 big-endian, milliseconds)
      Bytes 9–24: magic (16 bytes)
      Bytes 25–32: client GUID (int64 big-endian)
    """
    return (
        struct.pack(">B", _PKT_UNCONNECTED_PING)
        + struct.pack(">q", timestamp_ms)
        + _RAKNET_MAGIC
        + struct.pack(">q", client_guid)
    )


# ---------------------------------------------------------------------------
# Pong parser
# ---------------------------------------------------------------------------


def _parse_pong(data: bytes, result: BedrockResult) -> None:
    """
    Parse a RakNet Unconnected Pong datagram and populate *result*.

    Pong layout:
      Byte 0     : 0x1C (packet ID)
      Bytes 1–8  : echo timestamp (int64 big-endian)
      Bytes 9–16 : server GUID (int64 big-endian)
      Bytes 17–32: magic (16 bytes)
      Bytes 33–34: string length (uint16 big-endian)
      Bytes 35+  : advertisement string (UTF-8)

    Raises ``ValueError`` on structural errors.
    """
    if len(data) < 35:
        raise ValueError(f"Pong datagram too short: {len(data)} bytes")

    if data[0] != _PKT_UNCONNECTED_PONG:
        raise ValueError(f"Expected pong (0x1C), got 0x{data[0]:02X}")

    # Server GUID
    server_guid = struct.unpack(">q", data[9:17])[0]
    result.server_guid = server_guid

    # Magic check
    pong_magic = data[17:33]
    if pong_magic != _RAKNET_MAGIC:
        log.debug(
            "Pong magic mismatch (continuing anyway)",
            expected=_RAKNET_MAGIC.hex(),
            got=pong_magic.hex(),
        )

    # Advertisement string
    str_len = struct.unpack(">H", data[33:35])[0]
    if 35 + str_len > len(data):
        # Some servers omit/truncate — read what we have
        str_len = len(data) - 35

    adv_bytes = data[35 : 35 + str_len]
    adv_str = adv_bytes.decode("utf-8", errors="replace")

    result.motd_raw = adv_str
    _parse_advertisement(adv_str, result)


def _parse_advertisement(adv: str, result: BedrockResult) -> None:
    """
    Parse the semicolon-delimited Bedrock advertisement string.

    Expected fields (indices):
      0   Edition      — "MCPE" or "MCEE"
      1   MOTD line 1
      2   Protocol version
      3   Version name
      4   Players online
      5   Players max
      6   Server GUID (redundant with pong header)
      7   Sub-MOTD / level name
      8   Game mode string
      9   Game mode integer
      10  IPv4 port
      11  IPv6 port

    Fields after index 5 are optional — older server versions may omit them.
    """
    parts = adv.split(";")

    if not parts:
        result.error = "Empty advertisement string"
        return

    edition = parts[0].strip()
    if edition not in _BEDROCK_PREFIXES:
        # Not a recognised Bedrock advertisement, but keep going
        log.debug("Unexpected Bedrock edition prefix", prefix=edition)

    result.edition = "education" if edition == "MCEE" else "bedrock"

    # MOTD line 1
    if len(parts) > 1:
        result.motd_clean = parts[1].strip()

    # Protocol version
    if len(parts) > 2:
        try:
            result.version_protocol = int(parts[2])
        except ValueError:
            pass

    # Version name
    if len(parts) > 3:
        result.version_name = parts[3].strip() or None

    # Players online
    if len(parts) > 4:
        try:
            result.players_online = int(parts[4])
        except ValueError:
            pass

    # Players max
    if len(parts) > 5:
        try:
            result.players_max = int(parts[5])
        except ValueError:
            pass

    # Sub-MOTD (level name / second line)
    if len(parts) > 7:
        result.motd_sub = parts[7].strip() or None

    # Game mode
    if len(parts) > 8:
        gm_raw = parts[8].strip()
        result.gamemode = _GAMEMODE_MAP.get(gm_raw, gm_raw) or None

    # Numeric game mode as fallback
    if result.gamemode is None and len(parts) > 9:
        gm_num = parts[9].strip()
        result.gamemode = _GAMEMODE_MAP.get(gm_num)

    # IPv4 port
    if len(parts) > 10:
        try:
            result.ipv4_port = int(parts[10])
        except ValueError:
            pass

    # IPv6 port
    if len(parts) > 11:
        try:
            result.ipv6_port = int(parts[11])
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Async UDP transport helper
# ---------------------------------------------------------------------------


class _UdpProtocol(asyncio.DatagramProtocol):
    """
    Minimal asyncio DatagramProtocol that stores the first datagram received
    and signals a Future when it arrives (or when an error occurs).
    """

    def __init__(self, future: asyncio.Future[bytes]) -> None:
        self._future = future

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self._future.done():
            self._future.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self._future.done():
            if exc:
                self._future.set_exception(exc)
            else:
                self._future.set_exception(
                    ConnectionResetError("UDP connection closed without response")
                )


# ---------------------------------------------------------------------------
# Core ping function
# ---------------------------------------------------------------------------


async def ping_bedrock(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = _DEFAULT_TIMEOUT,
) -> BedrockResult:
    """
    Ping a Minecraft Bedrock Edition server using the RakNet Unconnected Ping.

    Parameters
    ----------
    host:
        Hostname or IP address of the Bedrock server.
    port:
        UDP port (default 19132).
    timeout:
        Seconds to wait for a response datagram before giving up.

    Returns
    -------
    BedrockResult
        Always returns a result object.  Check ``result.success`` to
        determine whether the ping succeeded.
    """
    result = BedrockResult(host=host, port=port)

    log.debug("Pinging Bedrock server", host=host, port=port, timeout=timeout)

    # Generate a random client GUID for this session
    client_guid = struct.unpack(">q", os.urandom(8))[0]
    timestamp_ms = int(time.time() * 1000) & 0x7FFFFFFFFFFFFFFF

    ping_data = _build_unconnected_ping(timestamp_ms, client_guid)

    loop = asyncio.get_running_loop()
    pong_future: asyncio.Future[bytes] = loop.create_future()

    transport: asyncio.BaseTransport | None = None
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpProtocol(pong_future),
            remote_addr=(host, port),
        )

        t_send = time.perf_counter()
        transport.sendto(ping_data)  # type: ignore[attr-defined]

        pong_data = await asyncio.wait_for(pong_future, timeout=timeout)
        t_recv = time.perf_counter()

        result.latency_ms = round((t_recv - t_send) * 1000, 2)

        _parse_pong(pong_data, result)
        result.success = True

        log.info(
            "Bedrock ping successful",
            host=host,
            port=port,
            version=result.version_name,
            online=result.players_online,
            max_players=result.players_max,
            latency_ms=result.latency_ms,
            gamemode=result.gamemode,
        )

    except asyncio.TimeoutError:
        result.error = f"No response within {timeout}s (server may be offline or UDP is blocked)"
        log.debug("Bedrock ping timed out", host=host, port=port)

    except OSError as exc:
        result.error = f"Network error: {exc}"
        log.debug("Bedrock ping network error", host=host, port=port, error=str(exc))

    except ValueError as exc:
        result.error = f"Protocol parse error: {exc}"
        log.debug("Bedrock ping parse error", host=host, port=port, error=str(exc))

    except Exception as exc:
        result.error = f"Unexpected error: {exc}"
        log.debug("Bedrock ping unexpected error", host=host, port=port, error=str(exc))

    finally:
        if transport is not None:
            transport.close()

    return result


# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------


async def ping_bedrock_many(
    targets: list[tuple[str, int]],
    timeout: float = _DEFAULT_TIMEOUT,
    max_concurrency: int = 50,
) -> list[BedrockResult]:
    """
    Ping multiple Bedrock servers concurrently with a bounded semaphore.

    Parameters
    ----------
    targets:
        List of ``(host, port)`` tuples.
    timeout:
        Per-ping timeout in seconds.
    max_concurrency:
        Maximum number of simultaneous ping coroutines.

    Returns
    -------
    List of ``BedrockResult`` in the same order as *targets*.
    """
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded(host: str, port: int) -> BedrockResult:
        async with semaphore:
            return await ping_bedrock(host, port, timeout)

    tasks = [_bounded(h, p) for h, p in targets]
    return list(await asyncio.gather(*tasks))
