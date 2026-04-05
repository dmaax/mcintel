"""
mcintel.scanner.slp
~~~~~~~~~~~~~~~~~~~
Java Edition Server List Ping (SLP) implementation.

Supports:
  - Modern SLP (1.7+)  — Handshake → Status Request → Status Response → Ping/Pong
  - Legacy SLP (1.4–1.6) — 0xFE 0x01 ping with optional 1.6 extended payload
  - Automatic fallback: tries modern first, then legacy on failure

Protocol reference
------------------
  https://wiki.vg/Server_List_Ping
  https://wiki.vg/Protocol  (VarInt, String, packet framing)

Usage
-----
    from mcintel.scanner.slp import ping

    result = await ping("play.example.com", port=25565, timeout=5.0)
    if result.success:
        print(result.motd_clean, result.players_online, result.version_name)
    else:
        print("offline:", result.error)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any

from mcintel.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Protocol version sent in our Handshake packet.
# -1 means "requesting status" — most servers accept any value here.
_HANDSHAKE_PROTOCOL_VERSION = -1  # VarInt: will encode as 0xFF 0xFF 0xFF 0xFF 0x0F

# Default Minecraft Java port
DEFAULT_PORT: int = 25565

# Maximum JSON payload we are willing to read (4 MB)
_MAX_PAYLOAD_BYTES: int = 4 * 1024 * 1024

# Maximum character count accepted in a legacy kick packet response.
# A realistic MOTD + metadata is well under 500 chars; 4096 is very generous.
_MAX_LEGACY_CHAR_COUNT: int = 4096

# Legacy / modern timeout defaults (seconds)
_DEFAULT_TIMEOUT: float = 5.0

# § colour code stripper pattern
_SECTION_SIGN_RE = re.compile(r"§[0-9a-fk-or]", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Minecraft data types — VarInt
# ---------------------------------------------------------------------------


def _encode_varint(value: int) -> bytes:
    """Encode an integer as a Minecraft VarInt (up to 5 bytes)."""
    if value < 0:
        # VarInt is signed; handle negative numbers via two's complement (32-bit)
        value = value & 0xFFFFFFFF
    buf = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            part |= 0x80
        buf.append(part)
        if not value:
            break
    return bytes(buf)


def _decode_varint_from_bytes(data: bytes, offset: int = 0) -> tuple[int, int]:
    """
    Decode a VarInt starting at *offset* inside *data*.

    Returns ``(value, new_offset)`` where ``new_offset`` is the position
    immediately after the last byte of the VarInt.

    Raises ``ValueError`` if the VarInt is malformed or exceeds 5 bytes.
    """
    result = 0
    shift = 0
    for i in range(5):
        if offset + i >= len(data):
            raise ValueError("VarInt is truncated")
        byte = data[offset + i]
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, offset + i + 1
    raise ValueError("VarInt is too long (> 5 bytes)")


async def _read_varint(reader: asyncio.StreamReader) -> int:
    """Read a VarInt from an async stream reader."""
    result = 0
    shift = 0
    for _ in range(5):
        byte_data = await reader.readexactly(1)
        byte = byte_data[0]
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            # Sign-extend 32-bit signed integer
            if result & 0x80000000:
                result -= 0x100000000
            return result
    raise ValueError("VarInt exceeds 5 bytes")


def _encode_string(s: str) -> bytes:
    """Encode a UTF-8 string prefixed with its VarInt byte-length."""
    encoded = s.encode("utf-8")
    return _encode_varint(len(encoded)) + encoded


def _build_packet(packet_id: int, payload: bytes = b"") -> bytes:
    """
    Frame a Minecraft packet: VarInt(total_length) + VarInt(packet_id) + payload.
    """
    pid_bytes = _encode_varint(packet_id)
    inner = pid_bytes + payload
    return _encode_varint(len(inner)) + inner


# ---------------------------------------------------------------------------
# MOTD / Chat component parsing
# ---------------------------------------------------------------------------


def _chat_to_plain(obj: Any) -> str:
    """
    Recursively convert a Minecraft Chat component (dict, list, or string)
    to plain text, stripping all formatting.

    Handles:
      - Plain strings (including legacy § colour codes)
      - Chat component dicts with ``text`` / ``translate`` / ``extra``
      - Lists of components
    """
    if obj is None:
        return ""

    if isinstance(obj, str):
        return _SECTION_SIGN_RE.sub("", obj)

    if isinstance(obj, list):
        return "".join(_chat_to_plain(part) for part in obj)

    if isinstance(obj, dict):
        parts: list[str] = []

        # Primary text
        text = obj.get("text")
        if text is not None:
            parts.append(_SECTION_SIGN_RE.sub("", str(text)))

        # Translated text (just use the key as a fallback; full translation
        # would require a language file, which is out of scope for OSINT)
        translate = obj.get("translate")
        if translate and not text:
            parts.append(str(translate))

        # Extra / children
        extra = obj.get("extra")
        if extra:
            parts.append(_chat_to_plain(extra))

        return "".join(parts)

    return ""


def _parse_motd(description: Any) -> tuple[str, str]:
    """
    Parse the ``description`` field of an SLP JSON response.

    Returns ``(raw, clean)`` where:
      - ``raw``   is the JSON-serialised original (or the bare string)
      - ``clean`` is plain text with all formatting stripped
    """
    if description is None:
        return "", ""

    if isinstance(description, str):
        raw = description
        clean = _SECTION_SIGN_RE.sub("", description).strip()
        return raw, clean

    if isinstance(description, dict):
        raw = json.dumps(description, ensure_ascii=False)
        clean = _chat_to_plain(description).strip()
        return raw, clean

    if isinstance(description, list):
        raw = json.dumps(description, ensure_ascii=False)
        clean = _chat_to_plain(description).strip()
        return raw, clean

    raw = str(description)
    return raw, raw


# ---------------------------------------------------------------------------
# Favicon helpers
# ---------------------------------------------------------------------------


def _favicon_sha256(favicon_b64: str | None) -> str | None:
    """Return the SHA-256 hex digest of the raw favicon data URI bytes."""
    if not favicon_b64:
        return None
    try:
        # favicon_b64 is "data:image/png;base64,<base64-data>"
        b64_part = favicon_b64.split(",", 1)[-1]
        import base64

        raw = base64.b64decode(b64_part)
        return hashlib.sha256(raw).hexdigest()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Server software fingerprinting
# ---------------------------------------------------------------------------

# Ordered list of (pattern, software_name) for ``version.name`` matching.
# More specific patterns must come before more general ones.
_SOFTWARE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"waterfall", re.I), "Waterfall"),
    (re.compile(r"velocity", re.I), "Velocity"),
    (re.compile(r"bungeecord", re.I), "BungeeCord"),
    (re.compile(r"travertine", re.I), "Travertine"),
    (re.compile(r"geyser", re.I), "GeyserMC"),
    (re.compile(r"neoforge", re.I), "NeoForge"),
    (re.compile(r"forge", re.I), "Forge"),
    (re.compile(r"fabric", re.I), "Fabric"),
    (re.compile(r"quilt", re.I), "Quilt"),
    (re.compile(r"purpur", re.I), "Purpur"),
    (re.compile(r"pufferfish", re.I), "Pufferfish"),
    (re.compile(r"folia", re.I), "Folia"),
    (re.compile(r"paper", re.I), "Paper"),
    (re.compile(r"spigot", re.I), "Spigot"),
    (re.compile(r"craftbukkit", re.I), "CraftBukkit"),
    (re.compile(r"sponge(vanilla)?", re.I), "Sponge"),
    (re.compile(r"mohist", re.I), "Mohist"),
    (re.compile(r"arclight", re.I), "Arclight"),
    (re.compile(r"catserver", re.I), "CatServer"),
    (re.compile(r"vanilla", re.I), "Vanilla"),
]

_PROXY_SOFTWARE: frozenset[str] = frozenset({"BungeeCord", "Waterfall", "Travertine", "Velocity"})

_MODDED_SOFTWARE: frozenset[str] = frozenset(
    {"Forge", "NeoForge", "Fabric", "Quilt", "Sponge", "Mohist", "Arclight", "CatServer"}
)


def _fingerprint_software(
    version_name: str | None,
    has_mod_info: bool,
) -> tuple[str | None, bool, bool]:
    """
    Derive ``(software, is_modded, is_proxy)`` from the ``version.name`` field
    and whether mod metadata was present in the response.

    Returns ``(None, False, False)`` if no match is found.
    """
    if not version_name:
        return None, has_mod_info, False

    for pattern, name in _SOFTWARE_PATTERNS:
        if pattern.search(version_name):
            return name, has_mod_info or name in _MODDED_SOFTWARE, name in _PROXY_SOFTWARE

    return None, has_mod_info, False


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ModInfo:
    """A single mod / plugin reported by the server."""

    mod_id: str
    version: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"mod_id": self.mod_id, "version": self.version}


@dataclass
class PlayerSample:
    """An entry from the ``players.sample`` list."""

    uuid: str
    name: str

    def to_dict(self) -> dict[str, str]:
        return {"uuid": self.uuid, "name": self.name}


@dataclass
class SlpResult:
    """
    The result of an SLP query.

    ``success`` is True if the server responded correctly.
    All other fields are None / empty on failure.
    """

    host: str
    port: int

    # ── Status ───────────────────────────────────────────────────────────────
    success: bool = False
    # Latency measured as RTT to the Status Response packet (milliseconds)
    latency_ms: float | None = None
    # "modern" | "legacy" | None
    protocol_type: str | None = None
    error: str | None = None

    # ── Version ───────────────────────────────────────────────────────────────
    version_name: str | None = None
    version_protocol: int | None = None

    # ── Players ───────────────────────────────────────────────────────────────
    players_online: int | None = None
    players_max: int | None = None
    players_sample: list[PlayerSample] = field(default_factory=list)

    # ── MOTD ──────────────────────────────────────────────────────────────────
    motd_raw: str | None = None
    motd_clean: str | None = None

    # ── Favicon ───────────────────────────────────────────────────────────────
    favicon_b64: str | None = None
    favicon_hash: str | None = None  # SHA-256 hex

    # ── Software fingerprint ─────────────────────────────────────────────────
    software: str | None = None
    is_modded: bool = False
    is_proxy: bool = False

    # ── Mods ──────────────────────────────────────────────────────────────────
    mods: list[ModInfo] = field(default_factory=list)

    # ── Misc flags ────────────────────────────────────────────────────────────
    enforces_secure_chat: bool | None = None
    prevents_chat_reports: bool | None = None

    # ── Raw response ─────────────────────────────────────────────────────────
    raw_json: str | None = None

    # ── Address helper ────────────────────────────────────────────────────────
    @property
    def address(self) -> str:
        if self.port == DEFAULT_PORT:
            return self.host
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (suitable for JSON or DB storage)."""
        return {
            "host": self.host,
            "port": self.port,
            "success": self.success,
            "latency_ms": self.latency_ms,
            "protocol_type": self.protocol_type,
            "error": self.error,
            "version_name": self.version_name,
            "version_protocol": self.version_protocol,
            "players_online": self.players_online,
            "players_max": self.players_max,
            "players_sample": [p.to_dict() for p in self.players_sample],
            "motd_raw": self.motd_raw,
            "motd_clean": self.motd_clean,
            "favicon_hash": self.favicon_hash,
            "software": self.software,
            "is_modded": self.is_modded,
            "is_proxy": self.is_proxy,
            "mods": [m.to_dict() for m in self.mods],
            "enforces_secure_chat": self.enforces_secure_chat,
            "prevents_chat_reports": self.prevents_chat_reports,
        }


# ---------------------------------------------------------------------------
# Modern SLP (1.7+)
# ---------------------------------------------------------------------------


async def _ping_modern(
    host: str,
    port: int,
    timeout: float,
) -> SlpResult:
    """
    Perform a modern SLP exchange (Minecraft 1.7+).

    Sequence:
      C→S  Handshake   (0x00, next_state=1)
      C→S  StatusRequest (0x00)
      S→C  StatusResponse (0x00, JSON payload)
      C→S  Ping (0x01, timestamp)
      S→C  Pong (0x01, timestamp echo)

    The latency is measured from sending the Ping to receiving the Pong.
    """
    result = SlpResult(host=host, port=port, protocol_type="modern")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        result.error = "Connection timed out"
        return result
    except OSError as exc:
        result.error = f"Connection refused: {exc}"
        return result

    try:
        # ── Handshake packet ────────────────────────────────────────────────
        # Next state 1 = STATUS
        handshake_payload = (
            _encode_varint(_HANDSHAKE_PROTOCOL_VERSION)
            + _encode_string(host)
            + struct.pack(">H", port)  # unsigned short, big-endian
            + _encode_varint(1)  # next_state = STATUS
        )
        writer.write(_build_packet(0x00, handshake_payload))

        # ── Status Request ──────────────────────────────────────────────────
        writer.write(_build_packet(0x00))
        await writer.drain()

        # ── Status Response ─────────────────────────────────────────────────
        # Read packet length (VarInt)
        packet_length = await asyncio.wait_for(_read_varint(reader), timeout=timeout)
        if packet_length <= 0 or packet_length > _MAX_PAYLOAD_BYTES:
            result.error = f"Invalid packet length: {packet_length}"
            return result

        # Read the rest of the packet
        packet_data = await asyncio.wait_for(reader.readexactly(packet_length), timeout=timeout)

        # Parse packet ID
        packet_id, offset = _decode_varint_from_bytes(packet_data, 0)
        if packet_id != 0x00:
            result.error = f"Expected Status Response (0x00), got 0x{packet_id:02X}"
            return result

        # Read JSON string (VarInt length + UTF-8 bytes)
        json_length, offset = _decode_varint_from_bytes(packet_data, offset)
        if json_length <= 0 or offset + json_length > len(packet_data):
            result.error = "Malformed JSON string in Status Response"
            return result

        json_bytes = packet_data[offset : offset + json_length]
        raw_json = json_bytes.decode("utf-8")

        # ── Ping / Pong for latency measurement ─────────────────────────────
        ping_timestamp = int(time.time() * 1000) & 0x7FFFFFFFFFFFFFFF  # positive long
        ping_payload = struct.pack(">q", ping_timestamp)
        writer.write(_build_packet(0x01, ping_payload))
        await writer.drain()

        t_ping_sent = time.perf_counter()

        try:
            pong_length = await asyncio.wait_for(_read_varint(reader), timeout=timeout)
            if 0 < pong_length <= 16:
                await asyncio.wait_for(reader.readexactly(pong_length), timeout=timeout)
            t_pong_received = time.perf_counter()
            result.latency_ms = round((t_pong_received - t_ping_sent) * 1000, 2)
        except Exception:
            # Latency is a nice-to-have; don't fail the whole ping for it
            result.latency_ms = None

        # ── Parse JSON response ─────────────────────────────────────────────
        result.raw_json = raw_json
        _parse_slp_json(raw_json, result)

    except asyncio.TimeoutError:
        result.error = "Read timed out"
    except asyncio.IncompleteReadError:
        result.error = "Connection closed prematurely"
    except Exception as exc:
        result.error = f"Unexpected error: {exc}"
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return result


# ---------------------------------------------------------------------------
# Legacy SLP (Minecraft 1.4–1.6)
# ---------------------------------------------------------------------------


async def _ping_legacy(
    host: str,
    port: int,
    timeout: float,
) -> SlpResult:
    """
    Perform a legacy SLP exchange (Minecraft 1.4–1.6).

    Sends the 1.6 extended ping payload (FE 01 FA …) which is also understood
    by 1.4 and 1.5 servers.  Falls back to bare FE 01 if the extended payload
    causes an error.

    Response format (kick packet, 0xFF):
        FF <length:uint16_be> <utf-16be data>

    The data is one of:
      - Old format (1.3–): ``§<protocol>§<motd>§<online>§<max>``
      - New format (1.6+): ``§1\x00<protocol>\x00<version>\x00<motd>\x00<online>\x00<max>``
    """
    result = SlpResult(host=host, port=port, protocol_type="legacy")

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        result.error = "Connection timed out"
        return result
    except OSError as exc:
        result.error = f"Connection refused: {exc}"
        return result

    try:
        # ── Build 1.6 extended ping payload ─────────────────────────────────
        # FA 00 0B  (plugin message, channel "MC|PingHost", len=11)
        # Then: protocol_version (uint8), utf-16be host, port (uint32)
        host_utf16 = host.encode("utf-16-be")
        host_len = len(host_utf16) // 2  # length in characters (uint16)

        # FA plugin message channel "MC|PingHost"
        channel = "MC|PingHost".encode("utf-16-be")
        channel_len = len(channel) // 2  # 11 characters

        # Payload of the FA message:
        #   1 byte   — client protocol version (74 = 1.6.2)
        #   2 bytes  — host string length (uint16)
        #   N bytes  — host string (utf-16-be)
        #   4 bytes  — port (uint32, big-endian)
        fa_data = (
            struct.pack(">B", 74)  # protocol version 1.6.2
            + struct.pack(">H", host_len)  # host length in chars
            + host_utf16  # host string
            + struct.pack(">I", port)  # port
        )

        ping_packet = (
            b"\xfe\x01"  # FE 01 — ping request
            b"\xfa"  # FA — plugin message
            + struct.pack(">H", channel_len)  # channel name length
            + channel  # "MC|PingHost" utf-16-be
            + struct.pack(">H", len(fa_data))  # data length (bytes)
            + fa_data
        )

        writer.write(ping_packet)
        await writer.drain()

        # ── Read response ────────────────────────────────────────────────────
        # Expect: FF <uint16: char_count> <utf-16-be data>
        header = await asyncio.wait_for(reader.readexactly(3), timeout=timeout)

        if header[0] != 0xFF:
            result.error = f"Expected kick packet (0xFF), got 0x{header[0]:02X}"
            return result

        char_count = struct.unpack(">H", header[1:3])[0]
        if char_count == 0 or char_count > _MAX_LEGACY_CHAR_COUNT:
            result.error = f"Legacy response char_count out of range: {char_count}"
            return result
        raw_bytes = await asyncio.wait_for(reader.readexactly(char_count * 2), timeout=timeout)
        raw_str = raw_bytes.decode("utf-16-be")

        # ── Parse response string ────────────────────────────────────────────
        _parse_legacy_response(raw_str, result)

    except asyncio.TimeoutError:
        result.error = "Read timed out"
    except asyncio.IncompleteReadError:
        result.error = "Connection closed prematurely"
    except Exception as exc:
        result.error = f"Unexpected error: {exc}"
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return result


def _parse_legacy_response(raw: str, result: SlpResult) -> None:
    """
    Parse the UTF-16 payload from a legacy kick packet.

    Two sub-formats:
      New (1.6+): starts with ``§1`` followed by NUL separators
      Old (≤1.5): ``§<protocol>§<motd>§<online>§<max>``
    """
    if raw.startswith("\xa7\x31") or raw.startswith("§1"):
        # New format: §1 \0 <protocol> \0 <version> \0 <motd> \0 <online> \0 <max>
        parts = raw.split("\x00")
        # parts[0] = "§1", parts[1] = protocol, parts[2] = version,
        # parts[3] = motd, parts[4] = online, parts[5] = max
        if len(parts) >= 6:
            try:
                result.version_protocol = int(parts[1])
            except (ValueError, IndexError):
                pass
            result.version_name = parts[2] if len(parts) > 2 else None
            motd_raw = parts[3] if len(parts) > 3 else ""
            result.motd_raw = motd_raw
            result.motd_clean = _SECTION_SIGN_RE.sub("", motd_raw).strip()
            try:
                result.players_online = int(parts[4])
            except (ValueError, IndexError):
                pass
            try:
                result.players_max = int(parts[5])
            except (ValueError, IndexError):
                pass
            result.success = True
    else:
        # Old format: §<protocol>§<motd>§<online>§<max>
        # The MOTD itself may contain § colour codes, so we cannot rely on a
        # fixed index for the player counts.  Protocol is always parts[1];
        # the last two fields are online and max; everything in between is MOTD.
        parts = raw.split("§")
        # parts[0] = "" (before the leading §), parts[1] = protocol,
        # parts[2:-2] = MOTD (may be multiple segments if MOTD has § codes),
        # parts[-2] = online, parts[-1] = max
        if len(parts) >= 5:
            try:
                result.version_protocol = int(parts[1])
            except (ValueError, IndexError):
                pass
            motd_raw = "§".join(parts[2:-2])
            result.motd_raw = motd_raw
            result.motd_clean = _SECTION_SIGN_RE.sub("", motd_raw).strip()
            try:
                result.players_online = int(parts[-2])
            except (ValueError, IndexError):
                pass
            try:
                result.players_max = int(parts[-1])
            except (ValueError, IndexError):
                pass
            result.success = True
        else:
            result.error = f"Unrecognised legacy response: {raw[:80]!r}"


# ---------------------------------------------------------------------------
# JSON parsing (modern SLP)
# ---------------------------------------------------------------------------


def _parse_slp_json(raw_json: str, result: SlpResult) -> None:
    """
    Populate *result* from the JSON string in a modern SLP Status Response.

    Sets ``result.success = True`` on valid data, leaves it False on error.
    """
    try:
        data: dict[str, Any] = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        result.error = f"Invalid JSON in Status Response: {exc}"
        return

    if not isinstance(data, dict):
        result.error = "Status Response JSON is not an object"
        return

    # ── Version ──────────────────────────────────────────────────────────────
    version = data.get("version", {})
    if isinstance(version, dict):
        result.version_name = version.get("name")
        result.version_protocol = version.get("protocol")

    # ── Players ──────────────────────────────────────────────────────────────
    players = data.get("players", {})
    if isinstance(players, dict):
        result.players_online = players.get("online")
        result.players_max = players.get("max")
        sample = players.get("sample")
        if isinstance(sample, list):
            for entry in sample:
                if isinstance(entry, dict):
                    uid = entry.get("id", "")
                    name = entry.get("name", "")
                    result.players_sample.append(PlayerSample(uuid=uid, name=name))

    # ── MOTD ─────────────────────────────────────────────────────────────────
    description = data.get("description")
    result.motd_raw, result.motd_clean = _parse_motd(description)

    # ── Favicon ───────────────────────────────────────────────────────────────
    favicon = data.get("favicon")
    if isinstance(favicon, str) and favicon.startswith("data:image/"):
        result.favicon_b64 = favicon
        result.favicon_hash = _favicon_sha256(favicon)

    # ── Mod info ─────────────────────────────────────────────────────────────
    has_mod_info = False

    # Forge 1.7–1.12 style: {"modinfo": {"type": "FML", "modList": [...]}}
    modinfo = data.get("modinfo")
    if isinstance(modinfo, dict):
        has_mod_info = True
        mod_list = modinfo.get("modList", [])
        if isinstance(mod_list, list):
            for mod in mod_list:
                if isinstance(mod, dict):
                    result.mods.append(
                        ModInfo(
                            mod_id=mod.get("modid", ""),
                            version=mod.get("version", ""),
                        )
                    )

    # Forge 1.13+ / NeoForge style: {"forgeData": {"mods": [...]}}
    forge_data = data.get("forgeData")
    if isinstance(forge_data, dict):
        has_mod_info = True
        mods_list = forge_data.get("mods", [])
        if isinstance(mods_list, list):
            for mod in mods_list:
                if isinstance(mod, dict):
                    result.mods.append(
                        ModInfo(
                            mod_id=mod.get("modId", ""),
                            version=mod.get("modmarker", ""),
                        )
                    )

    # ── Software fingerprint ─────────────────────────────────────────────────
    result.software, result.is_modded, result.is_proxy = _fingerprint_software(
        result.version_name, has_mod_info
    )

    # ── Security flags ────────────────────────────────────────────────────────
    enforces = data.get("enforcesSecureChat")
    if isinstance(enforces, bool):
        result.enforces_secure_chat = enforces

    prevents = data.get("preventsChatReports")
    if isinstance(prevents, bool):
        result.prevents_chat_reports = prevents

    result.success = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def ping(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = _DEFAULT_TIMEOUT,
    *,
    try_legacy: bool = True,
) -> SlpResult:
    """
    Ping a Java Edition Minecraft server and return an ``SlpResult``.

    Strategy:
      1. Attempt the modern SLP protocol (1.7+).
      2. If that fails and *try_legacy* is True, fall back to the legacy
         0xFE ping (1.4–1.6).

    Parameters
    ----------
    host:
        Hostname or IP address of the server.
    port:
        TCP port (default 25565).
    timeout:
        Per-operation timeout in seconds.  The total wall-clock time may be
        up to ``2 × timeout`` when both modern and legacy are tried.
    try_legacy:
        Whether to attempt the legacy protocol on modern-protocol failure.

    Returns
    -------
    SlpResult
        Always returns a result object.  Check ``result.success`` to
        determine whether the ping succeeded.
    """
    log.debug("Pinging server", host=host, port=port, timeout=timeout)

    result = await _ping_modern(host, port, timeout)

    if not result.success and try_legacy:
        log.debug(
            "Modern SLP failed, trying legacy",
            host=host,
            port=port,
            reason=result.error,
        )
        legacy_result = await _ping_legacy(host, port, timeout)
        if legacy_result.success:
            return legacy_result
        # Return the modern result (richer error) if both fail
        result.error = f"modern: {result.error}; legacy: {legacy_result.error}"

    if result.success:
        log.info(
            "Ping successful",
            host=host,
            port=port,
            protocol=result.protocol_type,
            version=result.version_name,
            online=result.players_online,
            max_players=result.players_max,
            latency_ms=result.latency_ms,
            software=result.software,
        )
    else:
        log.debug("Ping failed", host=host, port=port, error=result.error)

    return result


async def ping_many(
    targets: list[tuple[str, int]],
    timeout: float = _DEFAULT_TIMEOUT,
    max_concurrency: int = 50,
) -> list[SlpResult]:
    """
    Ping multiple servers concurrently with a bounded semaphore.

    Parameters
    ----------
    targets:
        List of ``(host, port)`` tuples.
    timeout:
        Per-ping timeout in seconds.
    max_concurrency:
        Maximum number of simultaneous TCP connections.

    Returns
    -------
    List of ``SlpResult`` in the same order as *targets*.
    """
    semaphore = asyncio.Semaphore(max_concurrency)

    async def _bounded_ping(host: str, port: int) -> SlpResult:
        async with semaphore:
            return await ping(host, port, timeout)

    tasks = [_bounded_ping(host, port) for host, port in targets]
    return list(await asyncio.gather(*tasks))
