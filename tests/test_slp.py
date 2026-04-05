"""
tests.test_slp
~~~~~~~~~~~~~~
Unit tests for mcintel.scanner.slp — packet encoding, parsing helpers,
and result dataclasses.  No network connections are made.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct

import pytest

from mcintel.scanner.slp import (
    DEFAULT_PORT,
    ModInfo,
    PlayerSample,
    SlpResult,
    _build_packet,
    _chat_to_plain,
    _decode_varint_from_bytes,
    _encode_string,
    _encode_varint,
    _favicon_sha256,
    _fingerprint_software,
    _parse_legacy_response,
    _parse_motd,
    _parse_slp_json,
)

# ---------------------------------------------------------------------------
# VarInt encoding
# ---------------------------------------------------------------------------


class TestEncodeVarint:
    def test_zero(self) -> None:
        assert _encode_varint(0) == b"\x00"

    def test_one(self) -> None:
        assert _encode_varint(1) == b"\x01"

    def test_127(self) -> None:
        # Fits in one byte (0x7F)
        assert _encode_varint(127) == b"\x7f"

    def test_128(self) -> None:
        # Needs two bytes — 128 = 0x80 → 0x80 0x01
        assert _encode_varint(128) == b"\x80\x01"

    def test_255(self) -> None:
        assert _encode_varint(255) == b"\xff\x01"

    def test_300(self) -> None:
        # 300 = 0b100101100 → VarInt: 0xAC 0x02
        assert _encode_varint(300) == b"\xac\x02"

    def test_two_byte_boundary(self) -> None:
        # 16383 = 0x3FFF → 0xFF 0x7F
        assert _encode_varint(16383) == b"\xff\x7f"

    def test_16384(self) -> None:
        # 16384 = 0x4000 → 3 bytes: 0x80 0x80 0x01
        assert _encode_varint(16384) == b"\x80\x80\x01"

    def test_large_value(self) -> None:
        # 2147483647 = 0x7FFFFFFF — max positive 32-bit VarInt
        result = _encode_varint(2147483647)
        assert len(result) == 5
        assert result == b"\xff\xff\xff\xff\x07"

    def test_negative_wraps_to_unsigned(self) -> None:
        # -1 in two's complement (32-bit) = 0xFFFFFFFF
        result = _encode_varint(-1)
        assert len(result) == 5


# ---------------------------------------------------------------------------
# VarInt decoding
# ---------------------------------------------------------------------------


class TestDecodeVarintFromBytes:
    def test_zero(self) -> None:
        value, new_offset = _decode_varint_from_bytes(b"\x00", 0)
        assert value == 0
        assert new_offset == 1

    def test_one(self) -> None:
        value, new_offset = _decode_varint_from_bytes(b"\x01", 0)
        assert value == 1
        assert new_offset == 1

    def test_127(self) -> None:
        value, new_offset = _decode_varint_from_bytes(b"\x7f", 0)
        assert value == 127
        assert new_offset == 1

    def test_128(self) -> None:
        value, new_offset = _decode_varint_from_bytes(b"\x80\x01", 0)
        assert value == 128
        assert new_offset == 2

    def test_300(self) -> None:
        value, new_offset = _decode_varint_from_bytes(b"\xac\x02", 0)
        assert value == 300
        assert new_offset == 2

    def test_with_offset(self) -> None:
        # Data with a leading 0xFF byte that we skip
        data = b"\xff\x01"
        value, new_offset = _decode_varint_from_bytes(data, 0)
        assert value == 255
        assert new_offset == 2

    def test_offset_midway(self) -> None:
        # First byte is junk; VarInt starts at offset 1
        data = b"\x99\x80\x01"
        value, new_offset = _decode_varint_from_bytes(data, 1)
        assert value == 128
        assert new_offset == 3

    def test_roundtrip_various_values(self) -> None:
        for original in [0, 1, 127, 128, 255, 300, 16383, 16384, 2097151, 2097152]:
            encoded = _encode_varint(original)
            decoded, consumed = _decode_varint_from_bytes(encoded, 0)
            assert decoded == original, f"Roundtrip failed for {original}"
            assert consumed == len(encoded)

    def test_truncated_varint_raises(self) -> None:
        # High bit set but no continuation byte
        with pytest.raises(ValueError, match="truncated"):
            _decode_varint_from_bytes(b"\x80", 0)

    def test_too_long_raises(self) -> None:
        # Six continuation bytes — exceeds 5-byte VarInt limit
        with pytest.raises(ValueError, match="too long"):
            _decode_varint_from_bytes(b"\x80\x80\x80\x80\x80\x01", 0)


# ---------------------------------------------------------------------------
# String encoding
# ---------------------------------------------------------------------------


class TestEncodeString:
    def test_empty_string(self) -> None:
        result = _encode_string("")
        # Should be a single zero byte (length = 0)
        assert result == b"\x00"

    def test_ascii_string(self) -> None:
        result = _encode_string("hello")
        # 5 bytes payload, length prefix is VarInt(5) = 0x05
        assert result[0:1] == b"\x05"
        assert result[1:] == b"hello"

    def test_unicode_string(self) -> None:
        text = "héllo"  # 'é' is two bytes in UTF-8
        encoded = text.encode("utf-8")
        result = _encode_string(text)
        # Length prefix = byte length of UTF-8, not char length
        length, offset = _decode_varint_from_bytes(result, 0)
        assert length == len(encoded)
        assert result[offset:] == encoded

    def test_length_prefix_correct(self) -> None:
        s = "play.hypixel.net"
        result = _encode_string(s)
        length, offset = _decode_varint_from_bytes(result, 0)
        assert length == len(s.encode("utf-8"))
        assert result[offset:] == s.encode("utf-8")


# ---------------------------------------------------------------------------
# Packet building
# ---------------------------------------------------------------------------


class TestBuildPacket:
    def test_empty_payload(self) -> None:
        packet = _build_packet(0x00)
        # Packet = VarInt(length) + VarInt(packet_id)
        # length = 1 (just the packet_id byte 0x00)
        # So: 0x01 0x00
        assert packet == b"\x01\x00"

    def test_packet_id_zero_with_data(self) -> None:
        packet = _build_packet(0x00, b"\x01\x02")
        # Inner = 0x00 (id) + 0x01 0x02 (payload) → 3 bytes
        # Length prefix = VarInt(3) = 0x03
        assert packet[0:1] == b"\x03"
        assert packet[1:2] == b"\x00"  # packet id
        assert packet[2:] == b"\x01\x02"

    def test_packet_id_nonzero(self) -> None:
        packet = _build_packet(0x01, struct.pack(">q", 12345))
        # Inner = 0x01 (id) + 8 bytes (Long) → 9 bytes total
        length, offset = _decode_varint_from_bytes(packet, 0)
        assert length == 9

    def test_status_request_packet(self) -> None:
        # Status Request: packet id 0x00, no payload → total inner = 1 byte
        packet = _build_packet(0x00)
        assert len(packet) == 2  # 1-byte length prefix + 1-byte packet id


# ---------------------------------------------------------------------------
# Chat component parsing
# ---------------------------------------------------------------------------


class TestChatToPlain:
    def test_plain_string(self) -> None:
        assert _chat_to_plain("Hello, World!") == "Hello, World!"

    def test_none(self) -> None:
        assert _chat_to_plain(None) == ""

    def test_empty_string(self) -> None:
        assert _chat_to_plain("") == ""

    def test_section_sign_stripped(self) -> None:
        assert _chat_to_plain("§aGreen §lBold") == "Green Bold"

    def test_section_sign_all_codes(self) -> None:
        codes = "0123456789abcdefklmnorABCDEF"
        input_str = "".join(f"§{c}x" for c in codes)
        result = _chat_to_plain(input_str)
        # All codes stripped — only the 'x' chars remain
        assert result == "x" * len(codes)

    def test_dict_with_text(self) -> None:
        obj = {"text": "Hello"}
        assert _chat_to_plain(obj) == "Hello"

    def test_dict_with_extra(self) -> None:
        obj = {"text": "Hello", "extra": [{"text": " World"}]}
        assert _chat_to_plain(obj) == "Hello World"

    def test_dict_nested_extra(self) -> None:
        obj = {
            "text": "A",
            "extra": [{"text": "B", "extra": [{"text": "C"}]}],
        }
        assert _chat_to_plain(obj) == "ABC"

    def test_list_of_components(self) -> None:
        obj = [{"text": "foo"}, {"text": "bar"}]
        assert _chat_to_plain(obj) == "foobar"

    def test_dict_translate_key(self) -> None:
        obj = {"translate": "death.attack.player"}
        result = _chat_to_plain(obj)
        assert "death.attack.player" in result

    def test_dict_with_formatting_codes_in_text(self) -> None:
        obj = {"text": "§cRed §aGreen"}
        assert _chat_to_plain(obj) == "Red Green"

    def test_hypixel_style_motd(self) -> None:
        # Typical Hypixel-style MOTD
        motd = {
            "text": "",
            "extra": [
                {"text": "§aHypixel Network", "bold": True},
                {"text": " §7[1.8-1.21]"},
            ],
        }
        result = _chat_to_plain(motd)
        assert "Hypixel Network" in result
        assert "[1.8-1.21]" in result
        # No § colour codes
        assert "§" not in result


# ---------------------------------------------------------------------------
# MOTD parsing
# ---------------------------------------------------------------------------


class TestParseMotd:
    def test_plain_string(self) -> None:
        raw, clean = _parse_motd("Hello server")
        assert raw == "Hello server"
        assert clean == "Hello server"

    def test_none(self) -> None:
        raw, clean = _parse_motd(None)
        assert raw == ""
        assert clean == ""

    def test_string_with_colour_codes(self) -> None:
        raw, clean = _parse_motd("§aGreen §cRed")
        assert raw == "§aGreen §cRed"
        assert clean == "Green Red"

    def test_dict_component(self) -> None:
        obj = {"text": "A Minecraft Server"}
        raw, clean = _parse_motd(obj)
        assert "A Minecraft Server" in raw  # raw is JSON string
        assert clean == "A Minecraft Server"

    def test_list_component(self) -> None:
        obj = [{"text": "Part1"}, {"text": "Part2"}]
        raw, clean = _parse_motd(obj)
        assert "Part1" in raw
        assert "Part1Part2" == clean

    def test_clean_is_stripped(self) -> None:
        _, clean = _parse_motd("  §l§6Server  ")
        assert not clean.startswith(" ")
        assert not clean.endswith(" ")


# ---------------------------------------------------------------------------
# Favicon SHA-256
# ---------------------------------------------------------------------------


class TestFaviconSha256:
    def _make_favicon(self, content: bytes = b"fake-png-data") -> str:
        b64 = base64.b64encode(content).decode()
        return f"data:image/png;base64,{b64}"

    def test_none_returns_none(self) -> None:
        assert _favicon_sha256(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert _favicon_sha256("") is None

    def test_valid_favicon(self) -> None:
        content = b"fake-png-bytes"
        favicon = self._make_favicon(content)
        result = _favicon_sha256(favicon)
        expected = hashlib.sha256(content).hexdigest()
        assert result == expected

    def test_different_content_different_hash(self) -> None:
        h1 = _favicon_sha256(self._make_favicon(b"img1"))
        h2 = _favicon_sha256(self._make_favicon(b"img2"))
        assert h1 != h2

    def test_same_content_same_hash(self) -> None:
        content = b"consistent-image"
        fav = self._make_favicon(content)
        assert _favicon_sha256(fav) == _favicon_sha256(fav)

    def test_hash_is_hex_string_64_chars(self) -> None:
        result = _favicon_sha256(self._make_favicon(b"x"))
        assert result is not None
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


# ---------------------------------------------------------------------------
# Software fingerprinting
# ---------------------------------------------------------------------------


class TestFingerprintSoftware:
    def _fp(self, version_name: str | None, has_mod_info: bool = False):
        return _fingerprint_software(version_name, has_mod_info)

    def test_paper(self) -> None:
        sw, modded, proxy = self._fp("Paper 1.20.4")
        assert sw == "Paper"
        assert not modded
        assert not proxy

    def test_spigot(self) -> None:
        sw, _, _ = self._fp("Spigot 1.8.8")
        assert sw == "Spigot"

    def test_purpur(self) -> None:
        sw, _, _ = self._fp("Purpur 1.20.4")
        assert sw == "Purpur"

    def test_bungeecord(self) -> None:
        sw, _, proxy = self._fp("BungeeCord 1.20")
        assert sw == "BungeeCord"
        assert proxy

    def test_velocity(self) -> None:
        sw, _, proxy = self._fp("Velocity 3.3.0")
        assert sw == "Velocity"
        assert proxy

    def test_waterfall(self) -> None:
        sw, _, proxy = self._fp("Waterfall 1.20")
        assert sw == "Waterfall"
        assert proxy

    def test_forge(self) -> None:
        sw, modded, proxy = self._fp("Forge 1.20.1")
        assert sw == "Forge"
        assert modded
        assert not proxy

    def test_neoforge(self) -> None:
        sw, modded, _ = self._fp("NeoForge 1.21")
        assert sw == "NeoForge"
        assert modded

    def test_fabric(self) -> None:
        sw, modded, _ = self._fp("Fabric 0.15 1.20")
        assert sw == "Fabric"
        assert modded

    def test_case_insensitive(self) -> None:
        sw1, _, _ = self._fp("paper")
        sw2, _, _ = self._fp("PAPER")
        sw3, _, _ = self._fp("Paper")
        assert sw1 == sw2 == sw3 == "Paper"

    def test_unknown_returns_none(self) -> None:
        sw, modded, proxy = self._fp("Some Unknown Server")
        assert sw is None
        assert not proxy

    def test_none_version(self) -> None:
        sw, modded, proxy = self._fp(None)
        assert sw is None
        assert not proxy

    def test_modinfo_flag_propagates(self) -> None:
        # Even if version name doesn't indicate modded, mod_info flag should
        sw, modded, _ = self._fp("Paper 1.20", has_mod_info=True)
        assert modded

    def test_folia(self) -> None:
        sw, _, _ = self._fp("Folia 1.20.4")
        assert sw == "Folia"

    def test_vanilla(self) -> None:
        sw, modded, proxy = self._fp("1.21.1")
        # No pattern match for bare version strings
        assert sw is None

    def test_vanilla_explicit(self) -> None:
        sw, _, _ = self._fp("vanilla")
        assert sw == "Vanilla"


# ---------------------------------------------------------------------------
# Legacy SLP response parsing
# ---------------------------------------------------------------------------


class TestParseLegacyResponse:
    def _make_result(self) -> SlpResult:
        return SlpResult(host="test", port=25565, protocol_type="legacy")

    def test_new_format_1_6(self) -> None:
        # New format: §1 \0 protocol \0 version \0 motd \0 online \0 max
        raw = "§1\x00127\x001.8.9\x00A Minecraft Server\x0042\x001000"
        result = self._make_result()
        _parse_legacy_response(raw, result)

        assert result.success
        assert result.version_protocol == 127
        assert result.version_name == "1.8.9"
        assert result.motd_clean == "A Minecraft Server"
        assert result.players_online == 42
        assert result.players_max == 1000

    def test_new_format_strips_colour_from_motd(self) -> None:
        raw = "§1\x00127\x001.8.9\x00§aGreen Server§r\x005\x00100"
        result = self._make_result()
        _parse_legacy_response(raw, result)

        assert result.success
        assert result.motd_clean == "Green Server"

    def test_old_format(self) -> None:
        # Old format: §<protocol>§<motd>§<online>§<max>
        raw = "§47§My Old Server§10§200"
        result = self._make_result()
        _parse_legacy_response(raw, result)

        assert result.success
        assert result.version_protocol == 47
        assert result.motd_clean == "My Old Server"
        assert result.players_online == 10
        assert result.players_max == 200

    def test_old_format_colour_in_motd(self) -> None:
        # MOTD contains § colour codes which should be stripped.
        # Old format: §<protocol>§<motd>§<online>§<max>
        # Here the MOTD is "§cRed §aGreen", so after splitting on § we get:
        #   parts = ["", "47", "cRed ", "aGreen", "10", "50"]
        # protocol=parts[1]="47", online=parts[-2]="10", max=parts[-1]="50"
        # motd = "§".join(parts[2:-2]) = "cRed §aGreen" → clean = "Red Green"
        raw = "§47§§cRed §aGreen§10§50"
        result = self._make_result()
        _parse_legacy_response(raw, result)
        assert result.success
        assert "§" not in result.motd_clean
        assert result.motd_clean == "Red Green"
        assert result.version_protocol == 47
        assert result.players_online == 10
        assert result.players_max == 50

    def test_invalid_response(self) -> None:
        raw = "not a valid legacy response"
        result = self._make_result()
        _parse_legacy_response(raw, result)
        # Should not succeed
        assert not result.success

    def test_new_format_with_zero_players(self) -> None:
        raw = "§1\x0047\x001.4.7\x00Empty Server\x000\x0020"
        result = self._make_result()
        _parse_legacy_response(raw, result)

        assert result.success
        assert result.players_online == 0
        assert result.players_max == 20


# ---------------------------------------------------------------------------
# Modern SLP JSON parsing
# ---------------------------------------------------------------------------


class TestParseSlpJson:
    def _base_json(self, **overrides) -> str:
        data = {
            "version": {"name": "Paper 1.20.4", "protocol": 765},
            "players": {"online": 10, "max": 100, "sample": []},
            "description": "A Minecraft Server",
            "favicon": None,
        }
        data.update(overrides)
        # Remove None values to simulate real server responses
        if data.get("favicon") is None:
            del data["favicon"]
        return json.dumps(data)

    def _make_result(self) -> SlpResult:
        return SlpResult(host="test", port=25565, protocol_type="modern")

    def test_basic_parse(self) -> None:
        result = self._make_result()
        _parse_slp_json(self._base_json(), result)

        assert result.success
        assert result.version_name == "Paper 1.20.4"
        assert result.version_protocol == 765
        assert result.players_online == 10
        assert result.players_max == 100
        assert result.motd_clean == "A Minecraft Server"

    def test_software_fingerprint_applied(self) -> None:
        result = self._make_result()
        _parse_slp_json(self._base_json(), result)
        assert result.software == "Paper"
        assert not result.is_proxy

    def test_bungeecord_proxy_detected(self) -> None:
        raw = json.dumps(
            {
                "version": {"name": "BungeeCord 1.20", "protocol": 765},
                "players": {"online": 0, "max": 1},
                "description": "Proxy",
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)
        assert result.is_proxy
        assert result.software == "BungeeCord"

    def test_player_sample_parsed(self) -> None:
        sample = [
            {"id": "069a79f4-44e9-4726-a5be-fca90e38aaf5", "name": "Notch"},
            {"id": "61699b2e-d327-4a01-9f1e-0ea8c3f06bc6", "name": "jeb_"},
        ]
        raw = json.dumps(
            {
                "version": {"name": "Paper 1.20", "protocol": 765},
                "players": {"online": 2, "max": 100, "sample": sample},
                "description": "Test",
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success
        assert len(result.players_sample) == 2
        assert result.players_sample[0].name == "Notch"
        assert result.players_sample[0].uuid == "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert result.players_sample[1].name == "jeb_"

    def test_favicon_parsed(self) -> None:
        content = b"fake-png"
        b64 = base64.b64encode(content).decode()
        favicon = f"data:image/png;base64,{b64}"
        raw = json.dumps(
            {
                "version": {"name": "Paper 1.20", "protocol": 765},
                "players": {"online": 0, "max": 10},
                "description": "Test",
                "favicon": favicon,
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success
        assert result.favicon_b64 == favicon
        expected_hash = hashlib.sha256(content).hexdigest()
        assert result.favicon_hash == expected_hash

    def test_forge_modinfo_parsed(self) -> None:
        raw = json.dumps(
            {
                "version": {"name": "Forge 1.12.2", "protocol": 340},
                "players": {"online": 1, "max": 20},
                "description": "Modded",
                "modinfo": {
                    "type": "FML",
                    "modList": [
                        {"modid": "forge", "version": "14.23.5"},
                        {"modid": "jei", "version": "4.16.1"},
                        {"modid": "thaumcraft", "version": "6.1.BETA26"},
                    ],
                },
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success
        assert result.is_modded
        assert result.software == "Forge"
        assert len(result.mods) == 3
        mod_ids = [m.mod_id for m in result.mods]
        assert "forge" in mod_ids
        assert "jei" in mod_ids
        assert "thaumcraft" in mod_ids

    def test_neoforge_forgedata_parsed(self) -> None:
        raw = json.dumps(
            {
                "version": {"name": "NeoForge 1.21", "protocol": 770},
                "players": {"online": 0, "max": 20},
                "description": "NeoForge Server",
                "forgeData": {
                    "mods": [
                        {"modId": "neoforge", "modmarker": "21.1.0"},
                        {"modId": "examplemod", "modmarker": "1.0.0"},
                    ],
                },
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success
        assert result.is_modded
        assert len(result.mods) == 2
        assert result.mods[0].mod_id == "neoforge"

    def test_secure_chat_flags(self) -> None:
        raw = json.dumps(
            {
                "version": {"name": "Paper 1.20", "protocol": 765},
                "players": {"online": 0, "max": 10},
                "description": "Test",
                "enforcesSecureChat": True,
                "preventsChatReports": False,
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.enforces_secure_chat is True
        assert result.prevents_chat_reports is False

    def test_dict_motd(self) -> None:
        raw = json.dumps(
            {
                "version": {"name": "Paper 1.20", "protocol": 765},
                "players": {"online": 0, "max": 10},
                "description": {
                    "text": "",
                    "extra": [
                        {"text": "§aFancy ", "bold": True},
                        {"text": "§bServer"},
                    ],
                },
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success
        assert result.motd_clean == "Fancy Server"
        assert "§" not in result.motd_clean

    def test_invalid_json(self) -> None:
        result = self._make_result()
        _parse_slp_json("not json at all {{", result)

        assert not result.success
        assert result.error is not None
        assert "JSON" in result.error or "json" in result.error.lower()

    def test_json_not_dict(self) -> None:
        result = self._make_result()
        _parse_slp_json("[1, 2, 3]", result)

        assert not result.success
        assert result.error is not None

    def test_empty_player_sample(self) -> None:
        result = self._make_result()
        _parse_slp_json(self._base_json(), result)

        assert result.players_sample == []

    def test_missing_version_field(self) -> None:
        raw = json.dumps(
            {
                "players": {"online": 5, "max": 50},
                "description": "No version",
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success  # Should still succeed
        assert result.version_name is None
        assert result.version_protocol is None

    def test_missing_players_field(self) -> None:
        raw = json.dumps(
            {
                "version": {"name": "Paper 1.20", "protocol": 765},
                "description": "No players",
            }
        )
        result = self._make_result()
        _parse_slp_json(raw, result)

        assert result.success
        assert result.players_online is None
        assert result.players_max is None


# ---------------------------------------------------------------------------
# SlpResult dataclass
# ---------------------------------------------------------------------------


class TestSlpResult:
    def test_address_property_default_port(self) -> None:
        r = SlpResult(host="play.example.com", port=25565)
        assert r.address == "play.example.com"

    def test_address_property_custom_port(self) -> None:
        r = SlpResult(host="play.example.com", port=25566)
        assert r.address == "play.example.com:25566"

    def test_default_success_is_false(self) -> None:
        r = SlpResult(host="test", port=25565)
        assert not r.success

    def test_default_lists_are_empty(self) -> None:
        r = SlpResult(host="test", port=25565)
        assert r.players_sample == []
        assert r.mods == []

    def test_to_dict_includes_all_keys(self) -> None:
        r = SlpResult(
            host="play.example.com",
            port=25565,
            success=True,
            version_name="Paper 1.20",
            version_protocol=765,
            players_online=10,
            players_max=100,
            motd_clean="Test Server",
            software="Paper",
            is_modded=False,
            is_proxy=False,
        )
        d = r.to_dict()
        assert d["host"] == "play.example.com"
        assert d["port"] == 25565
        assert d["success"] is True
        assert d["version_name"] == "Paper 1.20"
        assert d["players_online"] == 10
        assert d["software"] == "Paper"

    def test_to_dict_players_sample_serialised(self) -> None:
        r = SlpResult(host="test", port=25565)
        r.players_sample = [PlayerSample(uuid="abc", name="Notch")]
        d = r.to_dict()
        assert d["players_sample"] == [{"uuid": "abc", "name": "Notch"}]

    def test_to_dict_mods_serialised(self) -> None:
        r = SlpResult(host="test", port=25565)
        r.mods = [ModInfo(mod_id="forge", version="14.0")]
        d = r.to_dict()
        assert d["mods"] == [{"mod_id": "forge", "version": "14.0"}]


# ---------------------------------------------------------------------------
# PlayerSample & ModInfo dataclasses
# ---------------------------------------------------------------------------


class TestPlayerSample:
    def test_to_dict(self) -> None:
        ps = PlayerSample(uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5", name="Notch")
        d = ps.to_dict()
        assert d == {
            "uuid": "069a79f4-44e9-4726-a5be-fca90e38aaf5",
            "name": "Notch",
        }


class TestModInfo:
    def test_to_dict_with_version(self) -> None:
        m = ModInfo(mod_id="jei", version="4.16.1")
        assert m.to_dict() == {"mod_id": "jei", "version": "4.16.1"}

    def test_to_dict_empty_version(self) -> None:
        m = ModInfo(mod_id="minecraft")
        assert m.to_dict() == {"mod_id": "minecraft", "version": ""}
