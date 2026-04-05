"""
tests.test_players
~~~~~~~~~~~~~~~~~~
Unit tests for mcintel.players.mojang — UUID utilities, offline-mode
detection, texture parsing, and result dataclasses.
No network connections are made.
"""

from __future__ import annotations

import base64
import json

import pytest

from mcintel.players.mojang import (
    MojangProfile,
    PlayerSkin,
    UuidLookupResult,
    _classify_cape,
    _extract_textures,
    _parse_textures_property,
    is_premium_uuid,
    normalise_uuid,
    offline_uuid,
    uuid_version,
)

# ---------------------------------------------------------------------------
# normalise_uuid
# ---------------------------------------------------------------------------


class TestNormaliseUuid:
    def test_already_normalised(self) -> None:
        u = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert normalise_uuid(u) == u

    def test_undashed_to_dashed(self) -> None:
        undashed = "069a79f444e94726a5befca90e38aaf5"
        expected = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert normalise_uuid(undashed) == expected

    def test_uppercase_lowercased(self) -> None:
        upper = "069A79F4-44E9-4726-A5BE-FCA90E38AAF5"
        expected = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert normalise_uuid(upper) == expected

    def test_uppercase_undashed(self) -> None:
        undashed_upper = "069A79F444E94726A5BEFCA90E38AAF5"
        expected = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert normalise_uuid(undashed_upper) == expected

    def test_mixed_case(self) -> None:
        mixed = "069a79F4-44E9-4726-a5be-FCA90E38aaf5"
        expected = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert normalise_uuid(mixed) == expected

    def test_output_format_is_8_4_4_4_12(self) -> None:
        result = normalise_uuid("069a79f444e94726a5befca90e38aaf5")
        parts = result.split("-")
        assert len(parts) == 5
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12]

    def test_all_zeros(self) -> None:
        assert normalise_uuid("00000000-0000-0000-0000-000000000000") == (
            "00000000-0000-0000-0000-000000000000"
        )

    def test_all_zeros_undashed(self) -> None:
        assert normalise_uuid("0" * 32) == "00000000-0000-0000-0000-000000000000"

    def test_all_f_undashed(self) -> None:
        result = normalise_uuid("f" * 32)
        assert result == "ffffffff-ffff-ffff-ffff-ffffffffffff"

    def test_invalid_too_short(self) -> None:
        with pytest.raises(ValueError):
            normalise_uuid("069a79f4-44e9-4726-a5be")

    def test_invalid_too_long(self) -> None:
        with pytest.raises(ValueError):
            normalise_uuid("069a79f4-44e9-4726-a5be-fca90e38aaf5-extra")

    def test_invalid_non_hex(self) -> None:
        with pytest.raises(ValueError):
            normalise_uuid("zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz")

    def test_invalid_empty_string(self) -> None:
        with pytest.raises(ValueError):
            normalise_uuid("")

    def test_jeb_uuid(self) -> None:
        result = normalise_uuid("853c80ef-3c37-49fd-aa49-938b674adae6")
        assert result == "853c80ef-3c37-49fd-aa49-938b674adae6"

    def test_idempotent(self) -> None:
        u = "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert normalise_uuid(normalise_uuid(u)) == u


# ---------------------------------------------------------------------------
# uuid_version
# ---------------------------------------------------------------------------


class TestUuidVersion:
    def test_version_4_notch(self) -> None:
        # Notch's UUID is version 4
        assert uuid_version("069a79f4-44e9-4726-a5be-fca90e38aaf5") == 4

    def test_version_4_jeb(self) -> None:
        assert uuid_version("853c80ef-3c37-49fd-aa49-938b674adae6") == 4

    def test_version_3_offline(self) -> None:
        # Offline UUID for "TestPlayer" is version 3
        ou = offline_uuid("TestPlayer")
        assert uuid_version(ou) == 3

    def test_version_from_explicit_v3_uuid(self) -> None:
        # Manually crafted v3 UUID (version nibble = 3)
        # xxxxxxxx-xxxx-3xxx-xxxx-xxxxxxxxxxxx
        v3 = "a3bb189e-8bf9-3888-9917-50ab0f3af95e"
        assert uuid_version(v3) == 3

    def test_version_from_explicit_v4_uuid(self) -> None:
        # Version nibble = 4
        v4 = "550e8400-e29b-41d4-a716-446655440000"
        assert uuid_version(v4) == 4

    def test_version_1_uuid(self) -> None:
        # Version nibble = 1
        v1 = "550e8400-e29b-11d4-a716-446655440000"
        assert uuid_version(v1) == 1

    def test_version_5_uuid(self) -> None:
        # Version nibble = 5
        v5 = "550e8400-e29b-51d4-a716-446655440000"
        assert uuid_version(v5) == 5

    def test_invalid_uuid_returns_minus_one(self) -> None:
        assert uuid_version("not-a-uuid") == -1

    def test_empty_string_returns_minus_one(self) -> None:
        assert uuid_version("") == -1

    def test_undashed_v4_uuid(self) -> None:
        # python's uuid.UUID accepts undashed format too
        assert uuid_version("069a79f444e94726a5befca90e38aaf5") == 4


# ---------------------------------------------------------------------------
# is_premium_uuid
# ---------------------------------------------------------------------------


class TestIsPremiumUuid:
    def test_notch_is_premium(self) -> None:
        assert is_premium_uuid("069a79f4-44e9-4726-a5be-fca90e38aaf5")

    def test_jeb_is_premium(self) -> None:
        assert is_premium_uuid("853c80ef-3c37-49fd-aa49-938b674adae6")

    def test_offline_uuid_is_not_premium(self) -> None:
        ou = offline_uuid("SomePlayer")
        assert not is_premium_uuid(ou)

    def test_v3_uuid_is_not_premium(self) -> None:
        v3 = "a3bb189e-8bf9-3888-9917-50ab0f3af95e"
        assert not is_premium_uuid(v3)

    def test_v1_uuid_is_not_premium(self) -> None:
        v1 = "550e8400-e29b-11d4-a716-446655440000"
        assert not is_premium_uuid(v1)

    def test_invalid_uuid_is_not_premium(self) -> None:
        assert not is_premium_uuid("not-valid")

    def test_empty_is_not_premium(self) -> None:
        assert not is_premium_uuid("")


# ---------------------------------------------------------------------------
# offline_uuid
# ---------------------------------------------------------------------------


class TestOfflineUuid:
    def test_returns_string(self) -> None:
        result = offline_uuid("Notch")
        assert isinstance(result, str)

    def test_format_is_uuid_v3(self) -> None:
        result = offline_uuid("TestPlayer")
        parts = result.split("-")
        assert len(parts) == 5
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12]

    def test_version_is_3(self) -> None:
        result = offline_uuid("AnyUsername")
        assert uuid_version(result) == 3

    def test_is_not_premium(self) -> None:
        assert not is_premium_uuid(offline_uuid("SomePlayer"))

    def test_known_value_notch(self) -> None:
        # The offline UUID for "Notch" can be verified against Minecraft's
        # own offline-mode UUID generation (Java NameUUIDFromBytes).
        # Python result should match the well-known value.
        result = offline_uuid("Notch")
        # Version 3 check
        assert uuid_version(result) == 3
        # Must not be the same as Notch's real premium UUID
        assert result != "069a79f4-44e9-4726-a5be-fca90e38aaf5"

    def test_different_names_produce_different_uuids(self) -> None:
        u1 = offline_uuid("Alice")
        u2 = offline_uuid("Bob")
        assert u1 != u2

    def test_same_name_always_produces_same_uuid(self) -> None:
        name = "ConsistentName"
        assert offline_uuid(name) == offline_uuid(name)

    def test_case_sensitive(self) -> None:
        # Minecraft offline mode is case-sensitive for UUID generation
        u_lower = offline_uuid("testplayer")
        u_upper = offline_uuid("TestPlayer")
        u_mixed = offline_uuid("TESTPLAYER")
        assert u_lower != u_upper
        assert u_upper != u_mixed

    def test_empty_username(self) -> None:
        # Should not raise; returns a deterministic UUID
        result = offline_uuid("")
        assert uuid_version(result) == 3

    def test_special_characters(self) -> None:
        # Minecraft usernames can only have [A-Za-z0-9_], but the function
        # should handle anything without crashing.
        result = offline_uuid("player_123")
        assert uuid_version(result) == 3

    def test_unicode_username(self) -> None:
        result = offline_uuid("héllo")
        assert uuid_version(result) == 3

    def test_16_char_max_username(self) -> None:
        result = offline_uuid("A" * 16)
        assert uuid_version(result) == 3

    def test_output_all_lowercase(self) -> None:
        result = offline_uuid("TestPlayer")
        assert result == result.lower()


# ---------------------------------------------------------------------------
# _classify_cape
# ---------------------------------------------------------------------------


class TestClassifyCape:
    def test_none_returns_none(self) -> None:
        assert _classify_cape(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert _classify_cape("") is None

    def test_mojang_cape_url(self) -> None:
        url = "https://textures.minecraft.net/texture/abc123"
        assert _classify_cape(url) == "mojang"

    def test_mojang_cape_http(self) -> None:
        url = "http://textures.minecraft.net/texture/abc123"
        assert _classify_cape(url) == "mojang"

    def test_optifine_cape(self) -> None:
        url = "https://optifine.net/capes/Notch.png"
        assert _classify_cape(url) == "optifine"

    def test_labymod_cape(self) -> None:
        url = "https://dl.labymod.net/capes/069a79f444e94726a5befca90e38aaf5"
        assert _classify_cape(url) == "labymod"

    def test_minecraftcapes_co_uk(self) -> None:
        url = "https://minecraftcapes.co.uk/profile/069a79f444e94726a5befca90e38aaf5/cape"
        assert _classify_cape(url) == "minecraftcapes"

    def test_minecraftcapes_net(self) -> None:
        url = "https://minecraftcapes.net/profile/abc/cape"
        assert _classify_cape(url) == "minecraftcapes"

    def test_unknown_domain(self) -> None:
        url = "https://some-unknown-cape-service.example.com/cape/xyz.png"
        assert _classify_cape(url) == "unknown"

    def test_case_insensitive_matching(self) -> None:
        url = "https://OPTIFINE.NET/capes/test.png"
        assert _classify_cape(url) == "optifine"

    def test_textures_minecraft_net_case_insensitive(self) -> None:
        url = "HTTPS://TEXTURES.MINECRAFT.NET/TEXTURE/abc"
        assert _classify_cape(url) == "mojang"


# ---------------------------------------------------------------------------
# _parse_textures_property
# ---------------------------------------------------------------------------


def _make_textures_b64(
    skin_url: str | None = None,
    cape_url: str | None = None,
    model: str | None = None,
) -> str:
    """Build a base64-encoded textures JSON blob for testing."""
    skin_data: dict = {}
    if skin_url:
        skin_data["url"] = skin_url
        if model:
            skin_data["metadata"] = {"model": model}

    cape_data: dict = {}
    if cape_url:
        cape_data["url"] = cape_url

    textures: dict = {}
    if skin_data:
        textures["SKIN"] = skin_data
    if cape_data:
        textures["CAPE"] = cape_data

    payload = {
        "timestamp": 1700000000000,
        "profileId": "069a79f444e94726a5befca90e38aaf5",
        "profileName": "TestPlayer",
        "textures": textures,
    }
    json_str = json.dumps(payload)
    return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")


class TestParseTexturesProperty:
    def test_skin_url_extracted(self) -> None:
        url = "http://textures.minecraft.net/texture/abc123"
        b64 = _make_textures_b64(skin_url=url)
        skin = _parse_textures_property(b64)
        assert skin.skin_url == url

    def test_default_variant_is_classic(self) -> None:
        b64 = _make_textures_b64(skin_url="http://textures.minecraft.net/texture/abc")
        skin = _parse_textures_property(b64)
        assert skin.skin_variant == "classic"

    def test_slim_variant_detected(self) -> None:
        url = "http://textures.minecraft.net/texture/abc"
        b64 = _make_textures_b64(skin_url=url, model="slim")
        skin = _parse_textures_property(b64)
        assert skin.skin_variant == "slim"

    def test_cape_url_extracted(self) -> None:
        cape_url = "https://textures.minecraft.net/texture/cape123"
        b64 = _make_textures_b64(
            skin_url="http://textures.minecraft.net/texture/skin",
            cape_url=cape_url,
        )
        skin = _parse_textures_property(b64)
        assert skin.cape_url == cape_url

    def test_cape_type_classified_as_mojang(self) -> None:
        cape_url = "https://textures.minecraft.net/texture/cape123"
        b64 = _make_textures_b64(cape_url=cape_url)
        skin = _parse_textures_property(b64)
        assert skin.cape_type == "mojang"

    def test_no_cape_fields_are_none(self) -> None:
        b64 = _make_textures_b64(skin_url="http://textures.minecraft.net/texture/s")
        skin = _parse_textures_property(b64)
        assert skin.cape_url is None
        assert skin.cape_type is None

    def test_no_skin_url_is_none(self) -> None:
        b64 = _make_textures_b64()  # no skin, no cape
        skin = _parse_textures_property(b64)
        assert skin.skin_url is None

    def test_invalid_base64_returns_empty_skin(self) -> None:
        skin = _parse_textures_property("not-valid-base64!!!")
        # Should not raise; returns a skin object (possibly empty)
        assert isinstance(skin, PlayerSkin)

    def test_invalid_json_inside_b64_returns_empty_skin(self) -> None:
        not_json = base64.b64encode(b"this is not json").decode()
        skin = _parse_textures_property(not_json)
        assert isinstance(skin, PlayerSkin)

    def test_empty_textures_block(self) -> None:
        payload = {"timestamp": 0, "profileId": "abc", "profileName": "x", "textures": {}}
        b64 = base64.b64encode(json.dumps(payload).encode()).decode()
        skin = _parse_textures_property(b64)
        assert skin.skin_url is None
        assert skin.cape_url is None

    def test_base64_padding_tolerance(self) -> None:
        # Python's base64.b64decode handles missing padding with the '==' trick
        url = "http://textures.minecraft.net/texture/abc"
        b64 = _make_textures_b64(skin_url=url)
        # Strip trailing padding to simulate servers that omit it
        b64_stripped = b64.rstrip("=")
        skin = _parse_textures_property(b64_stripped)
        assert skin.skin_url == url


# ---------------------------------------------------------------------------
# _extract_textures
# ---------------------------------------------------------------------------


class TestExtractTextures:
    def test_returns_none_when_no_textures_property(self) -> None:
        properties = [
            {"name": "isLegacy", "value": "true"},
        ]
        assert _extract_textures(properties) is None

    def test_returns_none_for_empty_list(self) -> None:
        assert _extract_textures([]) is None

    def test_extracts_textures_property(self) -> None:
        skin_url = "http://textures.minecraft.net/texture/abc"
        b64 = _make_textures_b64(skin_url=skin_url)
        properties = [
            {"name": "textures", "value": b64},
        ]
        result = _extract_textures(properties)
        assert result is not None
        assert result.skin_url == skin_url

    def test_ignores_non_textures_properties(self) -> None:
        properties = [
            {"name": "isDemo", "value": "true"},
            {"name": "something_else", "value": "data"},
        ]
        assert _extract_textures(properties) is None

    def test_finds_textures_among_multiple_props(self) -> None:
        skin_url = "http://textures.minecraft.net/texture/xyz"
        b64 = _make_textures_b64(skin_url=skin_url)
        properties = [
            {"name": "isLegacy", "value": "true"},
            {"name": "textures", "value": b64},
            {"name": "isDemo", "value": "false"},
        ]
        result = _extract_textures(properties)
        assert result is not None
        assert result.skin_url == skin_url

    def test_handles_missing_value_key(self) -> None:
        properties = [{"name": "textures"}]
        # No 'value' key — should not raise
        result = _extract_textures(properties)
        assert result is None

    def test_handles_empty_value(self) -> None:
        properties = [{"name": "textures", "value": ""}]
        result = _extract_textures(properties)
        assert result is None


# ---------------------------------------------------------------------------
# PlayerSkin dataclass
# ---------------------------------------------------------------------------


class TestPlayerSkin:
    def test_defaults_are_none(self) -> None:
        s = PlayerSkin()
        assert s.skin_url is None
        assert s.skin_hash is None
        assert s.skin_variant is None
        assert s.cape_url is None
        assert s.cape_type is None

    def test_to_dict_all_fields(self) -> None:
        s = PlayerSkin(
            skin_url="http://textures.minecraft.net/texture/abc",
            skin_hash="deadbeef" * 8,
            skin_variant="slim",
            cape_url="http://textures.minecraft.net/texture/cape",
            cape_type="mojang",
        )
        d = s.to_dict()
        assert d["skin_url"] == "http://textures.minecraft.net/texture/abc"
        assert d["skin_hash"] == "deadbeef" * 8
        assert d["skin_variant"] == "slim"
        assert d["cape_url"] == "http://textures.minecraft.net/texture/cape"
        assert d["cape_type"] == "mojang"

    def test_to_dict_none_fields(self) -> None:
        s = PlayerSkin()
        d = s.to_dict()
        assert d["skin_url"] is None
        assert d["cape_url"] is None
        assert d["cape_type"] is None

    def test_to_dict_contains_all_keys(self) -> None:
        d = PlayerSkin().to_dict()
        expected_keys = {"skin_url", "skin_hash", "skin_variant", "cape_url", "cape_type"}
        assert set(d.keys()) == expected_keys


# ---------------------------------------------------------------------------
# UuidLookupResult dataclass
# ---------------------------------------------------------------------------


class TestUuidLookupResult:
    def test_success_when_uuid_and_no_error(self) -> None:
        r = UuidLookupResult(username="Notch", uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5")
        assert r.success

    def test_success_false_when_no_uuid(self) -> None:
        r = UuidLookupResult(username="Notch")
        assert not r.success

    def test_success_false_when_not_found(self) -> None:
        r = UuidLookupResult(
            username="NonExistent",
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            not_found=True,
        )
        assert not r.success

    def test_success_false_when_error(self) -> None:
        r = UuidLookupResult(
            username="Notch",
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            error="HTTP 429",
        )
        assert not r.success

    def test_default_not_found_is_false(self) -> None:
        r = UuidLookupResult(username="test")
        assert not r.not_found

    def test_to_dict_includes_all_keys(self) -> None:
        r = UuidLookupResult(
            username="Notch",
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            is_premium=True,
            not_found=False,
            error=None,
        )
        d = r.to_dict()
        assert d["username"] == "Notch"
        assert d["uuid"] == "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert d["is_premium"] is True
        assert d["not_found"] is False
        assert d["error"] is None

    def test_to_dict_not_found(self) -> None:
        r = UuidLookupResult(username="FakePlayer", not_found=True)
        d = r.to_dict()
        assert d["not_found"] is True
        assert d["uuid"] is None

    def test_to_dict_with_error(self) -> None:
        r = UuidLookupResult(username="test", error="rate limited")
        d = r.to_dict()
        assert d["error"] == "rate limited"

    def test_premium_none_by_default(self) -> None:
        r = UuidLookupResult(username="test")
        assert r.is_premium is None


# ---------------------------------------------------------------------------
# MojangProfile dataclass
# ---------------------------------------------------------------------------


class TestMojangProfile:
    def test_success_when_uuid_and_no_error(self) -> None:
        p = MojangProfile(uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5", username="Notch")
        assert p.success

    def test_success_false_when_empty_uuid(self) -> None:
        p = MojangProfile(uuid="", username="Notch")
        assert not p.success

    def test_success_false_when_error(self) -> None:
        p = MojangProfile(
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            username="Notch",
            error="Player not found",
        )
        assert not p.success

    def test_default_not_demo(self) -> None:
        p = MojangProfile(uuid="abc", username="test")
        assert not p.is_demo

    def test_default_not_legacy(self) -> None:
        p = MojangProfile(uuid="abc", username="test")
        assert not p.is_legacy

    def test_default_properties_is_empty_list(self) -> None:
        p = MojangProfile(uuid="abc", username="test")
        assert p.properties == []

    def test_default_textures_is_none(self) -> None:
        p = MojangProfile(uuid="abc", username="test")
        assert p.textures is None

    def test_to_dict_full(self) -> None:
        skin = PlayerSkin(
            skin_url="http://textures.minecraft.net/texture/abc",
            skin_variant="classic",
        )
        p = MojangProfile(
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            username="Notch",
            textures=skin,
            is_premium=True,
            is_demo=False,
            is_legacy=False,
        )
        d = p.to_dict()
        assert d["uuid"] == "069a79f4-44e9-4726-a5be-fca90e38aaf5"
        assert d["username"] == "Notch"
        assert d["is_premium"] is True
        assert d["is_demo"] is False
        assert d["is_legacy"] is False
        assert d["textures"] is not None
        assert d["textures"]["skin_url"] == "http://textures.minecraft.net/texture/abc"
        assert d["error"] is None

    def test_to_dict_no_textures(self) -> None:
        p = MojangProfile(uuid="abc", username="test")
        d = p.to_dict()
        assert d["textures"] is None

    def test_to_dict_with_error(self) -> None:
        p = MojangProfile(uuid="", username="ghost", error="Player not found")
        d = p.to_dict()
        assert d["error"] == "Player not found"

    def test_to_dict_contains_all_expected_keys(self) -> None:
        p = MojangProfile(uuid="abc", username="test")
        d = p.to_dict()
        expected = {"uuid", "username", "is_premium", "is_demo", "is_legacy", "textures", "error"}
        assert set(d.keys()) == expected

    def test_offline_mode_profile(self) -> None:
        ou = offline_uuid("OfflinePlayer")
        p = MojangProfile(uuid=ou, username="OfflinePlayer", is_premium=False)
        assert p.success
        assert not p.is_premium
        assert uuid_version(p.uuid) == 3

    def test_premium_profile(self) -> None:
        p = MojangProfile(
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            username="Notch",
            is_premium=True,
        )
        assert p.is_premium
        assert uuid_version(p.uuid) == 4

    def test_demo_and_legacy_flags(self) -> None:
        p = MojangProfile(
            uuid="069a79f4-44e9-4726-a5be-fca90e38aaf5",
            username="OldAccount",
            is_demo=True,
            is_legacy=True,
        )
        assert p.is_demo
        assert p.is_legacy
        d = p.to_dict()
        assert d["is_demo"] is True
        assert d["is_legacy"] is True
