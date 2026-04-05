"""
tests.test_dns
~~~~~~~~~~~~~~
Unit tests for mcintel.dns.resolver helpers and mcintel.scanner.bedrock
advertisement / packet parsing.  No network connections are made.
"""

from __future__ import annotations

import struct

import pytest

from mcintel.dns.resolver import (
    DnsRecordInfo,
    IpGeoInfo,
    ResolutionChain,
    _is_ip_address,
    _parse_ipinfo_response,
    _strip_trailing_dot,
)
from mcintel.scanner.bedrock import (
    _PKT_UNCONNECTED_PING,
    _PKT_UNCONNECTED_PONG,
    _RAKNET_MAGIC,
    BedrockResult,
    _build_unconnected_ping,
    _parse_advertisement,
    _parse_pong,
)

# ---------------------------------------------------------------------------
# _is_ip_address
# ---------------------------------------------------------------------------


class TestIsIpAddress:
    def test_ipv4(self) -> None:
        assert _is_ip_address("192.168.1.1")

    def test_ipv4_loopback(self) -> None:
        assert _is_ip_address("127.0.0.1")

    def test_ipv4_broadcast(self) -> None:
        assert _is_ip_address("255.255.255.255")

    def test_ipv4_zeros(self) -> None:
        assert _is_ip_address("0.0.0.0")

    def test_ipv6_full(self) -> None:
        assert _is_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_ipv6_compressed(self) -> None:
        assert _is_ip_address("::1")

    def test_ipv6_loopback(self) -> None:
        assert _is_ip_address("::1")

    def test_ipv6_partial_compressed(self) -> None:
        assert _is_ip_address("2001:db8::1")

    def test_hostname_is_not_ip(self) -> None:
        assert not _is_ip_address("play.hypixel.net")

    def test_domain_with_subdomain(self) -> None:
        assert not _is_ip_address("mc.example.com")

    def test_empty_string(self) -> None:
        assert not _is_ip_address("")

    def test_partial_ipv4(self) -> None:
        assert not _is_ip_address("192.168.1")

    def test_ipv4_with_port(self) -> None:
        # host:port is not a bare IP
        assert not _is_ip_address("192.168.1.1:25565")

    def test_localhost(self) -> None:
        assert not _is_ip_address("localhost")

    def test_number_only(self) -> None:
        # A plain integer is not an IP address
        assert not _is_ip_address("12345")


# ---------------------------------------------------------------------------
# _strip_trailing_dot
# ---------------------------------------------------------------------------


class TestStripTrailingDot:
    def test_strips_single_dot(self) -> None:
        assert _strip_trailing_dot("example.com.") == "example.com"

    def test_no_dot(self) -> None:
        assert _strip_trailing_dot("example.com") == "example.com"

    def test_empty_string(self) -> None:
        assert _strip_trailing_dot("") == ""

    def test_only_dot(self) -> None:
        assert _strip_trailing_dot(".") == ""

    def test_multiple_trailing_dots(self) -> None:
        # rstrip removes all trailing dots
        assert _strip_trailing_dot("example.com...") == "example.com"

    def test_dot_in_middle_preserved(self) -> None:
        assert _strip_trailing_dot("sub.example.com.") == "sub.example.com"

    def test_root_dot(self) -> None:
        # The DNS root "." becomes ""
        assert _strip_trailing_dot(".") == ""

    def test_fully_qualified_srv_target(self) -> None:
        assert _strip_trailing_dot("mc.hypixel.net.") == "mc.hypixel.net"


# ---------------------------------------------------------------------------
# DnsRecordInfo
# ---------------------------------------------------------------------------


class TestDnsRecordInfo:
    def test_to_dict_all_fields(self) -> None:
        rec = DnsRecordInfo(
            domain="play.example.com",
            record_type="A",
            value="1.2.3.4",
            ttl=300,
        )
        d = rec.to_dict()
        assert d["domain"] == "play.example.com"
        assert d["record_type"] == "A"
        assert d["value"] == "1.2.3.4"
        assert d["ttl"] == 300

    def test_to_dict_none_ttl(self) -> None:
        rec = DnsRecordInfo(domain="example.com", record_type="NS", value="ns1.example.com")
        d = rec.to_dict()
        assert d["ttl"] is None

    def test_srv_record_value_format(self) -> None:
        rec = DnsRecordInfo(
            domain="_minecraft._tcp.play.example.com",
            record_type="SRV",
            value="10 5 25565 mc.example.com",
            ttl=60,
        )
        assert "25565" in rec.value
        assert rec.record_type == "SRV"

    def test_txt_record(self) -> None:
        rec = DnsRecordInfo(
            domain="example.com",
            record_type="TXT",
            value="v=spf1 include:_spf.google.com ~all",
            ttl=3600,
        )
        assert rec.record_type == "TXT"
        assert "spf1" in rec.value


# ---------------------------------------------------------------------------
# ResolutionChain
# ---------------------------------------------------------------------------


class TestResolutionChain:
    def _make_chain(self, **kwargs) -> ResolutionChain:
        defaults = {
            "input_host": "play.example.com",
            "input_port": 25565,
        }
        defaults.update(kwargs)
        return ResolutionChain(**defaults)

    def test_success_true_when_ips_and_no_error(self) -> None:
        chain = self._make_chain()
        chain.resolved_ips = ["1.2.3.4"]
        chain.error = None
        assert chain.success

    def test_success_false_when_no_ips(self) -> None:
        chain = self._make_chain()
        chain.resolved_ips = []
        assert not chain.success

    def test_success_false_when_error_set(self) -> None:
        chain = self._make_chain()
        chain.resolved_ips = ["1.2.3.4"]
        chain.error = "DNS timeout"
        assert not chain.success

    def test_default_resolved_port_is_25565(self) -> None:
        chain = self._make_chain()
        assert chain.resolved_port == 25565

    def test_default_srv_used_is_false(self) -> None:
        chain = self._make_chain()
        assert not chain.srv_used

    def test_to_dict_contains_expected_keys(self) -> None:
        chain = self._make_chain()
        chain.resolved_host = "mc.example.com"
        chain.resolved_port = 25565
        chain.resolved_ips = ["1.2.3.4", "1.2.3.5"]
        chain.srv_used = True
        chain.cname_chain = ["alias.example.com"]
        chain.records = [DnsRecordInfo("play.example.com", "A", "1.2.3.4", 300)]

        d = chain.to_dict()
        assert d["input_host"] == "play.example.com"
        assert d["input_port"] == 25565
        assert d["resolved_host"] == "mc.example.com"
        assert d["resolved_port"] == 25565
        assert d["resolved_ips"] == ["1.2.3.4", "1.2.3.5"]
        assert d["srv_used"] is True
        assert d["cname_chain"] == ["alias.example.com"]
        assert len(d["records"]) == 1
        assert d["records"][0]["record_type"] == "A"

    def test_to_dict_records_are_serialised(self) -> None:
        chain = self._make_chain()
        chain.records = [
            DnsRecordInfo("play.example.com", "SRV", "10 5 25565 mc.example.com", 60),
            DnsRecordInfo("mc.example.com", "A", "5.6.7.8", 120),
        ]
        d = chain.to_dict()
        assert d["records"][0]["record_type"] == "SRV"
        assert d["records"][1]["record_type"] == "A"

    def test_empty_chain_to_dict(self) -> None:
        chain = self._make_chain()
        d = chain.to_dict()
        assert d["resolved_ips"] == []
        assert d["records"] == []
        assert d["cname_chain"] == []
        assert d["error"] is None


# ---------------------------------------------------------------------------
# IpGeoInfo
# ---------------------------------------------------------------------------


class TestIpGeoInfo:
    def test_success_true_with_country(self) -> None:
        geo = IpGeoInfo(ip="1.2.3.4", country_code="US")
        assert geo.success

    def test_success_false_without_country(self) -> None:
        geo = IpGeoInfo(ip="1.2.3.4")
        assert not geo.success

    def test_success_false_with_error(self) -> None:
        geo = IpGeoInfo(ip="1.2.3.4", country_code="US", error="rate limited")
        assert not geo.success

    def test_to_dict_all_fields(self) -> None:
        geo = IpGeoInfo(
            ip="1.2.3.4",
            city="Amsterdam",
            region="North Holland",
            country_code="NL",
            country_name="Netherlands",
            latitude=52.3676,
            longitude=4.9041,
            timezone="Europe/Amsterdam",
            postal_code="1011",
            asn="AS1234",
            org="AS1234 Example BV",
            hostname="host.example.com",
            is_datacenter=True,
            is_vpn=False,
            is_proxy=False,
            is_tor=False,
            protection_provider=None,
            data_source="ipinfo",
        )
        d = geo.to_dict()
        assert d["ip"] == "1.2.3.4"
        assert d["city"] == "Amsterdam"
        assert d["country_code"] == "NL"
        assert d["latitude"] == pytest.approx(52.3676)
        assert d["longitude"] == pytest.approx(4.9041)
        assert d["asn"] == "AS1234"
        assert d["org"] == "AS1234 Example BV"
        assert d["is_datacenter"] is True
        assert d["is_vpn"] is False

    def test_to_dict_none_fields(self) -> None:
        geo = IpGeoInfo(ip="10.0.0.1")
        d = geo.to_dict()
        assert d["city"] is None
        assert d["region"] is None
        assert d["country_code"] is None
        assert d["asn"] is None
        assert d["is_datacenter"] is None


# ---------------------------------------------------------------------------
# _parse_ipinfo_response
# ---------------------------------------------------------------------------


class TestParseIpinfoResponse:
    def _base_response(self, **overrides) -> dict:
        data = {
            "ip": "1.2.3.4",
            "city": "Frankfurt",
            "region": "Hesse",
            "country": "DE",
            "loc": "50.1109,8.6821",
            "org": "AS24940 Hetzner Online GmbH",
            "postal": "60311",
            "timezone": "Europe/Berlin",
            "hostname": "static.1.2.3.4.hetzner.com",
        }
        data.update(overrides)
        return data

    def test_basic_parse(self) -> None:
        info = _parse_ipinfo_response("1.2.3.4", self._base_response())
        assert info.ip == "1.2.3.4"
        assert info.city == "Frankfurt"
        assert info.region == "Hesse"
        assert info.country_code == "DE"
        assert info.postal_code == "60311"
        assert info.timezone == "Europe/Berlin"
        assert info.hostname == "static.1.2.3.4.hetzner.com"

    def test_coordinates_parsed(self) -> None:
        info = _parse_ipinfo_response("1.2.3.4", self._base_response())
        assert info.latitude == pytest.approx(50.1109)
        assert info.longitude == pytest.approx(8.6821)

    def test_asn_split_from_org(self) -> None:
        info = _parse_ipinfo_response("1.2.3.4", self._base_response())
        assert info.asn == "AS24940"
        assert info.org == "AS24940 Hetzner Online GmbH"

    def test_org_without_asn_prefix(self) -> None:
        data = self._base_response(org="Some Company")
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.org == "Some Company"
        assert info.asn is None  # No "AS" prefix

    def test_datacenter_detected_from_org(self) -> None:
        # Hetzner is in the DATACENTER_KEYWORDS list
        info = _parse_ipinfo_response("1.2.3.4", self._base_response())
        assert info.is_datacenter is True

    def test_datacenter_not_detected_for_residential(self) -> None:
        data = self._base_response(org="AS12345 Some Home ISP")
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.is_datacenter is False

    def test_cloudflare_protection_detected(self) -> None:
        data = self._base_response(org="AS13335 Cloudflare, Inc.")
        info = _parse_ipinfo_response("172.65.197.160", data)
        assert info.is_datacenter is True
        assert info.protection_provider is not None
        assert "cloudflare" in info.protection_provider.lower()

    def test_ovh_detected(self) -> None:
        data = self._base_response(org="AS16276 OVH SAS")
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.is_datacenter is True
        assert info.protection_provider is not None

    def test_missing_loc_field(self) -> None:
        data = self._base_response()
        del data["loc"]
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.latitude is None
        assert info.longitude is None

    def test_malformed_loc_field(self) -> None:
        data = self._base_response(loc="not-valid")
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.latitude is None
        assert info.longitude is None

    def test_privacy_block_datacenter(self) -> None:
        data = self._base_response(
            privacy={"vpn": False, "proxy": False, "tor": False, "hosting": True}
        )
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.is_datacenter is True
        assert info.is_vpn is False
        assert info.is_proxy is False
        assert info.is_tor is False

    def test_privacy_block_vpn(self) -> None:
        data = self._base_response(
            privacy={"vpn": True, "proxy": False, "tor": False, "hosting": False}
        )
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.is_vpn is True
        assert info.is_datacenter is False

    def test_privacy_block_tor(self) -> None:
        data = self._base_response(
            privacy={"vpn": False, "proxy": False, "tor": True, "hosting": False}
        )
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.is_tor is True

    def test_empty_response(self) -> None:
        info = _parse_ipinfo_response("1.2.3.4", {})
        assert info.ip == "1.2.3.4"
        assert info.city is None
        assert info.country_code is None

    def test_digitalocean_detected(self) -> None:
        data = self._base_response(org="AS14061 DigitalOcean, LLC")
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.is_datacenter is True

    def test_data_source_is_ipinfo(self) -> None:
        info = _parse_ipinfo_response("1.2.3.4", self._base_response())
        assert info.data_source == "ipinfo"

    def test_negative_coordinates(self) -> None:
        # Southern hemisphere
        data = self._base_response(loc="-33.8688,151.2093")
        info = _parse_ipinfo_response("1.2.3.4", data)
        assert info.latitude == pytest.approx(-33.8688)
        assert info.longitude == pytest.approx(151.2093)


# ---------------------------------------------------------------------------
# BedrockResult
# ---------------------------------------------------------------------------


class TestBedrockResult:
    def test_default_not_success(self) -> None:
        r = BedrockResult(host="test", port=19132)
        assert not r.success

    def test_success_when_set(self) -> None:
        r = BedrockResult(host="test", port=19132, success=True)
        assert r.success

    def test_address_default_port(self) -> None:
        r = BedrockResult(host="pe.example.com", port=19132)
        assert r.address == "pe.example.com"

    def test_address_custom_port(self) -> None:
        r = BedrockResult(host="pe.example.com", port=19133)
        assert r.address == "pe.example.com:19133"

    def test_to_dict_contains_keys(self) -> None:
        r = BedrockResult(
            host="pe.example.com",
            port=19132,
            success=True,
            version_name="1.21.50",
            version_protocol=712,
            players_online=42,
            players_max=100,
            motd_clean="My Bedrock Server",
            gamemode="Survival",
            edition="bedrock",
        )
        d = r.to_dict()
        assert d["host"] == "pe.example.com"
        assert d["port"] == 19132
        assert d["success"] is True
        assert d["version_name"] == "1.21.50"
        assert d["players_online"] == 42
        assert d["gamemode"] == "Survival"
        assert d["edition"] == "bedrock"

    def test_to_dict_none_fields(self) -> None:
        r = BedrockResult(host="test", port=19132)
        d = r.to_dict()
        assert d["version_name"] is None
        assert d["players_online"] is None
        assert d["motd_clean"] is None

    def test_default_edition_is_bedrock(self) -> None:
        r = BedrockResult(host="test", port=19132)
        assert r.edition == "bedrock"


# ---------------------------------------------------------------------------
# _build_unconnected_ping
# ---------------------------------------------------------------------------


class TestBuildUnconnectedPing:
    def test_packet_id_is_0x01(self) -> None:
        data = _build_unconnected_ping(12345, 67890)
        assert data[0] == 0x01  # _PKT_UNCONNECTED_PING

    def test_length_is_33_bytes(self) -> None:
        # 1 (id) + 8 (timestamp) + 16 (magic) + 8 (client guid) = 33
        data = _build_unconnected_ping(0, 0)
        assert len(data) == 33

    def test_timestamp_encoded_big_endian(self) -> None:
        ts = 1_700_000_000_000  # realistic millisecond timestamp
        data = _build_unconnected_ping(ts, 0)
        # Bytes 1–8 are the timestamp as big-endian int64
        extracted_ts = struct.unpack(">q", data[1:9])[0]
        assert extracted_ts == ts

    def test_magic_bytes_correct(self) -> None:
        data = _build_unconnected_ping(0, 0)
        # Bytes 9–24 are the RakNet magic
        magic_in_packet = data[9:25]
        assert magic_in_packet == _RAKNET_MAGIC

    def test_client_guid_encoded_big_endian(self) -> None:
        guid = 0x0102030405060708
        data = _build_unconnected_ping(0, guid)
        # Bytes 25–32 are the client GUID as big-endian int64
        extracted_guid = struct.unpack(">q", data[25:33])[0]
        assert extracted_guid == guid

    def test_different_timestamps_produce_different_packets(self) -> None:
        p1 = _build_unconnected_ping(1000, 42)
        p2 = _build_unconnected_ping(2000, 42)
        assert p1 != p2

    def test_magic_matches_constant(self) -> None:
        data = _build_unconnected_ping(999, 888)
        assert data[9:25] == _RAKNET_MAGIC
        assert len(_RAKNET_MAGIC) == 16

    def test_zero_timestamp_and_guid(self) -> None:
        data = _build_unconnected_ping(0, 0)
        assert data[0] == _PKT_UNCONNECTED_PING
        # All timestamp bytes should be zero
        assert data[1:9] == b"\x00" * 8
        # All guid bytes should be zero
        assert data[25:33] == b"\x00" * 8


# ---------------------------------------------------------------------------
# _parse_advertisement
# ---------------------------------------------------------------------------


class TestParseAdvertisement:
    def _make_result(self) -> BedrockResult:
        return BedrockResult(host="test", port=19132)

    def test_full_modern_advertisement(self) -> None:
        adv = "MCPE;My Bedrock Server;712;1.21.50;42;100;1234567890;World;Survival;1;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)

        assert result.motd_clean == "My Bedrock Server"
        assert result.version_protocol == 712
        assert result.version_name == "1.21.50"
        assert result.players_online == 42
        assert result.players_max == 100
        assert result.motd_sub == "World"
        assert result.gamemode == "Survival"
        assert result.ipv4_port == 19132
        assert result.ipv6_port == 19133
        assert result.edition == "bedrock"

    def test_education_edition_prefix(self) -> None:
        adv = "MCEE;Education Server;712;1.21.50;5;30;1234;Class;Survival;1;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.edition == "education"

    def test_minimal_advertisement(self) -> None:
        # Only the mandatory fields (0–5)
        adv = "MCPE;Simple Server;712;1.21.50;0;20"
        result = self._make_result()
        _parse_advertisement(adv, result)

        assert result.motd_clean == "Simple Server"
        assert result.version_protocol == 712
        assert result.version_name == "1.21.50"
        assert result.players_online == 0
        assert result.players_max == 20
        # Optional fields should be None
        assert result.motd_sub is None
        assert result.gamemode is None
        assert result.ipv4_port is None
        assert result.ipv6_port is None

    def test_creative_gamemode(self) -> None:
        adv = "MCPE;Creative Server;712;1.21.50;1;10;123;level;Creative;1;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.gamemode == "Creative"

    def test_adventure_gamemode(self) -> None:
        adv = "MCPE;Adventure Server;712;1.21.50;1;10;123;level;Adventure;2;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.gamemode == "Adventure"

    def test_numeric_gamemode_0_is_survival(self) -> None:
        adv = "MCPE;Server;712;1.21.50;1;10;123;level;0;0;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.gamemode == "Survival"

    def test_numeric_gamemode_1_is_creative(self) -> None:
        adv = "MCPE;Server;712;1.21.50;1;10;123;level;1;1;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.gamemode == "Creative"

    def test_invalid_protocol_version(self) -> None:
        adv = "MCPE;Server;NOTANUMBER;1.21.50;1;10"
        result = self._make_result()
        _parse_advertisement(adv, result)
        # Should not raise; protocol_version stays None
        assert result.version_protocol is None
        assert result.motd_clean == "Server"

    def test_invalid_player_counts(self) -> None:
        adv = "MCPE;Server;712;1.21.50;NOTANUMBER;ALSONOTANUMBER"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.players_online is None
        assert result.players_max is None

    def test_whitespace_in_motd_stripped(self) -> None:
        adv = "MCPE;  My Server  ;712;1.21.50;0;10"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.motd_clean == "My Server"

    def test_empty_version_name_becomes_none(self) -> None:
        adv = "MCPE;Server;712;;0;10"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.version_name is None

    def test_zero_players_online(self) -> None:
        adv = "MCPE;Empty Server;712;1.21;0;500"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.players_online == 0
        assert result.players_max == 500

    def test_high_player_counts(self) -> None:
        adv = "MCPE;Huge Server;712;1.21;99999;100000"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.players_online == 99999
        assert result.players_max == 100000

    def test_motd_with_unicode(self) -> None:
        adv = "MCPE;§lBold §cRed;712;1.21;5;50"
        result = self._make_result()
        _parse_advertisement(adv, result)
        # Raw string (§ is kept — stripping happens at a higher level)
        assert "Bold" in result.motd_clean or "§" in result.motd_clean

    def test_nethergames_style(self) -> None:
        adv = "MCPE;NetherGames Network;748;1.21.50;135;500;1234;Hub;Survival;1;19132;19133"
        result = self._make_result()
        _parse_advertisement(adv, result)
        assert result.motd_clean == "NetherGames Network"
        assert result.version_protocol == 748
        assert result.players_online == 135


# ---------------------------------------------------------------------------
# _parse_pong
# ---------------------------------------------------------------------------


def _build_valid_pong(
    server_guid: int = 0x0EADBEEFCAFEBABE,
    adv: str = "MCPE;Test;712;1.21;1;10;1234;World;Survival;1;19132;19133",
) -> bytes:
    """Build a minimal valid Unconnected Pong datagram for testing."""
    echo_ts = struct.pack(">q", 12345)  # bytes 1–8
    guid_bytes = struct.pack(">q", server_guid)  # bytes 9–16
    adv_encoded = adv.encode("utf-8")
    str_len = struct.pack(">H", len(adv_encoded))

    return (
        bytes([_PKT_UNCONNECTED_PONG])  # byte 0: packet id 0x1C
        + echo_ts  # bytes 1–8: echo timestamp
        + guid_bytes  # bytes 9–16: server GUID
        + _RAKNET_MAGIC  # bytes 17–32: magic
        + str_len  # bytes 33–34: string length
        + adv_encoded  # bytes 35+: advertisement
    )


class TestParsePong:
    def _make_result(self) -> BedrockResult:
        return BedrockResult(host="test", port=19132)

    def test_basic_valid_pong(self) -> None:
        data = _build_valid_pong()
        result = self._make_result()
        _parse_pong(data, result)

        assert result.motd_clean == "Test"
        assert result.version_protocol == 712
        assert result.players_online == 1
        assert result.players_max == 10

    def test_server_guid_extracted(self) -> None:
        guid = 0x0102030405060708  # fits in signed int64
        data = _build_valid_pong(server_guid=guid)
        result = self._make_result()
        _parse_pong(data, result)
        assert result.server_guid == guid

    def test_wrong_packet_id_raises(self) -> None:
        data = b"\x00" + b"\x00" * 34  # wrong packet ID
        result = self._make_result()
        with pytest.raises(ValueError, match="Expected pong"):
            _parse_pong(data, result)

    def test_too_short_raises(self) -> None:
        data = b"\x1c\x00\x00"  # only 3 bytes, far too short
        result = self._make_result()
        with pytest.raises(ValueError, match="too short"):
            _parse_pong(data, result)

    def test_advertisement_parsed_via_pong(self) -> None:
        adv = "MCPE;FullPong Server;748;1.21.50;200;500;9999;Hub;Creative;1;19132;19133"
        data = _build_valid_pong(adv=adv)
        result = self._make_result()
        _parse_pong(data, result)

        assert result.motd_clean == "FullPong Server"
        assert result.version_protocol == 748
        assert result.players_online == 200
        assert result.players_max == 500
        assert result.gamemode == "Creative"

    def test_motd_raw_set_to_full_adv_string(self) -> None:
        adv = "MCPE;My Server;712;1.21;0;10"
        data = _build_valid_pong(adv=adv)
        result = self._make_result()
        _parse_pong(data, result)
        assert result.motd_raw == adv

    def test_pong_with_zero_guid(self) -> None:
        data = _build_valid_pong(server_guid=0)
        result = self._make_result()
        _parse_pong(data, result)
        assert result.server_guid == 0

    def test_pong_preserves_edition_from_adv(self) -> None:
        adv = "MCEE;Edu Server;712;1.21;5;30;123;Class;Survival;1;19132;19133"
        data = _build_valid_pong(adv=adv)
        result = self._make_result()
        _parse_pong(data, result)
        assert result.edition == "education"

    def test_truncated_advertisement_does_not_crash(self) -> None:
        # Build a pong where the declared string length exceeds actual data
        echo_ts = struct.pack(">q", 0)
        guid_bytes = struct.pack(">q", 0)
        adv_encoded = b"MCPE;Truncated"
        # Declare a much larger length than what we provide
        str_len = struct.pack(">H", 9999)

        data = (
            bytes([_PKT_UNCONNECTED_PONG])
            + echo_ts
            + guid_bytes
            + _RAKNET_MAGIC
            + str_len
            + adv_encoded  # shorter than declared
        )
        result = self._make_result()
        # Should not raise — _parse_pong clips to available bytes
        _parse_pong(data, result)
        assert result.motd_raw is not None
