"""
mcintel.db.models
~~~~~~~~~~~~~~~~~
SQLAlchemy ORM models for mcintel.

All models use the SQLAlchemy 2.0 ``DeclarativeBase`` / ``mapped_column``
API for full type-annotation support.

Table overview
--------------
  servers            — tracked Minecraft servers (one row per unique host:port:edition)
  server_pings       — timestamped SLP / Bedrock responses for a server
  server_motd_history— deduplicated MOTD change log
  server_favicon_history — deduplicated favicon change log
  players            — known players (uuid is the primary key)
  player_username_history — username changes observed for a player
  player_sightings   — (server, player) observations from SLP sample lists
  dns_records        — historical DNS records for a domain
  ip_metadata        — geolocation / ASN info cached per IP
  port_scan_results  — open/closed port observations per host
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    """Common declarative base shared by all mcintel models."""

    pass


# ---------------------------------------------------------------------------
# Utility mixin — automatic created_at / updated_at timestamps
# ---------------------------------------------------------------------------


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------


class Server(TimestampMixin, Base):
    """
    A tracked Minecraft server.

    The primary natural key is (host, port).  ``host`` is stored as entered
    by the user (may be a domain name or a bare IP).  The resolved IP at the
    time of the last ping is stored in ``resolved_ip``.
    """

    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ── Address ──────────────────────────────────────────────────────────────
    host: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    port: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=25565)
    resolved_ip: Mapped[Optional[str]] = mapped_column(String(45))  # IPv4 or IPv6

    # ── Edition ──────────────────────────────────────────────────────────────
    # "java" | "bedrock" | "unknown"
    edition: Mapped[str] = mapped_column(String(10), nullable=False, default="java")

    # ── Latest snapshot (denormalised for fast lookups) ───────────────────────
    # These mirror the most recent ping row to avoid a join on every read.
    version_name: Mapped[Optional[str]] = mapped_column(String(128))
    version_protocol: Mapped[Optional[int]] = mapped_column(Integer)
    motd_raw: Mapped[Optional[str]] = mapped_column(Text)
    motd_clean: Mapped[Optional[str]] = mapped_column(Text)
    players_online: Mapped[Optional[int]] = mapped_column(Integer)
    players_max: Mapped[Optional[int]] = mapped_column(Integer)
    favicon_hash: Mapped[Optional[str]] = mapped_column(String(64))  # SHA-256 hex
    favicon_b64: Mapped[Optional[str]] = mapped_column(Text)  # data:image/png;base64,…

    # ── Server software fingerprint ──────────────────────────────────────────
    # e.g. "Paper", "Spigot", "Fabric", "Forge", "BungeeCord", "Velocity", …
    software: Mapped[Optional[str]] = mapped_column(String(64))
    is_modded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_proxy: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Monitoring state ─────────────────────────────────────────────────────
    is_online: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_monitored: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_pinged_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_online_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # ── Uptime counters ──────────────────────────────────────────────────────
    ping_count_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ping_count_online: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # ── Opt-out ──────────────────────────────────────────────────────────────
    opted_out: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # ── Relationships ─────────────────────────────────────────────────────────
    pings: Mapped[list[ServerPing]] = relationship(
        "ServerPing", back_populates="server", cascade="all, delete-orphan"
    )
    motd_history: Mapped[list[ServerMotdHistory]] = relationship(
        "ServerMotdHistory", back_populates="server", cascade="all, delete-orphan"
    )
    favicon_history: Mapped[list[ServerFaviconHistory]] = relationship(
        "ServerFaviconHistory", back_populates="server", cascade="all, delete-orphan"
    )
    dns_records: Mapped[list[DnsRecord]] = relationship(
        "DnsRecord", back_populates="server", cascade="all, delete-orphan"
    )
    port_scans: Mapped[list[PortScanResult]] = relationship(
        "PortScanResult", back_populates="server", cascade="all, delete-orphan"
    )
    player_sightings: Mapped[list[PlayerSighting]] = relationship(
        "PlayerSighting", back_populates="server"
    )

    __table_args__ = (
        UniqueConstraint("host", "port", "edition", name="uq_server_host_port_edition"),
        Index("ix_server_resolved_ip", "resolved_ip"),
        Index("ix_server_is_online", "is_online"),
        Index("ix_server_software", "software"),
    )

    def __repr__(self) -> str:
        return f"<Server id={self.id} host={self.host!r} port={self.port} online={self.is_online}>"

    @property
    def address(self) -> str:
        """Human-readable ``host:port`` (omits port if it is the default 25565)."""
        if self.port == 25565:
            return self.host
        return f"{self.host}:{self.port}"

    @property
    def uptime_percent(self) -> float | None:
        """Uptime as a percentage, or None if the server has never been pinged."""
        if self.ping_count_total == 0:
            return None
        return round(self.ping_count_online / self.ping_count_total * 100, 2)


# ---------------------------------------------------------------------------
# server_pings
# ---------------------------------------------------------------------------


class ServerPing(Base):
    """
    One timestamped ping result for a server.

    A new row is appended every time the scanner contacts the server.
    This table grows without bound; prune rows older than
    ``settings.retention_ping_days`` with the housekeeping job.
    """

    __tablename__ = "server_pings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pinged_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # ── Result ───────────────────────────────────────────────────────────────
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    latency_ms: Mapped[Optional[float]] = mapped_column(Float)
    error_msg: Mapped[Optional[str]] = mapped_column(String(256))

    # ── Payload (only populated on success) ──────────────────────────────────
    version_name: Mapped[Optional[str]] = mapped_column(String(128))
    version_protocol: Mapped[Optional[int]] = mapped_column(Integer)
    players_online: Mapped[Optional[int]] = mapped_column(Integer)
    players_max: Mapped[Optional[int]] = mapped_column(Integer)
    # Raw JSON string of players.sample[] — list of {"id": uuid, "name": str}
    players_sample_json: Mapped[Optional[str]] = mapped_column(Text)
    motd_raw: Mapped[Optional[str]] = mapped_column(Text)
    motd_clean: Mapped[Optional[str]] = mapped_column(Text)
    favicon_hash: Mapped[Optional[str]] = mapped_column(String(64))
    # Serialised mod/plugin list (JSON array of {"name": str, "version": str})
    mods_json: Mapped[Optional[str]] = mapped_column(Text)
    # Raw full JSON response from the server
    raw_json: Mapped[Optional[str]] = mapped_column(Text)

    # ── Relationships ─────────────────────────────────────────────────────────
    server: Mapped[Server] = relationship("Server", back_populates="pings")

    __table_args__ = (Index("ix_ping_server_id_pinged_at", "server_id", "pinged_at"),)

    def __repr__(self) -> str:
        return (
            f"<ServerPing id={self.id} server_id={self.server_id} "
            f"success={self.success} pinged_at={self.pinged_at}>"
        )


# ---------------------------------------------------------------------------
# server_motd_history
# ---------------------------------------------------------------------------


class ServerMotdHistory(Base):
    """
    Deduplicated log of MOTD changes.

    A new row is only written when the MOTD differs from the previous entry,
    making this a compact change log rather than a copy of every ping.
    """

    __tablename__ = "server_motd_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    motd_raw: Mapped[str] = mapped_column(Text, nullable=False)
    motd_clean: Mapped[Optional[str]] = mapped_column(Text)

    server: Mapped[Server] = relationship("Server", back_populates="motd_history")

    def __repr__(self) -> str:
        preview = (self.motd_clean or "")[:40]
        return f"<ServerMotdHistory id={self.id} server_id={self.server_id} motd={preview!r}>"


# ---------------------------------------------------------------------------
# server_favicon_history
# ---------------------------------------------------------------------------


class ServerFaviconHistory(Base):
    """
    Deduplicated log of favicon changes.

    A new row is only written when the favicon SHA-256 differs from the
    previous entry.
    """

    __tablename__ = "server_favicon_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    favicon_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256 hex
    favicon_phash: Mapped[Optional[str]] = mapped_column(String(16))  # perceptual hash hex
    favicon_b64: Mapped[Optional[str]] = mapped_column(Text)  # full data URI

    server: Mapped[Server] = relationship("Server", back_populates="favicon_history")

    __table_args__ = (
        Index("ix_favicon_hash", "favicon_hash"),
        Index("ix_favicon_phash", "favicon_phash"),
    )

    def __repr__(self) -> str:
        return (
            f"<ServerFaviconHistory id={self.id} server_id={self.server_id} "
            f"hash={self.favicon_hash[:8]}…>"
        )


# ---------------------------------------------------------------------------
# players
# ---------------------------------------------------------------------------


class Player(TimestampMixin, Base):
    """
    A known Minecraft player.

    ``uuid`` is the Mojang UUID (version 4 for premium, version 3 offline).
    ``username`` is the most recently observed in-game name.
    """

    __tablename__ = "players"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # ── Identity ──────────────────────────────────────────────────────────────
    # Stored as a plain 36-char UUID string (with dashes) for readability.
    uuid: Mapped[str] = mapped_column(String(36), nullable=False, unique=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(16), index=True)

    # ── Profile data ──────────────────────────────────────────────────────────
    # Skin / cape texture URLs from the Mojang session server
    skin_url: Mapped[Optional[str]] = mapped_column(String(512))
    cape_url: Mapped[Optional[str]] = mapped_column(String(512))
    # SHA-256 of the raw skin texture PNG
    skin_hash: Mapped[Optional[str]] = mapped_column(String(64))
    # "default" | "slim"
    skin_variant: Mapped[Optional[str]] = mapped_column(String(10))

    # ── Online / offline mode detection ──────────────────────────────────────
    # True = premium UUID (v4); False = offline/cracked UUID (v3)
    is_premium: Mapped[Optional[bool]] = mapped_column(Boolean)

    # ── Observation metadata ─────────────────────────────────────────────────
    first_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # How many times this player has appeared in an SLP sample list
    sighting_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # ── Mojang API cache ──────────────────────────────────────────────────────
    profile_fetched_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    # ── Relationships ─────────────────────────────────────────────────────────
    username_history: Mapped[list[PlayerUsernameHistory]] = relationship(
        "PlayerUsernameHistory", back_populates="player", cascade="all, delete-orphan"
    )
    sightings: Mapped[list[PlayerSighting]] = relationship(
        "PlayerSighting", back_populates="player"
    )

    def __repr__(self) -> str:
        return f"<Player uuid={self.uuid!r} username={self.username!r}>"


# ---------------------------------------------------------------------------
# player_username_history
# ---------------------------------------------------------------------------


class PlayerUsernameHistory(Base):
    """
    Historical usernames observed for a player UUID.

    Populated from two sources:
      1. SLP sample lists (passive — as players appear in ping results)
      2. Mojang name-change history endpoint (active lookup)
    """

    __tablename__ = "player_username_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    player_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("players.id", ondelete="CASCADE"), nullable=False, index=True
    )
    username: Mapped[str] = mapped_column(String(16), nullable=False)
    # When this username was first observed (not necessarily when it was changed to)
    first_observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Source of this observation: "slp_sample" | "mojang_api" | "manual"
    source: Mapped[str] = mapped_column(String(20), nullable=False, default="slp_sample")

    player: Mapped[Player] = relationship("Player", back_populates="username_history")

    __table_args__ = (
        UniqueConstraint("player_id", "username", name="uq_player_username"),
        Index("ix_username_history_username", "username"),
    )

    def __repr__(self) -> str:
        return (
            f"<PlayerUsernameHistory player_id={self.player_id} "
            f"username={self.username!r} source={self.source!r}>"
        )


# ---------------------------------------------------------------------------
# player_sightings
# ---------------------------------------------------------------------------


class PlayerSighting(Base):
    """
    A single observation of a player on a server.

    Created whenever a player UUID appears in the ``players.sample[]``
    array of an SLP response.
    """

    __tablename__ = "player_sightings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    player_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("players.id", ondelete="CASCADE"), nullable=False, index=True
    )
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ping_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("server_pings.id", ondelete="SET NULL"), nullable=True
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Username as it appeared in the sample list at this moment
    username_at_time: Mapped[Optional[str]] = mapped_column(String(16))

    player: Mapped[Player] = relationship("Player", back_populates="sightings")
    server: Mapped[Server] = relationship("Server", back_populates="player_sightings")

    __table_args__ = (
        Index("ix_sighting_player_server", "player_id", "server_id"),
        Index("ix_sighting_observed_at", "observed_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<PlayerSighting player_id={self.player_id} "
            f"server_id={self.server_id} at={self.observed_at}>"
        )


# ---------------------------------------------------------------------------
# dns_records
# ---------------------------------------------------------------------------


class DnsRecord(Base):
    """
    A single DNS record observation tied to a server.

    New rows are appended whenever the resolved value differs from the
    previous observation (change log semantics).

    ``record_type`` is one of: A, AAAA, CNAME, SRV, TXT, NS, PTR, MX.
    ``value`` is the record's RDATA as a plain string.
    For SRV records, ``value`` stores the full ``priority weight port target``
    string (e.g. ``"10 5 25565 mc.example.com"``).
    """

    __tablename__ = "dns_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(10), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)

    # TTL at time of observation (seconds)
    ttl: Mapped[Optional[int]] = mapped_column(Integer)

    # Lifecycle timestamps
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Set when this record is no longer observed
    expired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    server: Mapped[Server] = relationship("Server", back_populates="dns_records")

    __table_args__ = (
        Index("ix_dns_domain_type", "domain", "record_type"),
        Index("ix_dns_value", "value"),
    )

    def __repr__(self) -> str:
        return (
            f"<DnsRecord id={self.id} domain={self.domain!r} "
            f"type={self.record_type} value={self.value!r}>"
        )


# ---------------------------------------------------------------------------
# ip_metadata
# ---------------------------------------------------------------------------


class IpMetadata(TimestampMixin, Base):
    """
    Cached geolocation and ASN data for an IP address.

    Populated from ipinfo.io (or fallback providers).
    One row per IP; ``updated_at`` is used to decide when to re-fetch.
    """

    __tablename__ = "ip_metadata"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)

    # ── Geolocation ───────────────────────────────────────────────────────────
    city: Mapped[Optional[str]] = mapped_column(String(128))
    region: Mapped[Optional[str]] = mapped_column(String(128))
    country_code: Mapped[Optional[str]] = mapped_column(String(2))  # ISO 3166-1 alpha-2
    country_name: Mapped[Optional[str]] = mapped_column(String(64))
    latitude: Mapped[Optional[float]] = mapped_column(Float)
    longitude: Mapped[Optional[float]] = mapped_column(Float)
    timezone: Mapped[Optional[str]] = mapped_column(String(64))
    postal_code: Mapped[Optional[str]] = mapped_column(String(16))

    # ── Network ───────────────────────────────────────────────────────────────
    asn: Mapped[Optional[str]] = mapped_column(String(16))  # e.g. "AS16276"
    org: Mapped[Optional[str]] = mapped_column(String(256))  # e.g. "OVH SAS"
    hostname: Mapped[Optional[str]] = mapped_column(String(253))  # reverse DNS

    # ── Hosting / proxy classification ────────────────────────────────────────
    is_datacenter: Mapped[Optional[bool]] = mapped_column(Boolean)
    is_vpn: Mapped[Optional[bool]] = mapped_column(Boolean)
    is_proxy: Mapped[Optional[bool]] = mapped_column(Boolean)
    is_tor: Mapped[Optional[bool]] = mapped_column(Boolean)
    # Name of detected DDoS protection / CDN layer (e.g. "TCPShield", "Cloudflare")
    protection_provider: Mapped[Optional[str]] = mapped_column(String(64))

    # ── Source ────────────────────────────────────────────────────────────────
    # "ipinfo" | "ip-api" | "maxmind" | "manual"
    data_source: Mapped[str] = mapped_column(String(16), nullable=False, default="ipinfo")

    def __repr__(self) -> str:
        return (
            f"<IpMetadata ip={self.ip!r} org={self.org!r} "
            f"country={self.country_code!r} datacenter={self.is_datacenter}>"
        )


# ---------------------------------------------------------------------------
# port_scan_results
# ---------------------------------------------------------------------------


class PortScanResult(Base):
    """
    Result of probing a specific TCP/UDP port on a server host.

    Tracks whether common Minecraft-adjacent ports are open and what
    service (if any) was identified there.
    """

    __tablename__ = "port_scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    server_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    port: Mapped[int] = mapped_column(Integer, nullable=False)
    # "tcp" | "udp"
    protocol: Mapped[str] = mapped_column(String(3), nullable=False, default="tcp")
    is_open: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # Service identification
    service_name: Mapped[Optional[str]] = mapped_column(String(64))  # e.g. "dynmap", "rcon"
    banner: Mapped[Optional[str]] = mapped_column(Text)  # raw banner grab

    server: Mapped[Server] = relationship("Server", back_populates="port_scans")

    __table_args__ = (
        Index("ix_port_scan_server_port", "server_id", "port"),
        Index("ix_port_scan_open", "is_open"),
    )

    def __repr__(self) -> str:
        state = "open" if self.is_open else "closed"
        return (
            f"<PortScanResult server_id={self.server_id} port={self.port}/{self.protocol} {state}>"
        )
