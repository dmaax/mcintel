"""
mcintel.dns.resolver
~~~~~~~~~~~~~~~~~~~~
Full DNS resolution chain for Minecraft server domains.

Covers:
  - SRV record lookup   (_minecraft._tcp.<domain> → host + port)
  - A / AAAA fallback   (when no SRV record exists)
  - CNAME chain tracing (records every hop in the chain)
  - PTR (reverse DNS)   (IP → hostname)
  - NS tracking         (identify the DNS provider)
  - TXT inspection      (SPF, verification tokens, info leaks)
  - IP geolocation      (ipinfo.io — city, ASN, org, datacenter flag)

Usage
-----
    from mcintel.dns.resolver import resolve_server, lookup_ip_geo

    chain = await resolve_server("play.example.com")
    print(chain.resolved_host, chain.resolved_port)
    for r in chain.records:
        print(r.record_type, r.value, r.ttl)

    geo = await lookup_ip_geo("1.2.3.4")
    print(geo.country_code, geo.org, geo.is_datacenter)
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from mcintel.config import settings
from mcintel.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default Minecraft Java port (used when no SRV is found)
_DEFAULT_PORT: int = 25565

# SRV service/protocol prefix for Minecraft Java
_SRV_SERVICE: str = "_minecraft._tcp"

# Maximum number of CNAME hops to follow before declaring a loop
_MAX_CNAME_DEPTH: int = 10

# ipinfo.io base URL
_IPINFO_BASE: str = "https://ipinfo.io"

# HTTP client timeout for geolocation API calls (seconds)
_GEO_HTTP_TIMEOUT: float = 8.0

# Cache TTL for geolocation results (seconds) — avoids hammering the API
# during a scanning session.  Entries older than this will be re-fetched.
_GEO_CACHE_TTL: int = 3600  # 1 hour

# Known DDoS-protection / proxy ASN keywords (case-insensitive)
_PROTECTION_KEYWORDS: tuple[str, ...] = (
    "tcpshield",
    "cosmic guard",
    "neoprotect",
    "ovh",
    "path.net",
    "cloudflare",
    "akamai",
    "imperva",
    "fastly",
    "incapsula",
)

# Known datacenter / hosting organisation substrings
_DATACENTER_KEYWORDS: tuple[str, ...] = (
    "hetzner",
    "contabo",
    "digitalocean",
    "linode",
    "akamai",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "vultr",
    "scaleway",
    "ovh",
    "online.net",
    "leaseweb",
    "serverius",
    "choopa",
    "psychz",
    "quadranet",
    "datacamp",
    "hostinger",
    "ionos",
    "strato",
    "gcore",
    "fastly",
    "cloudflare",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class DnsRecordInfo:
    """
    A single DNS record observation from the resolution chain.

    ``record_type`` is one of: A, AAAA, CNAME, SRV, TXT, NS, PTR, MX.
    ``value``       is the RDATA as a human-readable string.
    """

    domain: str
    record_type: str
    value: str
    ttl: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
        }


@dataclass
class ResolutionChain:
    """
    The complete DNS resolution result for a Minecraft server address.

    After calling ``resolve_server("play.example.com")``:
      - ``resolved_host``  is the final A/AAAA target (may equal the input)
      - ``resolved_port``  is the TCP port to connect to (from SRV or default)
      - ``resolved_ips``   is the list of IPv4/IPv6 addresses for the host
      - ``records``        contains every DNS record observed during resolution
      - ``srv_used``       is True when an SRV record drove the lookup
      - ``error``          is set if the overall resolution failed
    """

    input_host: str
    input_port: int

    # Final connection target
    resolved_host: str = ""
    resolved_port: int = _DEFAULT_PORT
    resolved_ips: list[str] = field(default_factory=list)

    # Full record trace
    records: list[DnsRecordInfo] = field(default_factory=list)

    # Flags
    srv_used: bool = False
    cname_chain: list[str] = field(default_factory=list)

    # Error (None on success)
    error: str | None = None

    @property
    def success(self) -> bool:
        return bool(self.resolved_ips) and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_host": self.input_host,
            "input_port": self.input_port,
            "resolved_host": self.resolved_host,
            "resolved_port": self.resolved_port,
            "resolved_ips": self.resolved_ips,
            "srv_used": self.srv_used,
            "cname_chain": self.cname_chain,
            "records": [r.to_dict() for r in self.records],
            "error": self.error,
        }


@dataclass
class IpGeoInfo:
    """
    Geolocation and network metadata for a single IP address.

    Populated from ipinfo.io (or a fallback provider if the token is absent).
    """

    ip: str

    # Geolocation
    city: str | None = None
    region: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    postal_code: str | None = None

    # Network
    asn: str | None = None  # e.g. "AS16276"
    org: str | None = None  # e.g. "AS16276 OVH SAS"
    hostname: str | None = None  # reverse DNS from ipinfo

    # Classification
    is_datacenter: bool | None = None
    is_vpn: bool | None = None
    is_proxy: bool | None = None
    is_tor: bool | None = None
    protection_provider: str | None = None

    # Source
    data_source: str = "ipinfo"
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and self.country_code is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "city": self.city,
            "region": self.region,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "timezone": self.timezone,
            "postal_code": self.postal_code,
            "asn": self.asn,
            "org": self.org,
            "hostname": self.hostname,
            "is_datacenter": self.is_datacenter,
            "is_vpn": self.is_vpn,
            "is_proxy": self.is_proxy,
            "is_tor": self.is_tor,
            "protection_provider": self.protection_provider,
            "data_source": self.data_source,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Module-level geo cache
# ---------------------------------------------------------------------------

import time as _time

_geo_cache: dict[str, tuple[IpGeoInfo, float]] = {}


# ---------------------------------------------------------------------------
# Internal DNS helpers
# ---------------------------------------------------------------------------


def _is_ip_address(host: str) -> bool:
    """Return True if *host* is a bare IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _strip_trailing_dot(name: str) -> str:
    """Remove a trailing dot from a DNS name."""
    return name.rstrip(".")


async def _query(
    resolver: dns.asyncresolver.Resolver,
    name: str,
    rdtype: str,
) -> dns.resolver.Answer | None:
    """
    Perform a single DNS query.

    Returns the Answer on success, or None if the name/type doesn't exist.
    Propagates unexpected exceptions to the caller.
    """
    try:
        return await resolver.resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None
    except dns.exception.DNSException as exc:
        log.debug("DNS query error", name=name, rdtype=rdtype, error=str(exc))
        return None


# ---------------------------------------------------------------------------
# SRV lookup
# ---------------------------------------------------------------------------


async def _lookup_srv(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
    chain: ResolutionChain,
) -> tuple[str | None, int | None]:
    """
    Query the ``_minecraft._tcp.<domain>`` SRV record.

    On success, returns ``(target_host, port)`` and appends a record to
    *chain*.  Returns ``(None, None)`` if no SRV record exists.
    """
    srv_name = f"{_SRV_SERVICE}.{domain}"
    answer = await _query(resolver, srv_name, "SRV")

    if not answer:
        return None, None

    # Pick the highest-priority (lowest priority value) record.
    # If multiple records share the same priority, pick the one with
    # the highest weight as a simple tie-break.
    best = sorted(answer, key=lambda r: (r.priority, -r.weight))[0]  # type: ignore[attr-defined]

    target = _strip_trailing_dot(str(best.target))  # type: ignore[attr-defined]
    port: int = best.port  # type: ignore[attr-defined]

    srv_value = f"{best.priority} {best.weight} {port} {target}"  # type: ignore[attr-defined]

    chain.records.append(
        DnsRecordInfo(
            domain=srv_name,
            record_type="SRV",
            value=srv_value,
            ttl=answer.rrset.ttl if answer.rrset else None,
        )
    )

    log.debug("SRV record found", domain=domain, target=target, port=port)
    return target, port


# ---------------------------------------------------------------------------
# CNAME chain follower
# ---------------------------------------------------------------------------


async def _follow_cname_chain(
    resolver: dns.asyncresolver.Resolver,
    name: str,
    chain: ResolutionChain,
    depth: int = 0,
) -> str:
    """
    Follow CNAME records starting from *name* until we reach a non-CNAME.

    Returns the final canonical name.
    Records every CNAME hop in *chain*.
    """
    if depth > _MAX_CNAME_DEPTH:
        log.warning("CNAME chain too deep — possible loop", start=name, depth=depth)
        return name

    answer = await _query(resolver, name, "CNAME")
    if not answer:
        return name  # no CNAME — this is the canonical name

    target = _strip_trailing_dot(str(answer[0].target))  # type: ignore[attr-defined]

    chain.records.append(
        DnsRecordInfo(
            domain=name,
            record_type="CNAME",
            value=target,
            ttl=answer.rrset.ttl if answer.rrset else None,
        )
    )
    chain.cname_chain.append(target)

    log.debug("CNAME hop", from_name=name, to_name=target, depth=depth)

    # Recurse
    return await _follow_cname_chain(resolver, target, chain, depth + 1)


# ---------------------------------------------------------------------------
# A / AAAA lookup
# ---------------------------------------------------------------------------


async def _lookup_addresses(
    resolver: dns.asyncresolver.Resolver,
    host: str,
    chain: ResolutionChain,
) -> list[str]:
    """
    Resolve A (IPv4) and AAAA (IPv6) records for *host*.

    Appends all records to *chain* and returns a flat list of IP strings.
    """
    ips: list[str] = []

    for rdtype in ("A", "AAAA"):
        answer = await _query(resolver, host, rdtype)
        if not answer:
            continue
        ttl = answer.rrset.ttl if answer.rrset else None
        for rdata in answer:
            ip_str = str(rdata.address)  # type: ignore[attr-defined]
            chain.records.append(
                DnsRecordInfo(domain=host, record_type=rdtype, value=ip_str, ttl=ttl)
            )
            ips.append(ip_str)

    return ips


# ---------------------------------------------------------------------------
# PTR (reverse DNS)
# ---------------------------------------------------------------------------


async def _lookup_ptr(
    resolver: dns.asyncresolver.Resolver,
    ip: str,
    chain: ResolutionChain,
) -> str | None:
    """
    Perform a PTR (reverse DNS) lookup for *ip*.

    Returns the hostname string (without trailing dot) or None.
    """
    try:
        ptr_name = dns.reversename.from_address(ip)
    except (ValueError, dns.exception.DNSException):
        return None

    answer = await _query(resolver, str(ptr_name), "PTR")
    if not answer:
        return None

    hostname = _strip_trailing_dot(str(answer[0]))  # type: ignore[index]

    chain.records.append(
        DnsRecordInfo(
            domain=str(ptr_name),
            record_type="PTR",
            value=hostname,
            ttl=answer.rrset.ttl if answer.rrset else None,
        )
    )
    log.debug("PTR record", ip=ip, hostname=hostname)
    return hostname


# ---------------------------------------------------------------------------
# NS records
# ---------------------------------------------------------------------------


async def _lookup_ns(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
    chain: ResolutionChain,
) -> list[str]:
    """
    Look up NS records for *domain*.

    Records each nameserver in *chain* and returns the list.
    """
    answer = await _query(resolver, domain, "NS")
    if not answer:
        return []

    nameservers: list[str] = []
    ttl = answer.rrset.ttl if answer.rrset else None

    for rdata in answer:
        ns = _strip_trailing_dot(str(rdata.target))  # type: ignore[attr-defined]
        nameservers.append(ns)
        chain.records.append(DnsRecordInfo(domain=domain, record_type="NS", value=ns, ttl=ttl))

    log.debug("NS records", domain=domain, nameservers=nameservers)
    return nameservers


# ---------------------------------------------------------------------------
# TXT records
# ---------------------------------------------------------------------------


async def _lookup_txt(
    resolver: dns.asyncresolver.Resolver,
    domain: str,
    chain: ResolutionChain,
) -> list[str]:
    """
    Look up TXT records for *domain*.

    Returns the list of TXT string values and records them in *chain*.
    """
    answer = await _query(resolver, domain, "TXT")
    if not answer:
        return []

    txt_values: list[str] = []
    ttl = answer.rrset.ttl if answer.rrset else None

    for rdata in answer:
        # Each TXT record may contain multiple strings — join them
        value = "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)  # type: ignore[attr-defined]
        txt_values.append(value)
        chain.records.append(DnsRecordInfo(domain=domain, record_type="TXT", value=value, ttl=ttl))

    log.debug("TXT records", domain=domain, count=len(txt_values))
    return txt_values


# ---------------------------------------------------------------------------
# IP-is-bare check (skip DNS for raw IPs)
# ---------------------------------------------------------------------------


async def _resolve_bare_ip(
    host: str,
    port: int,
    chain: ResolutionChain,
    resolver: dns.asyncresolver.Resolver,
) -> None:
    """
    Handle the case where *host* is already an IP address.

    No SRV/A/CNAME lookups are needed, but we still do PTR.
    """
    chain.resolved_host = host
    chain.resolved_port = port
    chain.resolved_ips = [host]

    # PTR lookup for reverse DNS
    await _lookup_ptr(resolver, host, chain)


# ---------------------------------------------------------------------------
# Main public resolver
# ---------------------------------------------------------------------------


async def resolve_server(
    host: str,
    port: int = _DEFAULT_PORT,
    *,
    lookup_ns: bool = True,
    lookup_txt: bool = True,
    lookup_ptr: bool = True,
    timeout: float = 5.0,
) -> ResolutionChain:
    """
    Perform a full DNS resolution chain for a Minecraft server address.

    Resolution strategy
    -------------------
    1. If *host* is a bare IP address, skip to step 5.
    2. Query ``_minecraft._tcp.<host>`` for an SRV record.
       - If found, update *host* and *port* from the SRV target.
    3. Follow any CNAME chain on the (possibly updated) host.
    4. Resolve A / AAAA records on the canonical name.
    5. Optionally look up PTR on each resolved IP.
    6. Optionally look up NS and TXT on the original domain.

    Parameters
    ----------
    host:
        The server address as entered by the user (domain or IP).
    port:
        Starting port (overridden by SRV if an SRV record exists).
    lookup_ns:
        Whether to query NS records.
    lookup_txt:
        Whether to query TXT records.
    lookup_ptr:
        Whether to query PTR records on resolved IPs.
    timeout:
        DNS query timeout in seconds.

    Returns
    -------
    ResolutionChain
        Full record of every DNS hop. ``chain.success`` is True when at
        least one IP was resolved without error.
    """
    chain = ResolutionChain(input_host=host, input_port=port)

    # Configure a resolver instance with the requested timeout
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        # ── Bare IP — nothing to resolve ────────────────────────────────────
        if _is_ip_address(host):
            log.debug("Host is a bare IP, skipping DNS resolution", host=host)
            await _resolve_bare_ip(host, port, chain, resolver)

            if lookup_ns or lookup_txt:
                # For bare IPs these make no sense at the IP level, skip them
                pass

            return chain

        log.debug("Resolving DNS chain", host=host, port=port)

        # ── Step 1: SRV lookup ───────────────────────────────────────────────
        srv_host, srv_port = await _lookup_srv(resolver, host, chain)

        if srv_host and srv_port:
            chain.srv_used = True
            chain.resolved_port = srv_port
            # Use the SRV target as the name to resolve further
            resolution_name = srv_host
        else:
            chain.resolved_port = port
            resolution_name = host

        # ── Step 2: Follow CNAME chain ───────────────────────────────────────
        canonical = await _follow_cname_chain(resolver, resolution_name, chain)
        chain.resolved_host = canonical

        # ── Step 3: A / AAAA lookup ──────────────────────────────────────────
        ips = await _lookup_addresses(resolver, canonical, chain)

        if not ips:
            # Some servers use bare IPs in SRV targets — try the original host too
            if canonical != host:
                ips = await _lookup_addresses(resolver, host, chain)

        chain.resolved_ips = ips

        if not ips:
            chain.error = f"No A/AAAA records found for {canonical!r}"
            log.debug("No IP addresses resolved", host=host, canonical=canonical)
        else:
            log.debug("Resolved IPs", host=host, ips=ips)

        # ── Step 4: Optional PTR lookups ─────────────────────────────────────
        if lookup_ptr and ips:
            # Only PTR the first IP to avoid excessive queries
            await _lookup_ptr(resolver, ips[0], chain)

        # ── Step 5: Optional NS lookup ───────────────────────────────────────
        if lookup_ns:
            await _lookup_ns(resolver, host, chain)

        # ── Step 6: Optional TXT lookup ──────────────────────────────────────
        if lookup_txt:
            await _lookup_txt(resolver, host, chain)

    except dns.exception.DNSException as exc:
        chain.error = f"DNS error: {exc}"
        log.warning("DNS resolution failed", host=host, error=str(exc))

    except Exception as exc:
        chain.error = f"Unexpected resolver error: {exc}"
        log.error("Unexpected DNS error", host=host, error=str(exc), exc_info=True)

    return chain


# ---------------------------------------------------------------------------
# IP Geolocation (ipinfo.io)
# ---------------------------------------------------------------------------


def _parse_ipinfo_response(ip: str, data: dict[str, Any]) -> IpGeoInfo:
    """
    Build an ``IpGeoInfo`` from an ipinfo.io JSON response dict.
    """
    info = IpGeoInfo(ip=ip, data_source="ipinfo")

    info.city = data.get("city") or None
    info.region = data.get("region") or None
    info.country_code = data.get("country") or None
    info.postal_code = data.get("postal") or None
    info.timezone = data.get("timezone") or None
    info.hostname = data.get("hostname") or None

    # Coordinates — ipinfo returns "lat,lon" as a string
    loc: str | None = data.get("loc")
    if loc and "," in loc:
        try:
            lat_str, lon_str = loc.split(",", 1)
            info.latitude = float(lat_str)
            info.longitude = float(lon_str)
        except (ValueError, TypeError):
            pass

    # ASN / org — ipinfo returns "AS16276 OVH SAS"
    org: str | None = data.get("org")
    if org:
        info.org = org
        parts = org.split(" ", 1)
        if parts[0].startswith("AS"):
            info.asn = parts[0]

    # Privacy block (requires ipinfo paid tier or the privacy endpoint)
    privacy: dict[str, Any] | None = data.get("privacy")
    if isinstance(privacy, dict):
        info.is_vpn = privacy.get("vpn") or False
        info.is_proxy = privacy.get("proxy") or False
        info.is_tor = privacy.get("tor") or False
        info.is_datacenter = privacy.get("hosting") or False

    # Heuristic datacenter detection from org name (fallback for free tier)
    if info.is_datacenter is None and info.org:
        org_lower = info.org.lower()
        info.is_datacenter = any(kw in org_lower for kw in _DATACENTER_KEYWORDS)

    # Detect DDoS protection / proxy provider from org name
    if info.org:
        org_lower = info.org.lower()
        for kw in _PROTECTION_KEYWORDS:
            if kw in org_lower:
                info.protection_provider = kw.title()
                break

    return info


async def lookup_ip_geo(
    ip: str,
    *,
    use_cache: bool = True,
    timeout: float = _GEO_HTTP_TIMEOUT,
) -> IpGeoInfo:
    """
    Fetch geolocation and network metadata for an IP address from ipinfo.io.

    Results are cached in-memory for ``_GEO_CACHE_TTL`` seconds to prevent
    redundant API calls within a scanning session.

    Parameters
    ----------
    ip:
        The IP address to look up (IPv4 or IPv6).
    use_cache:
        Whether to serve results from the in-memory cache.
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    IpGeoInfo
        Always returns an object.  Check ``info.success`` for status.
    """
    # ── Cache check ──────────────────────────────────────────────────────────
    if use_cache and ip in _geo_cache:
        cached_info, cached_at = _geo_cache[ip]
        age = _time.monotonic() - cached_at
        if age < _GEO_CACHE_TTL:
            log.debug("Geo cache hit", ip=ip, age_s=round(age, 1))
            return cached_info

    info = IpGeoInfo(ip=ip)

    # ── Build URL ────────────────────────────────────────────────────────────
    url = f"{_IPINFO_BASE}/{ip}/json"
    headers: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": "mcintel/0.1 (https://mcin.tel; research)",
    }
    if settings.ipinfo_token:
        headers["Authorization"] = f"Bearer {settings.ipinfo_token}"

    log.debug("Fetching IP geolocation", ip=ip)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data: dict[str, Any] = response.json()

        info = _parse_ipinfo_response(ip, data)

        log.debug(
            "Geo lookup complete",
            ip=ip,
            country=info.country_code,
            org=info.org,
            datacenter=info.is_datacenter,
        )

    except httpx.HTTPStatusError as exc:
        info.error = f"HTTP {exc.response.status_code}: {exc.response.text[:120]}"
        log.warning("IP geo lookup HTTP error", ip=ip, status=exc.response.status_code)

    except httpx.TimeoutException:
        info.error = f"HTTP request timed out after {timeout}s"
        log.warning("IP geo lookup timed out", ip=ip)

    except httpx.RequestError as exc:
        info.error = f"HTTP request error: {exc}"
        log.warning("IP geo lookup request error", ip=ip, error=str(exc))

    except Exception as exc:
        info.error = f"Unexpected error: {exc}"
        log.error("IP geo lookup unexpected error", ip=ip, error=str(exc), exc_info=True)

    # ── Store in cache (even failed results, to avoid hammering on errors) ───
    if use_cache:
        _geo_cache[ip] = (info, _time.monotonic())

    return info


# ---------------------------------------------------------------------------
# Convenience: resolve + geolocate in one shot
# ---------------------------------------------------------------------------


async def resolve_and_geolocate(
    host: str,
    port: int = _DEFAULT_PORT,
    *,
    timeout: float = 5.0,
    geo_timeout: float = _GEO_HTTP_TIMEOUT,
) -> tuple[ResolutionChain, list[IpGeoInfo]]:
    """
    Resolve a server's DNS chain and geolocate all discovered IPs.

    Returns ``(chain, geo_results)`` where *geo_results* maps to
    ``chain.resolved_ips`` in the same order.

    Parameters
    ----------
    host:
        Server hostname or IP.
    port:
        Starting port.
    timeout:
        DNS query timeout.
    geo_timeout:
        HTTP timeout for geolocation API calls.

    Returns
    -------
    tuple[ResolutionChain, list[IpGeoInfo]]
    """
    chain = await resolve_server(host, port, timeout=timeout)

    geo_tasks = [lookup_ip_geo(ip, timeout=geo_timeout) for ip in chain.resolved_ips]
    geo_results: list[IpGeoInfo] = list(await asyncio.gather(*geo_tasks))

    return chain, geo_results
