"""
mcintel.players.mojang
~~~~~~~~~~~~~~~~~~~~~~
Mojang API integration for player intelligence.

Covers:
  - Username → UUID resolution  (api.mojang.com)
  - UUID → full profile          (sessionserver.mojang.com)
  - Skin & cape URL extraction   (textures property in profile)
  - Offline / cracked UUID detection (UUID version 3 vs 4)
  - In-memory request cache to stay within Mojang rate limits
  - Bulk username → UUID resolution (up to 10 per request)

Mojang API reference
--------------------
  https://wiki.vg/Mojang_API

Rate limits (as of 2024)
------------------------
  - /users/profiles/minecraft/<name>  : ~600 req / 10 min per IP
  - /session/minecraft/profile/<uuid> : ~200 req / min per IP
  - POST /profiles/minecraft (bulk)   : ~200 req / min, 10 names per call

Usage
-----
    from mcintel.players.mojang import MojangClient

    async with MojangClient() as client:
        profile = await client.get_profile_by_username("Notch")
        if profile:
            print(profile.uuid, profile.username, profile.skin_url)

        bulk = await client.get_uuids_bulk(["Notch", "jeb_", "Dinnerbone"])
        for entry in bulk:
            print(entry.username, entry.uuid)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import uuid as _uuid_mod
from dataclasses import dataclass, field
from typing import Any

import httpx

from mcintel.logging import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MOJANG_API_BASE: str = "https://api.mojang.com"
_SESSION_SERVER_BASE: str = "https://sessionserver.mojang.com"

# Minimum delay between requests to the same endpoint (seconds)
# This is a conservative politeness floor — actual Mojang limits are higher.
_MIN_REQUEST_INTERVAL: float = 0.1

# Cache TTL for successful profile lookups (seconds)
_PROFILE_CACHE_TTL: int = 3600  # 1 hour

# Cache TTL for username→UUID lookups
_UUID_CACHE_TTL: int = 3600

# Cache TTL for "player not found" results (avoid hammering for non-existent names)
_NOT_FOUND_CACHE_TTL: int = 300  # 5 minutes

# Maximum usernames per bulk request
_BULK_MAX_NAMES: int = 10

# Minecraft username regex (3–16 chars, alphanumeric + underscore)
_USERNAME_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_]{1,16}$")

# UUID format regex (with or without dashes)
_UUID_RE: re.Pattern[str] = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
    re.IGNORECASE,
)

# Default HTTP request timeout (seconds)
_HTTP_TIMEOUT: float = 10.0


# ---------------------------------------------------------------------------
# UUID utilities
# ---------------------------------------------------------------------------


def normalise_uuid(raw: str) -> str:
    """
    Normalise a UUID string to the canonical 8-4-4-4-12 dash-separated form.

    Accepts both dashed and undashed variants.
    Raises ``ValueError`` if *raw* is not a valid UUID.
    """
    cleaned = raw.replace("-", "").lower()
    if len(cleaned) != 32 or not all(c in "0123456789abcdef" for c in cleaned):
        raise ValueError(f"Invalid UUID: {raw!r}")
    return f"{cleaned[0:8]}-{cleaned[8:12]}-{cleaned[12:16]}-{cleaned[16:20]}-{cleaned[20:32]}"


def uuid_version(uuid_str: str) -> int:
    """
    Return the version field of a UUID (integer 1–5).

    For Minecraft:
      - Version 4 (random)  → premium / online-mode account
      - Version 3 (name-based MD5) → offline / cracked UUID
        (offline UUID = MD5("OfflinePlayer:" + username))
    """
    try:
        u = _uuid_mod.UUID(uuid_str)
        return u.version
    except ValueError:
        return -1


def is_premium_uuid(uuid_str: str) -> bool:
    """
    Return True if the UUID looks like a premium (Mojang-issued) UUID.

    Premium UUIDs are version 4 (randomly generated).
    Cracked / offline-mode UUIDs are version 3.
    """
    return uuid_version(uuid_str) == 4


def offline_uuid(username: str) -> str:
    """
    Compute the offline-mode UUID for a given username.

    Minecraft offline servers use:
        UUID = MD5("OfflinePlayer:<username>")  with version bits set to 3.

    This is the same UUID a player would have if ``online-mode=false``
    on a vanilla server.
    """
    data = f"OfflinePlayer:{username}".encode("utf-8")
    digest = hashlib.md5(data).digest()  # noqa: S324 — intentional, matches MC spec
    # Set version = 3 and variant = RFC 4122
    ba = bytearray(digest)
    ba[6] = (ba[6] & 0x0F) | 0x30  # version 3
    ba[8] = (ba[8] & 0x3F) | 0x80  # RFC 4122 variant
    u = _uuid_mod.UUID(bytes=bytes(ba))
    return str(u)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class PlayerSkin:
    """Texture URLs and metadata for a player's skin and cape."""

    skin_url: str | None = None
    skin_hash: str | None = None  # SHA-256 of raw skin PNG bytes
    skin_variant: str | None = None  # "classic" (Steve) or "slim" (Alex)
    cape_url: str | None = None
    cape_type: str | None = None  # "mojang" | "optifine" | "labymod" | "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "skin_url": self.skin_url,
            "skin_hash": self.skin_hash,
            "skin_variant": self.skin_variant,
            "cape_url": self.cape_url,
            "cape_type": self.cape_type,
        }


@dataclass
class MojangProfile:
    """
    A fully resolved Mojang player profile.

    Combines the UUID lookup result and the profile (textures) endpoint.
    """

    uuid: str  # normalised 8-4-4-4-12 form
    username: str

    # Textures (None if not fetched or not available)
    textures: PlayerSkin | None = None

    # Raw properties list from the profile endpoint
    # Each entry: {"name": str, "value": base64, "signature": base64 | None}
    properties: list[dict[str, Any]] = field(default_factory=list)

    # Metadata
    is_premium: bool | None = None  # based on UUID version
    is_demo: bool = False  # flag set by Mojang for demo accounts
    is_legacy: bool = False  # flag set by Mojang for unmigrated legacy accounts
    profile_fetched_at: float | None = None  # time.monotonic() timestamp

    # Error
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and bool(self.uuid)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "username": self.username,
            "is_premium": self.is_premium,
            "is_demo": self.is_demo,
            "is_legacy": self.is_legacy,
            "textures": self.textures.to_dict() if self.textures else None,
            "error": self.error,
        }


@dataclass
class UuidLookupResult:
    """Result of a username → UUID lookup (no texture data)."""

    username: str
    uuid: str | None = None
    is_premium: bool | None = None
    not_found: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.uuid is not None and not self.not_found and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "uuid": self.uuid,
            "is_premium": self.is_premium,
            "not_found": self.not_found,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Texture / skin parsing helpers
# ---------------------------------------------------------------------------


def _parse_textures_property(b64_value: str) -> PlayerSkin:
    """
    Decode and parse the ``textures`` property from a Mojang profile.

    The value is a base64-encoded JSON string:
    {
        "timestamp": ...,
        "profileId": "...",
        "profileName": "...",
        "textures": {
            "SKIN": {"url": "...", "metadata": {"model": "slim"}},
            "CAPE": {"url": "..."}
        }
    }
    """
    skin = PlayerSkin()
    try:
        decoded = base64.b64decode(b64_value + "==").decode("utf-8")
        data: dict[str, Any] = json.loads(decoded)
        textures: dict[str, Any] = data.get("textures", {})

        skin_data = textures.get("SKIN")
        if isinstance(skin_data, dict):
            skin.skin_url = skin_data.get("url")
            metadata = skin_data.get("metadata", {})
            model = metadata.get("model", "classic") if isinstance(metadata, dict) else "classic"
            skin.skin_variant = model  # "slim" or "classic"

        cape_data = textures.get("CAPE")
        if isinstance(cape_data, dict):
            skin.cape_url = cape_data.get("url")
            # Classify cape type from URL patterns
            skin.cape_type = _classify_cape(skin.cape_url)

    except Exception as exc:
        log.debug("Failed to parse textures property", error=str(exc))

    return skin


def _classify_cape(cape_url: str | None) -> str | None:
    """
    Heuristically identify the cape type from its URL.

    Returns one of: "mojang", "optifine", "labymod", "minecraftcapes", "unknown"
    or None if *cape_url* is falsy.
    """
    if not cape_url:
        return None
    url_lower = cape_url.lower()
    if "textures.minecraft.net" in url_lower:
        return "mojang"
    if "optifine.net" in url_lower:
        return "optifine"
    if "labymod" in url_lower:
        return "labymod"
    if "minecraftcapes.co.uk" in url_lower or "minecraftcapes.net" in url_lower:
        return "minecraftcapes"
    return "unknown"


def _extract_textures(properties: list[dict[str, Any]]) -> PlayerSkin | None:
    """
    Find the ``textures`` property in a Mojang profile properties list and
    return a parsed ``PlayerSkin``, or None if the property is absent.
    """
    for prop in properties:
        if prop.get("name") == "textures":
            value = prop.get("value")
            if isinstance(value, str) and value:
                return _parse_textures_property(value)
    return None


# ---------------------------------------------------------------------------
# Rate-limit aware HTTP client
# ---------------------------------------------------------------------------


class _RateLimiter:
    """
    Simple per-endpoint token bucket rate limiter.

    Ensures at least ``min_interval`` seconds pass between consecutive
    calls to the same endpoint key.
    """

    def __init__(self, min_interval: float = _MIN_REQUEST_INTERVAL) -> None:
        self._min_interval = min_interval
        self._last_call: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, key: str) -> asyncio.Lock:
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    async def acquire(self, key: str) -> None:
        """Wait until the rate limit allows a request for *key*."""
        lock = self._get_lock(key)
        async with lock:
            now = time.monotonic()
            last = self._last_call.get(key, 0.0)
            wait_time = self._min_interval - (now - last)
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self._last_call[key] = time.monotonic()


# ---------------------------------------------------------------------------
# Main client
# ---------------------------------------------------------------------------


class MojangClient:
    """
    Async client for the Mojang player API.

    Provides:
      - ``get_uuid(username)``              — username → UUID
      - ``get_uuids_bulk(usernames)``       — up to 10 usernames at once
      - ``get_profile(uuid)``               — UUID → full profile + textures
      - ``get_profile_by_username(name)``   — combined lookup (UUID then profile)

    All methods cache results in memory to respect Mojang rate limits.
    Use as an async context manager or call ``close()`` when done.

    Example::

        async with MojangClient() as client:
            profile = await client.get_profile_by_username("Notch")
    """

    def __init__(
        self,
        *,
        http_timeout: float = _HTTP_TIMEOUT,
        user_agent: str = "mcintel/0.1 (https://mcin.tel; research)",
    ) -> None:
        self._timeout = http_timeout
        self._headers = {
            "Accept": "application/json",
            "User-Agent": user_agent,
        }
        self._http: httpx.AsyncClient | None = None
        self._rate_limiter = _RateLimiter()

        # In-memory caches: key → (value, stored_at_monotonic)
        self._uuid_cache: dict[str, tuple[UuidLookupResult, float]] = {}
        self._profile_cache: dict[str, tuple[MojangProfile, float]] = {}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def __aenter__(self) -> "MojangClient":
        self._http = httpx.AsyncClient(
            timeout=self._timeout,
            headers=self._headers,
            follow_redirects=True,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _get_uuid_cached(self, username_lower: str) -> UuidLookupResult | None:
        entry = self._uuid_cache.get(username_lower)
        if entry is None:
            return None
        result, stored_at = entry
        ttl = _NOT_FOUND_CACHE_TTL if result.not_found else _UUID_CACHE_TTL
        if time.monotonic() - stored_at > ttl:
            del self._uuid_cache[username_lower]
            return None
        return result

    def _put_uuid_cached(self, username_lower: str, result: UuidLookupResult) -> None:
        # Don't cache transient errors (timeouts, 5xx, network failures).
        # Only cache confirmed hits and confirmed not-found responses so a
        # temporary outage doesn't poison the cache for the full TTL.
        if result.error is not None and not result.not_found:
            return
        self._uuid_cache[username_lower] = (result, time.monotonic())

    def _get_profile_cached(
        self,
        uuid_norm: str,
        *,
        fetch_textures: bool = True,
    ) -> MojangProfile | None:
        entry = self._profile_cache.get(uuid_norm)
        if entry is None:
            return None
        profile, stored_at = entry
        if time.monotonic() - stored_at > _PROFILE_CACHE_TTL:
            del self._profile_cache[uuid_norm]
            return None
        # If the caller wants textures but the cached profile has none, treat
        # it as a cache miss so textures are decoded and the entry refreshed.
        if fetch_textures and profile.textures is None and profile.properties:
            return None
        return profile

    def _put_profile_cached(self, uuid_norm: str, profile: MojangProfile) -> None:
        # Don't cache transient errors — only successful fetches and not-found.
        if profile.error is not None and profile.error != "Player not found":
            return
        self._profile_cache[uuid_norm] = (profile, time.monotonic())

    # ── HTTP helper ───────────────────────────────────────────────────────────

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            # Allow use without context manager — create a one-shot client
            self._http = httpx.AsyncClient(
                timeout=self._timeout,
                headers=self._headers,
                follow_redirects=True,
            )
        return self._http

    async def _get_json(
        self,
        url: str,
        rate_key: str,
        *,
        allow_404: bool = False,
    ) -> tuple[dict[str, Any] | None, int]:
        """
        Perform a rate-limited GET request and return ``(json_body, status_code)``.

        Returns ``(None, status_code)`` on 404 (when *allow_404* is True) or
        on non-JSON responses.
        Raises ``httpx.HTTPStatusError`` for other 4xx/5xx errors.
        """
        await self._rate_limiter.acquire(rate_key)

        response = await self._client().get(url)

        if response.status_code == 404 and allow_404:
            return None, 404

        if response.status_code == 204:
            # 204 No Content — player not found (older Mojang API behaviour)
            return None, 204

        response.raise_for_status()

        try:
            return response.json(), response.status_code
        except Exception:
            return None, response.status_code

    async def _post_json(
        self,
        url: str,
        body: Any,
        rate_key: str,
    ) -> tuple[list[Any] | None, int]:
        """
        Perform a rate-limited POST request with a JSON body.

        Returns ``(json_body, status_code)``.
        """
        await self._rate_limiter.acquire(rate_key)

        response = await self._client().post(
            url,
            json=body,
            headers={**self._headers, "Content-Type": "application/json"},
        )
        response.raise_for_status()

        try:
            return response.json(), response.status_code
        except Exception:
            return None, response.status_code

    # ── UUID lookup ───────────────────────────────────────────────────────────

    async def get_uuid(self, username: str) -> UuidLookupResult:
        """
        Resolve a Minecraft username to a Mojang UUID.

        Uses ``GET /users/profiles/minecraft/<username>``.

        Parameters
        ----------
        username:
            The in-game name to look up (case-insensitive).

        Returns
        -------
        UuidLookupResult
            ``result.success`` is True when the player was found.
            ``result.not_found`` is True when the API confirms the player
            does not exist (or has never existed under that name).
        """
        key = username.lower()

        # ── Cache check ───────────────────────────────────────────────────────
        cached = self._get_uuid_cached(key)
        if cached is not None:
            log.debug("UUID cache hit", username=username)
            return cached

        result = UuidLookupResult(username=username)

        log.debug("Looking up UUID", username=username)

        try:
            url = f"{_MOJANG_API_BASE}/users/profiles/minecraft/{username}"
            data, status = await self._get_json(url, rate_key="uuid_lookup", allow_404=True)

            if status == 404 or data is None:
                result.not_found = True
                log.debug("Player not found", username=username)
            else:
                raw_uuid = data.get("id", "")
                result.uuid = normalise_uuid(raw_uuid) if raw_uuid else None
                result.username = data.get("name", username)
                if result.uuid:
                    result.is_premium = is_premium_uuid(result.uuid)
                log.debug(
                    "UUID resolved",
                    username=result.username,
                    uuid=result.uuid,
                    premium=result.is_premium,
                )

        except httpx.HTTPStatusError as exc:
            result.error = f"HTTP {exc.response.status_code}"
            log.warning(
                "UUID lookup HTTP error", username=username, status=exc.response.status_code
            )
        except httpx.TimeoutException:
            result.error = "Request timed out"
            log.warning("UUID lookup timed out", username=username)
        except httpx.RequestError as exc:
            result.error = f"Request error: {exc}"
            log.warning("UUID lookup request error", username=username, error=str(exc))
        except ValueError as exc:
            result.error = f"UUID parse error: {exc}"
            log.warning("UUID parse error", username=username, error=str(exc))
        except Exception as exc:
            result.error = f"Unexpected error: {exc}"
            log.error(
                "UUID lookup unexpected error", username=username, error=str(exc), exc_info=True
            )

        self._put_uuid_cached(key, result)
        return result

    # ── Bulk UUID lookup ──────────────────────────────────────────────────────

    async def get_uuids_bulk(
        self,
        usernames: list[str],
    ) -> list[UuidLookupResult]:
        """
        Resolve up to ``_BULK_MAX_NAMES`` (10) usernames to UUIDs in a single
        POST request.

        Usernames not found in the response are returned with
        ``not_found=True``.  Names already in the cache are served from cache
        without consuming an API request.

        Parameters
        ----------
        usernames:
            List of Minecraft usernames.  Automatically chunked into groups
            of 10 to comply with the API limit.

        Returns
        -------
        List of ``UuidLookupResult`` in the same order as *usernames*.
        """
        if not usernames:
            return []

        results: dict[str, UuidLookupResult] = {}

        # Serve cached entries first
        to_fetch: list[str] = []
        for name in usernames:
            cached = self._get_uuid_cached(name.lower())
            if cached is not None:
                results[name.lower()] = cached
            else:
                to_fetch.append(name)

        # Chunk remaining names into groups of _BULK_MAX_NAMES
        for i in range(0, len(to_fetch), _BULK_MAX_NAMES):
            chunk = to_fetch[i : i + _BULK_MAX_NAMES]
            await self._fetch_bulk_chunk(chunk, results)

        # Reconstruct in original order; mark any still-missing as not_found
        ordered: list[UuidLookupResult] = []
        for name in usernames:
            key = name.lower()
            if key in results:
                ordered.append(results[key])
            else:
                r = UuidLookupResult(username=name, not_found=True)
                self._put_uuid_cached(key, r)
                ordered.append(r)

        return ordered

    async def _fetch_bulk_chunk(
        self,
        names: list[str],
        results: dict[str, UuidLookupResult],
    ) -> None:
        """
        POST a single chunk of up to 10 names to the bulk profiles endpoint.

        Populates *results* (keyed by lowercase name) with the responses.
        """
        url = f"{_MOJANG_API_BASE}/profiles/minecraft"
        log.debug("Bulk UUID lookup", count=len(names), names=names)

        try:
            data, _ = await self._post_json(url, names, rate_key="uuid_bulk")
            if not isinstance(data, list):
                data = []

            found_keys: set[str] = set()
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                raw_uuid = entry.get("id", "")
                username = entry.get("name", "")
                key = username.lower()
                try:
                    norm_uuid = normalise_uuid(raw_uuid) if raw_uuid else None
                except ValueError:
                    norm_uuid = None

                r = UuidLookupResult(
                    username=username,
                    uuid=norm_uuid,
                    is_premium=is_premium_uuid(norm_uuid) if norm_uuid else None,
                )
                results[key] = r
                self._put_uuid_cached(key, r)
                found_keys.add(key)

            # Mark names not present in the response as not found
            for name in names:
                if name.lower() not in found_keys:
                    r = UuidLookupResult(username=name, not_found=True)
                    results[name.lower()] = r
                    self._put_uuid_cached(name.lower(), r)

        except httpx.HTTPStatusError as exc:
            log.warning("Bulk UUID lookup HTTP error", status=exc.response.status_code)
            for name in names:
                results[name.lower()] = UuidLookupResult(
                    username=name, error=f"HTTP {exc.response.status_code}"
                )
        except Exception as exc:
            log.error("Bulk UUID lookup error", error=str(exc), exc_info=True)
            for name in names:
                results[name.lower()] = UuidLookupResult(
                    username=name, error=f"Unexpected error: {exc}"
                )

    # ── Full profile fetch ────────────────────────────────────────────────────

    async def get_profile(
        self,
        uuid: str,
        *,
        fetch_textures: bool = True,
    ) -> MojangProfile:
        """
        Fetch a full Mojang player profile by UUID.

        Uses ``GET /session/minecraft/profile/<uuid>?unsigned=false``.

        Parameters
        ----------
        uuid:
            Player UUID (with or without dashes).
        fetch_textures:
            If True, decode the ``textures`` property from the profile
            to extract skin and cape URLs.

        Returns
        -------
        MojangProfile
            ``profile.success`` is True when the profile was found.
        """
        try:
            uuid_norm = normalise_uuid(uuid)
        except ValueError:
            return MojangProfile(uuid=uuid, username="", error=f"Invalid UUID: {uuid!r}")

        # ── Cache check ────────────────────────────────────────────────────────
        cached = self._get_profile_cached(uuid_norm, fetch_textures=fetch_textures)
        if cached is not None:
            log.debug("Profile cache hit", uuid=uuid_norm)
            return cached

        log.debug("Fetching profile", uuid=uuid_norm)

        profile = MojangProfile(uuid=uuid_norm, username="")
        profile.is_premium = is_premium_uuid(uuid_norm)

        try:
            url = f"{_SESSION_SERVER_BASE}/session/minecraft/profile/{uuid_norm}?unsigned=false"
            data, status = await self._get_json(url, rate_key="profile", allow_404=True)

            if status == 404 or data is None:
                profile.error = "Player not found"
                log.debug("Profile not found", uuid=uuid_norm)
            else:
                profile.username = data.get("name", "")
                profile.properties = data.get("properties", [])

                # Check for legacy / demo flags in properties
                for prop in profile.properties:
                    name = prop.get("name", "")
                    if name == "isLegacy":
                        profile.is_legacy = True
                    elif name == "isDemo":
                        profile.is_demo = True

                # Decode textures
                if fetch_textures:
                    profile.textures = _extract_textures(profile.properties)

                profile.profile_fetched_at = time.monotonic()

                log.debug(
                    "Profile fetched",
                    uuid=uuid_norm,
                    username=profile.username,
                    has_skin=profile.textures is not None and profile.textures.skin_url is not None,
                    has_cape=profile.textures is not None and profile.textures.cape_url is not None,
                )

        except httpx.HTTPStatusError as exc:
            profile.error = f"HTTP {exc.response.status_code}"
            log.warning("Profile fetch HTTP error", uuid=uuid_norm, status=exc.response.status_code)
        except httpx.TimeoutException:
            profile.error = "Request timed out"
            log.warning("Profile fetch timed out", uuid=uuid_norm)
        except httpx.RequestError as exc:
            profile.error = f"Request error: {exc}"
            log.warning("Profile fetch request error", uuid=uuid_norm, error=str(exc))
        except Exception as exc:
            profile.error = f"Unexpected error: {exc}"
            log.error(
                "Profile fetch unexpected error", uuid=uuid_norm, error=str(exc), exc_info=True
            )

        if profile.success:
            self._put_profile_cached(uuid_norm, profile)

        return profile

    # ── Combined lookup ───────────────────────────────────────────────────────

    async def get_profile_by_username(
        self,
        username: str,
        *,
        fetch_textures: bool = True,
    ) -> MojangProfile | None:
        """
        Convenience method: username → UUID → full profile in one call.

        Returns None if the username does not exist.

        Parameters
        ----------
        username:
            The in-game name to look up.
        fetch_textures:
            If True, decode skin and cape URLs from the profile.

        Returns
        -------
        MojangProfile | None
            None if the player was not found; a populated profile otherwise.
        """
        uuid_result = await self.get_uuid(username)

        if not uuid_result.success:
            if uuid_result.not_found:
                log.debug("Player not found by username", username=username)
                return None
            # An error occurred during UUID lookup — return an error profile
            return MojangProfile(
                uuid="",
                username=username,
                error=uuid_result.error or "UUID lookup failed",
            )

        return await self.get_profile(
            uuid_result.uuid,  # type: ignore[arg-type]
            fetch_textures=fetch_textures,
        )


# ---------------------------------------------------------------------------
# Module-level convenience helpers (use a shared ephemeral client)
# ---------------------------------------------------------------------------


async def lookup_uuid(username: str) -> UuidLookupResult:
    """
    One-shot UUID lookup for *username*.

    Creates and closes an ``MojangClient`` automatically.
    For bulk or repeated lookups, prefer instantiating ``MojangClient``
    directly so the HTTP connection and cache are reused.
    """
    async with MojangClient() as client:
        return await client.get_uuid(username)


async def lookup_profile(uuid: str, *, fetch_textures: bool = True) -> MojangProfile:
    """
    One-shot full profile fetch for *uuid*.

    Creates and closes an ``MojangClient`` automatically.
    """
    async with MojangClient() as client:
        return await client.get_profile(uuid, fetch_textures=fetch_textures)


async def lookup_profile_by_username(
    username: str,
    *,
    fetch_textures: bool = True,
) -> MojangProfile | None:
    """
    One-shot combined username → UUID → profile lookup.

    Creates and closes an ``MojangClient`` automatically.
    """
    async with MojangClient() as client:
        return await client.get_profile_by_username(username, fetch_textures=fetch_textures)
