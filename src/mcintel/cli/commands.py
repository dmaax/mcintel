"""
mcintel.cli.commands
~~~~~~~~~~~~~~~~~~~~
Command-line interface for mcintel.

Subcommands
-----------
  lookup  <address>          — Java SLP ping + DNS chain + IP geo + software fingerprint
  player  <username|uuid>    — Mojang profile lookup (UUID, skin, cape, offline detection)
  dns     <domain>           — Full DNS resolution chain analysis
  scan    <host> [--bedrock] — Ping a server (Java or Bedrock) and show a detailed report
  version                    — Print mcintel version and exit

Usage examples
--------------
  mcintel lookup play.hypixel.net
  mcintel lookup mc.example.com:19132 --bedrock
  mcintel player Notch
  mcintel player 069a79f4-44e9-4726-a5be-fca90e38aaf5
  mcintel dns play.hypixel.net
  mcintel scan play.hypixel.net --json
"""

from __future__ import annotations

import asyncio
import json as _json
import sys
from typing import Annotated, Optional

import typer
from rich import box
from rich import print as rprint
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from mcintel import __version__
from mcintel.logging import setup_logging

# ---------------------------------------------------------------------------
# App & console singletons
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="mcintel",
    help=(
        "[bold green]mcintel[/] — Minecraft Open-Source Intelligence Toolkit\n\n"
        "Gather, track, and analyse intelligence on Minecraft servers and players.\n"
        "Visit [link=https://mcin.tel]https://mcin.tel[/link] for the full web interface."
    ),
    rich_markup_mode="rich",
    add_completion=False,
    no_args_is_help=True,
)

# Shared console — used by every subcommand
console = Console(highlight=True, stderr=False)
err_console = Console(stderr=True, style="bold red")


# ---------------------------------------------------------------------------
# Shared options & helpers
# ---------------------------------------------------------------------------

_JSON_OPT = typer.Option("--json", help="Output raw JSON instead of a formatted table.")
_TIMEOUT_OPT = typer.Option("--timeout", "-t", help="Network operation timeout in seconds.")
_VERBOSE_OPT = typer.Option("--verbose", "-v", help="Enable debug-level logging.")


def _setup(verbose: bool) -> None:
    """Initialise logging for CLI commands."""
    setup_logging(level="DEBUG" if verbose else "WARNING", fmt="text", force=True)


def _run(coro):  # noqa: ANN001
    """Run an async coroutine from a synchronous Typer command."""
    return asyncio.run(coro)


def _error(msg: str) -> None:
    err_console.print(f"[bold red]✗[/] {msg}")
    raise typer.Exit(code=1)


def _success(msg: str) -> None:
    console.print(f"[bold green]✓[/] {msg}")


def _info(label: str, value: str | None, *, style: str = "white") -> str:
    """Format a label:value info line."""
    if value is None:
        return f"[dim]{label}:[/] [dim italic]n/a[/]"
    return f"[dim]{label}:[/] [{style}]{value}[/{style}]"


def _bool_icon(value: bool | None) -> str:
    if value is True:
        return "[green]✓ yes[/]"
    if value is False:
        return "[red]✗ no[/]"
    return "[dim]unknown[/]"


def _parse_address(address: str) -> tuple[str, int]:
    """
    Parse a ``host`` or ``host:port`` string.

    Returns ``(host, port)`` — port defaults to 25565 if omitted.

    Handles:
      - Bare IPv4:          ``1.2.3.4``          → (1.2.3.4, 25565)
      - IPv4 with port:     ``1.2.3.4:25566``    → (1.2.3.4, 25566)
      - Bare IPv6:          ``::1``              → (::1, 25565)
      - Bracketed IPv6:     ``[::1]:25565``      → (::1, 25565)
      - Hostname:           ``play.example.com`` → (play.example.com, 25565)
      - Hostname with port: ``play.example.com:25566``
    """
    import ipaddress

    # Bracketed IPv6 like [::1] or [::1]:25565
    if address.startswith("["):
        close = address.find("]")
        if close != -1:
            host = address[1:close]
            rest = address[close + 1 :]
            port = int(rest.lstrip(":")) if ":" in rest else 25565
            return host, port

    # Bare IPv6 address (multiple colons, no brackets) — no port possible
    try:
        parsed = ipaddress.ip_address(address)
        if parsed.version == 6:
            return address, 25565
    except ValueError:
        pass

    # IPv4 or hostname, optionally with :port suffix
    parts = address.rsplit(":", 1)
    if len(parts) == 2:
        try:
            return parts[0], int(parts[1])
        except ValueError:
            pass
    return address, 25565


# ---------------------------------------------------------------------------
# ``lookup`` command
# ---------------------------------------------------------------------------


@app.command()
def lookup(
    address: Annotated[
        str, typer.Argument(help="Server address, e.g. play.example.com or play.example.com:25565")
    ],
    bedrock: Annotated[
        bool, typer.Option("--bedrock", "-b", help="Ping as a Bedrock Edition server (UDP/19132).")
    ] = False,
    dns: Annotated[
        bool, typer.Option("--dns/--no-dns", help="Include DNS chain resolution.")
    ] = True,
    geo: Annotated[bool, typer.Option("--geo/--no-geo", help="Include IP geolocation.")] = True,
    output_json: Annotated[bool, _JSON_OPT] = False,
    timeout: Annotated[float, _TIMEOUT_OPT] = 5.0,
    verbose: Annotated[bool, _VERBOSE_OPT] = False,
) -> None:
    """
    Full intelligence lookup for a Minecraft server.

    Pings the server (Java or Bedrock), resolves its DNS chain, and
    optionally geolocates its IP address.

    Examples:

        mcintel lookup play.hypixel.net

        mcintel lookup mc.example.com:25565 --no-dns

        mcintel lookup pe.example.com --bedrock
    """
    _setup(verbose)
    _run(
        _lookup_async(
            address, bedrock=bedrock, do_dns=dns, do_geo=geo, as_json=output_json, timeout=timeout
        )
    )


async def _lookup_async(
    address: str,
    *,
    bedrock: bool,
    do_dns: bool,
    do_geo: bool,
    as_json: bool,
    timeout: float,
) -> None:
    host, port = _parse_address(address)
    if bedrock and port == 25565:
        port = 19132  # default Bedrock port

    result_data: dict = {}

    # Status output goes to stderr when emitting JSON so stdout stays clean.
    _status = err_console.status if as_json else console.status

    # ── Ping ─────────────────────────────────────────────────────────────────
    with _status(f"[cyan]Pinging [bold]{host}:{port}[/bold]…[/]"):
        if bedrock:
            from mcintel.scanner.bedrock import ping_bedrock

            ping_result = await ping_bedrock(host, port, timeout=timeout)
            result_data["ping"] = ping_result.to_dict()
        else:
            from mcintel.scanner.slp import ping

            ping_result = await ping(host, port, timeout=timeout)
            result_data["ping"] = ping_result.to_dict()

    # ── DNS ──────────────────────────────────────────────────────────────────
    chain = None
    geo_results = []
    if do_dns and not _is_bare_ip(host):
        with _status(f"[cyan]Resolving DNS for [bold]{host}[/bold]…[/]"):
            from mcintel.dns.resolver import lookup_ip_geo, resolve_server

            chain = await resolve_server(host, port, timeout=timeout)
            result_data["dns"] = chain.to_dict()

            if do_geo and chain.resolved_ips:
                geo_results = [await lookup_ip_geo(ip, timeout=8.0) for ip in chain.resolved_ips]
                result_data["geo"] = [g.to_dict() for g in geo_results]
    elif do_geo and _is_bare_ip(host):
        with _status(f"[cyan]Geolocating [bold]{host}[/bold]…[/]"):
            from mcintel.dns.resolver import lookup_ip_geo

            geo_info = await lookup_ip_geo(host, timeout=8.0)
            geo_results = [geo_info]
            result_data["geo"] = [geo_info.to_dict()]

    # ── Output ────────────────────────────────────────────────────────────────
    if as_json:
        console.print_json(_json.dumps(result_data, default=str))
        return

    _render_lookup(address, ping_result, chain, geo_results, bedrock=bedrock)


def _render_lookup(address, ping_result, chain, geo_results, *, bedrock: bool) -> None:  # noqa: ANN001
    """Render a rich lookup report to the console."""

    # ── Header ────────────────────────────────────────────────────────────────
    edition = "Bedrock" if bedrock else "Java"
    status_text = Text()
    if ping_result.success:
        status_text.append("● ONLINE", style="bold green")
    else:
        status_text.append("● OFFLINE", style="bold red")

    console.print()
    console.rule(f"[bold cyan]mcintel[/] · {address} · {edition}", style="cyan")
    console.print()

    # ── Ping result ───────────────────────────────────────────────────────────
    ping_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), expand=False)
    ping_table.add_column("Field", style="dim", min_width=18)
    ping_table.add_column("Value", style="white")

    ping_table.add_row("Status", status_text)

    if ping_result.success:
        ping_table.add_row(
            "Latency", f"{ping_result.latency_ms} ms" if ping_result.latency_ms else "n/a"
        )
        ping_table.add_row("Version", ping_result.version_name or "n/a")
        ping_table.add_row(
            "Protocol #",
            str(ping_result.version_protocol)
            if ping_result.version_protocol is not None
            else "n/a",
        )
        ping_table.add_row(
            "Players",
            f"{ping_result.players_online} / {ping_result.players_max}",
        )
        ping_table.add_row("MOTD", ping_result.motd_clean or "n/a")

        if not bedrock:
            ping_table.add_row("Software", ping_result.software or "unknown")
            ping_table.add_row("Modded", _bool_icon(ping_result.is_modded))
            ping_table.add_row("Proxy", _bool_icon(ping_result.is_proxy))
            if ping_result.enforces_secure_chat is not None:
                ping_table.add_row(
                    "Enforces chat sig.", _bool_icon(ping_result.enforces_secure_chat)
                )
        else:
            ping_table.add_row("Game mode", getattr(ping_result, "gamemode", None) or "n/a")
            ping_table.add_row("Edition", getattr(ping_result, "edition", "bedrock").title())

        if getattr(ping_result, "favicon_hash", None) and not bedrock:
            ping_table.add_row("Favicon SHA-256", f"[dim]{ping_result.favicon_hash[:16]}…[/]")

    else:
        ping_table.add_row("Error", f"[red]{ping_result.error}[/]")

    console.print(
        Panel(ping_table, title="[bold]Server Ping[/]", border_style="cyan", expand=False)
    )

    # ── Player sample list ────────────────────────────────────────────────────
    sample = getattr(ping_result, "players_sample", [])
    if sample:
        sample_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        sample_table.add_column("Username", style="yellow")
        sample_table.add_column("UUID", style="dim")
        for player in sample[:20]:
            sample_table.add_row(player.name, player.uuid)
        if len(sample) > 20:
            sample_table.add_row(f"[dim]… and {len(sample) - 20} more[/]", "")
        console.print(
            Panel(sample_table, title="[bold]Player Sample[/]", border_style="yellow", expand=False)
        )

    # ── Mod list ─────────────────────────────────────────────────────────────
    mods = getattr(ping_result, "mods", [])
    if mods:
        mod_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        mod_table.add_column("Mod ID", style="magenta")
        mod_table.add_column("Version", style="dim")
        for mod in mods[:30]:
            mod_table.add_row(mod.mod_id, mod.version or "n/a")
        if len(mods) > 30:
            mod_table.add_row(f"[dim]… and {len(mods) - 30} more[/]", "")
        console.print(
            Panel(
                mod_table,
                title=f"[bold]Mods ({len(mods)})[/]",
                border_style="magenta",
                expand=False,
            )
        )

    # ── DNS chain ────────────────────────────────────────────────────────────
    if chain:
        dns_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        dns_table.add_column("Type", style="cyan", min_width=6)
        dns_table.add_column("Domain / Name", style="white")
        dns_table.add_column("Value", style="green")
        dns_table.add_column("TTL", style="dim", justify="right")

        for rec in chain.records:
            ttl_str = str(rec.ttl) + "s" if rec.ttl is not None else "—"
            dns_table.add_row(rec.record_type, rec.domain, rec.value, ttl_str)

        extras = []
        if chain.srv_used:
            extras.append("[green]SRV resolved[/]")
        if chain.cname_chain:
            extras.append(f"CNAME chain: {' → '.join(chain.cname_chain)}")
        extras_str = "  ".join(extras) if extras else ""

        title = "[bold]DNS Chain[/]"
        if extras_str:
            title += f"  {extras_str}"

        console.print(Panel(dns_table, title=title, border_style="green", expand=False))

    # ── Geolocation ───────────────────────────────────────────────────────────
    if geo_results:
        for geo in geo_results:
            if not geo.success:
                continue
            geo_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), expand=False)
            geo_table.add_column("Field", style="dim", min_width=18)
            geo_table.add_column("Value", style="white")

            geo_table.add_row("IP", geo.ip)
            location_parts = [x for x in [geo.city, geo.region, geo.country_code] if x]
            geo_table.add_row("Location", ", ".join(location_parts) or "n/a")
            if geo.latitude and geo.longitude:
                geo_table.add_row("Coordinates", f"{geo.latitude:.4f}, {geo.longitude:.4f}")
            geo_table.add_row("ASN", geo.asn or "n/a")
            geo_table.add_row("Organization", geo.org or "n/a")
            geo_table.add_row("Datacenter", _bool_icon(geo.is_datacenter))
            if geo.protection_provider:
                geo_table.add_row("DDoS Protection", f"[yellow]{geo.protection_provider}[/]")
            if geo.hostname:
                geo_table.add_row("Reverse DNS", geo.hostname)

            console.print(
                Panel(
                    geo_table,
                    title=f"[bold]IP Intelligence · {geo.ip}[/]",
                    border_style="blue",
                    expand=False,
                )
            )

    console.print()


# ---------------------------------------------------------------------------
# ``player`` command
# ---------------------------------------------------------------------------


@app.command()
def player(
    identifier: Annotated[str, typer.Argument(help="Minecraft username or UUID.")],
    output_json: Annotated[bool, _JSON_OPT] = False,
    timeout: Annotated[float, _TIMEOUT_OPT] = 10.0,
    verbose: Annotated[bool, _VERBOSE_OPT] = False,
) -> None:
    """
    Look up a Minecraft player by username or UUID.

    Resolves the UUID via the Mojang API, fetches the full profile,
    and shows skin, cape, and online/offline-mode classification.

    Examples:

        mcintel player Notch

        mcintel player 069a79f4-44e9-4726-a5be-fca90e38aaf5
    """
    _setup(verbose)
    _run(_player_async(identifier, as_json=output_json, timeout=timeout))


async def _player_async(identifier: str, *, as_json: bool, timeout: float) -> None:
    from mcintel.players.mojang import MojangClient, offline_uuid, uuid_version

    # Detect whether the identifier looks like a UUID
    is_uuid = len(identifier.replace("-", "")) == 32 and all(
        c in "0123456789abcdefABCDEF" for c in identifier.replace("-", "")
    )

    _status = err_console.status if as_json else console.status
    with _status(f"[cyan]Looking up player [bold]{identifier}[/bold]…[/]"):
        async with MojangClient(http_timeout=timeout) as client:
            if is_uuid:
                profile = await client.get_profile(identifier)
            else:
                profile = await client.get_profile_by_username(identifier)

    if profile is None:
        _error(f"Player [bold]{identifier}[/] not found.")
        return

    if as_json:
        console.print_json(_json.dumps(profile.to_dict(), default=str))
        return

    _render_player(profile)


def _render_player(profile) -> None:  # noqa: ANN001
    console.print()
    console.rule(f"[bold cyan]mcintel[/] · Player · {profile.username}", style="cyan")
    console.print()

    table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), expand=False)
    table.add_column("Field", style="dim", min_width=18)
    table.add_column("Value", style="white")

    if not profile.success:
        table.add_row("Error", f"[red]{profile.error}[/]")
        console.print(
            Panel(table, title="[bold]Player Profile[/]", border_style="red", expand=False)
        )
        return

    table.add_row("Username", f"[bold yellow]{profile.username}[/]")
    table.add_row("UUID", profile.uuid)

    ver = profile.uuid and __import__(
        "mcintel.players.mojang", fromlist=["uuid_version"]
    ).uuid_version(profile.uuid)
    if ver == 4:
        table.add_row("Account type", "[green]Premium (online-mode)[/]")
    elif ver == 3:
        table.add_row("Account type", "[yellow]Offline / cracked (UUID v3)[/]")
    else:
        table.add_row("Account type", "[dim]Unknown[/]")

    if profile.is_legacy:
        table.add_row("Legacy account", "[yellow]Yes (unmigrated)[/]")
    if profile.is_demo:
        table.add_row("Demo account", "[yellow]Yes[/]")

    if profile.textures:
        t = profile.textures
        table.add_row(
            "Skin URL", f"[link={t.skin_url}]{t.skin_url or 'n/a'}[/link]" if t.skin_url else "n/a"
        )
        table.add_row("Skin variant", (t.skin_variant or "classic").title())
        if t.cape_url:
            table.add_row("Cape URL", f"[link={t.cape_url}]{t.cape_url}[/link]")
            table.add_row("Cape type", (t.cape_type or "unknown").title())
        else:
            table.add_row("Cape", "[dim]None[/]")
    else:
        table.add_row("Textures", "[dim]Not available[/]")

    table.add_row(
        "NameMC",
        f"[link=https://namemc.com/profile/{profile.uuid}]https://namemc.com/profile/{profile.uuid}[/link]",
    )

    console.print(
        Panel(table, title="[bold]Player Profile[/]", border_style="yellow", expand=False)
    )
    console.print()


# ---------------------------------------------------------------------------
# ``dns`` command
# ---------------------------------------------------------------------------


@app.command()
def dns(
    domain: Annotated[str, typer.Argument(help="Domain name to resolve, e.g. play.hypixel.net")],
    port: Annotated[
        int, typer.Option("--port", "-p", help="Starting port (overridden by SRV).")
    ] = 25565,
    geo: Annotated[bool, typer.Option("--geo/--no-geo", help="Geolocate resolved IPs.")] = True,
    output_json: Annotated[bool, _JSON_OPT] = False,
    timeout: Annotated[float, _TIMEOUT_OPT] = 5.0,
    verbose: Annotated[bool, _VERBOSE_OPT] = False,
) -> None:
    """
    Full DNS resolution chain analysis for a domain.

    Traces SRV records, CNAME chains, A/AAAA lookups, PTR (reverse DNS),
    NS, and TXT records.  Optionally geolocates the resolved IPs.

    Examples:

        mcintel dns play.hypixel.net

        mcintel dns mc.example.com --port 25566 --no-geo
    """
    _setup(verbose)
    _run(_dns_async(domain, port=port, do_geo=geo, as_json=output_json, timeout=timeout))


async def _dns_async(
    domain: str, *, port: int, do_geo: bool, as_json: bool, timeout: float
) -> None:
    from mcintel.dns.resolver import lookup_ip_geo, resolve_server

    _status = err_console.status if as_json else console.status
    with _status(f"[cyan]Resolving DNS for [bold]{domain}[/bold]…[/]"):
        chain = await resolve_server(domain, port, timeout=timeout)
        geo_results = []
        if do_geo and chain.resolved_ips:
            geo_results = [await lookup_ip_geo(ip) for ip in chain.resolved_ips]

    if as_json:
        out = {"dns": chain.to_dict(), "geo": [g.to_dict() for g in geo_results]}
        console.print_json(_json.dumps(out, default=str))
        return

    _render_dns(domain, chain, geo_results)


def _render_dns(domain: str, chain, geo_results: list) -> None:  # noqa: ANN001
    console.print()
    console.rule(f"[bold cyan]mcintel[/] · DNS · {domain}", style="cyan")
    console.print()

    # ── Summary ───────────────────────────────────────────────────────────────
    summary = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), expand=False)
    summary.add_column("Field", style="dim", min_width=18)
    summary.add_column("Value")

    summary.add_row("Input", domain)
    summary.add_row("Resolved host", chain.resolved_host or "[dim]—[/]")
    summary.add_row("Resolved port", str(chain.resolved_port))
    summary.add_row(
        "Resolved IPs", ", ".join(chain.resolved_ips) if chain.resolved_ips else "[red]None[/]"
    )
    summary.add_row("SRV used", _bool_icon(chain.srv_used))
    if chain.cname_chain:
        summary.add_row("CNAME chain", " → ".join(chain.cname_chain))
    if chain.error:
        summary.add_row("Error", f"[red]{chain.error}[/]")

    console.print(
        Panel(summary, title="[bold]Resolution Summary[/]", border_style="cyan", expand=False)
    )

    # ── Full record table ─────────────────────────────────────────────────────
    if chain.records:
        rec_table = Table(box=box.SIMPLE, show_header=True, padding=(0, 1))
        rec_table.add_column("Type", style="cyan", min_width=6)
        rec_table.add_column("Domain", style="white")
        rec_table.add_column("Value", style="green")
        rec_table.add_column("TTL", style="dim", justify="right")

        _TYPE_COLOURS = {
            "A": "green",
            "AAAA": "bright_green",
            "CNAME": "yellow",
            "SRV": "magenta",
            "PTR": "blue",
            "NS": "cyan",
            "TXT": "dim white",
            "MX": "orange3",
        }

        for rec in chain.records:
            colour = _TYPE_COLOURS.get(rec.record_type, "white")
            ttl_str = f"{rec.ttl}s" if rec.ttl is not None else "—"
            rec_table.add_row(
                f"[{colour}]{rec.record_type}[/{colour}]",
                rec.domain,
                rec.value,
                ttl_str,
            )

        console.print(
            Panel(rec_table, title="[bold]DNS Records[/]", border_style="green", expand=False)
        )

    # ── Geolocation ───────────────────────────────────────────────────────────
    if geo_results:
        for geo in geo_results:
            if not geo.success:
                continue
            geo_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 1), expand=False)
            geo_table.add_column("Field", style="dim", min_width=18)
            geo_table.add_column("Value")

            geo_table.add_row("IP", geo.ip)
            location_parts = [x for x in [geo.city, geo.region, geo.country_code] if x]
            geo_table.add_row("Location", ", ".join(location_parts) or "n/a")
            if geo.latitude and geo.longitude:
                geo_table.add_row("Coordinates", f"{geo.latitude:.4f}, {geo.longitude:.4f}")
            geo_table.add_row("ASN", geo.asn or "n/a")
            geo_table.add_row("Organization", geo.org or "n/a")
            geo_table.add_row("Datacenter", _bool_icon(geo.is_datacenter))
            if geo.protection_provider:
                geo_table.add_row("DDoS Protection", f"[yellow]{geo.protection_provider}[/]")
            if geo.hostname:
                geo_table.add_row("Reverse DNS", geo.hostname)

            console.print(
                Panel(
                    geo_table,
                    title=f"[bold]IP Intelligence · {geo.ip}[/]",
                    border_style="blue",
                    expand=False,
                )
            )

    console.print()


# ---------------------------------------------------------------------------
# ``scan`` command (alias for lookup with explicit host:port control)
# ---------------------------------------------------------------------------


@app.command()
def scan(
    host: Annotated[str, typer.Argument(help="Server hostname or IP to scan.")],
    port: Annotated[int, typer.Option("--port", "-p", help="TCP/UDP port to probe.")] = 25565,
    bedrock: Annotated[
        bool, typer.Option("--bedrock", "-b", help="Scan as Bedrock (UDP).")
    ] = False,
    output_json: Annotated[bool, _JSON_OPT] = False,
    timeout: Annotated[float, _TIMEOUT_OPT] = 5.0,
    verbose: Annotated[bool, _VERBOSE_OPT] = False,
) -> None:
    """
    Scan a single server and display a detailed intelligence report.

    For Java servers this runs an SLP ping.
    For Bedrock servers (--bedrock) this sends a RakNet Unconnected Ping.

    Examples:

        mcintel scan play.hypixel.net

        mcintel scan 192.168.1.10 --port 25566

        mcintel scan pe.example.com --bedrock --port 19132
    """
    _setup(verbose)
    address = f"{host}:{port}"
    _run(
        _lookup_async(
            address, bedrock=bedrock, do_dns=True, do_geo=True, as_json=output_json, timeout=timeout
        )
    )


# ---------------------------------------------------------------------------
# ``version`` command
# ---------------------------------------------------------------------------


@app.command()
def version() -> None:
    """Print the mcintel version and exit."""
    console.print(f"[bold green]mcintel[/] v{__version__}")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _is_bare_ip(host: str) -> bool:
    """Return True if *host* looks like a raw IPv4 or IPv6 address."""
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry-point used by the ``mcintel`` console script."""
    app()


if __name__ == "__main__":
    main()
