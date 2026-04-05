# MCIntel — Feature Plan & Roadmap

> Living document — updated as priorities shift and new ideas surface.

---

## Table of Contents

- [Phase 1 — Core Infrastructure](#phase-1--core-infrastructure)
- [Phase 2 — Server Intelligence](#phase-2--server-intelligence)
- [Phase 3 — DNS & Network Intelligence](#phase-3--dns--network-intelligence)
- [Phase 4 — Player Intelligence](#phase-4--player-intelligence)
- [Phase 5 — Data Aggregation & Visualization](#phase-5--data-aggregation--visualization)
- [Phase 6 — Mass Reconnaissance](#phase-6--mass-reconnaissance)
- [Phase 7 — Web Surface Discovery](#phase-7--web-surface-discovery)
- [Phase 8 — Community & Server List Intelligence](#phase-8--community--server-list-intelligence)
- [Phase 9 — Advanced Analysis & Correlation](#phase-9--advanced-analysis--correlation)
- [Phase 10 — API & Frontend](#phase-10--api--frontend)
- [Ideas Backlog](#ideas-backlog)

---

## Phase 1 — Core Infrastructure

Foundation that everything else depends on.

- [x] Project scaffolding (monorepo layout, linting, CI)
  - `pyproject.toml` with Hatch, Ruff, Mypy, pytest config
  - `src/mcintel/` package layout
  - `.gitignore`, `.env.example`
- [x] Database schema design (PostgreSQL / SQLite for dev)
  - `servers` table (host, port, edition, first_seen, last_seen, etc.)
  - `server_pings` table (timestamped SLP / Bedrock responses)
  - `server_motd_history` table (deduplicated MOTD change log)
  - `server_favicon_history` table (deduplicated favicon change log)
  - `players` table (uuid, username, skin, cape, first_seen)
  - `player_username_history` table (observed username changes)
  - `player_sightings` table ((server, player) observations from SLP samples)
  - `dns_records` table (historical A, SRV, CNAME, PTR, NS, TXT entries)
  - `ip_metadata` table (geo, ASN, hosting provider — cached per IP)
  - `port_scan_results` table (open/closed port observations per host)
- [x] Async SQLAlchemy session factory (SQLite dev / PostgreSQL prod)
  - `db/session.py` — `init_db()`, `close_db()`, `get_session()`, FastAPI `db_session` dep
  - Auto-create tables in dev/test; Alembic migrations for production
- [x] Configuration system (env vars, `.env` file, pydantic-settings)
  - `config.py` — typed `Settings` with all knobs documented in `.env.example`
  - Convenience properties: `is_development`, `using_sqlite`, etc.
- [x] Logging & structured output (text + JSON modes)
  - `logging.py` — `get_logger(__name__)` adapter supporting keyword extras
  - Two formatters: coloured human-readable (dev) and JSON-lines (production)
- [ ] Job scheduler / task queue for recurring scans
- [ ] Rate-limiting & politeness layer (respect targets, configurable delays)
  - In-scanner semaphore (`ping_many`, `ping_bedrock_many`) ✓ (basic concurrency cap)
  - Global target-level delay / opt-out list enforcement — pending

---

## Phase 2 — Server Intelligence

The bread and butter — query Minecraft servers and store everything.

### 2.1 Server List Ping (SLP)

- [x] Implement modern SLP protocol (1.7+)
  - Handshake → Status Request → Status Response → Ping/Pong
  - VarInt encoding/decoding, packet framing, string encoding
- [x] Parse full JSON response and persist:
  - `version.name` and `version.protocol`
  - `players.max`, `players.online`, `players.sample[]` (UUIDs + usernames)
  - `description` (MOTD — supports Chat component JSON and legacy `§` codes)
  - `favicon` (base64 PNG) with SHA-256 hash
  - `modinfo` / `forgeData` (Forge 1.7–1.12 and Forge 1.13+ / NeoForge formats)
  - `enforcesSecureChat`, `preventsChatReports` flags
- [x] Legacy SLP for servers < 1.7 (0xFE ping)
  - 1.6 extended payload (FE 01 FA MC|PingHost) with 1.3–1.5 fallback parsing
  - Both old (`§proto§motd§online§max`) and new (`§1\0proto\0ver\0motd\0online\0max`) formats
- [x] Bedrock Edition ping (RakNet Unconnected Ping/Pong)
  - Full MCPE advertisement string parsing (all 12 fields)
  - MCEE (Education Edition) detection
  - Game mode mapping (string and numeric)
- [x] Automatic modern → legacy fallback on failure
- [x] Concurrent batch pinging with bounded semaphore (`ping_many`, `ping_bedrock_many`)
- [ ] Scheduled pinging at configurable intervals (e.g., every 5 min, 15 min, 1 hr)
  - Requires job scheduler (Phase 1 TODO)

### 2.2 Query Protocol (UDP 25565)

- [ ] Implement Minecraft Query protocol (when `enable-query=true` on server)
  - Basic stat: MOTD, game type, map, players online/max, port, host IP
  - Full stat: all of the above + **plugin list** + full player list
- [ ] Detect whether query is enabled or firewalled

### 2.3 RCON Discovery

- [ ] Probe TCP port 25575 (default RCON) for open connections
- [ ] Detect if RCON is exposed to the internet (security misconfiguration)
- [ ] **No brute-forcing** — only detection of open/exposed ports

### 2.4 Mod & Plugin Fingerprinting

- [x] Parse Forge mod list from `modinfo.modList` (Forge 1.7–1.12 style)
- [x] Parse NeoForge mod list from `forgeData.mods` (1.13+ style)
- [x] Detect server software from `version.name` patterns:
  - Vanilla, Spigot, Paper, Purpur, Pufferfish, Folia, Fabric, Quilt,
    Forge, NeoForge, Sponge, Mohist, Arclight, CatServer
- [x] Detect proxy layers from version name:
  - BungeeCord, Waterfall, Travertine, Velocity
  - GeyserMC (Bedrock-to-Java bridge)
- [ ] Full Forge mod handshake (TCP-level, separate from SLP)
- [ ] Known vulnerability flagging based on detected software + version

### 2.5 Favicon Tracking

- [x] Store favicon SHA-256 hash per ping
- [x] `server_favicon_history` table for deduplicated change log
- [ ] Perceptual hash (imagehash) for visual similarity clustering
- [ ] Track favicon changes over time (diff logic / change detection job)
- [ ] Cluster servers sharing identical or visually similar favicons
- [ ] Reverse-search: "find all servers using this icon"

### 2.6 MOTD Analysis

- [x] Strip formatting codes (`§` colour codes), store both raw and plaintext
- [x] Recursive Chat component JSON parsing (nested `extra`, `translate`)
- [x] `server_motd_history` table for deduplicated change log
- [ ] Extract potential contact information (Discord invite links, URLs, emails)
- [ ] Track MOTD changes over time (change detection job)
- [ ] Cluster servers by similar MOTD text (fuzzy matching)

---

## Phase 3 — DNS & Network Intelligence

Map the network footprint of a Minecraft server.

### 3.1 DNS Resolution Chain

- [x] **SRV record lookup**: `_minecraft._tcp.<domain>` → target host + port
  - Priority/weight-aware (picks best record)
- [x] **A / AAAA record fallback** when no SRV exists
- [x] **CNAME chain following** — records every hop in the chain (loop-safe, max depth 10)
- [x] Reverse DNS (PTR) lookups on server IPs
- [x] TXT record inspection (SPF, verification tokens)
- [x] NS record tracking (identify DNS provider)
- [x] `dns_records` table for historical storage
- [x] Bare-IP detection (skips DNS, goes straight to PTR)
- [ ] Store historical DNS records with timestamps + change detection
- [ ] Detect DNS changes / migrations over time (scheduler job)
- [ ] DNS history diff reporting

### 3.2 IP Intelligence

- [x] **ipinfo.io integration** — `https://ipinfo.io/{ip}/json`
  - Geolocation (city, region, country, coordinates)
  - ASN & organisation name parsing (`"AS16276 OVH SAS"` → `asn`, `org`)
  - Timezone, postal code, reverse-DNS hostname
  - Privacy block parsing (VPN, proxy, Tor, hosting flags)
- [x] Heuristic datacenter detection from org name (free-tier fallback)
- [x] In-memory geo cache (1-hour TTL) to avoid redundant API calls
- [x] `ip_metadata` table for persistent caching
- [ ] Support for alternative providers (MaxMind GeoLite2, ip-api.com) as fallback
- [ ] Historical IP tracking — when did the server change IPs?
- [ ] Map visualization of server locations (GeoJSON export)

### 3.3 DDoS Protection & Proxy Detection

- [x] Detect common Minecraft DDoS protection services by ASN/org name:
  - TCPShield, Cosmic Guard, NeoProtect, OVH, Path.net, Cloudflare, Akamai
- [x] `protection_provider` field on `IpGeoInfo` / `ip_metadata`
- [ ] Identify if IP belongs to a known proxy/protection network (ASN list)
- [ ] Attempt to discover origin IP behind protection layers
  (via DNS history, certificate transparency, etc.)

### 3.4 Port Fingerprinting

- [x] `port_scan_results` table schema (port, protocol, is_open, service_name, banner)
- [ ] Active scanning for common Minecraft-adjacent ports:
  | Port  | Service                    |
  |-------|----------------------------|
  | 25565 | Minecraft Java (default)   |
  | 19132 | Minecraft Bedrock (default)|
  | 25575 | RCON                       |
  | 8123  | Dynmap                     |
  | 8100  | BlueMap                    |
  | 8804  | Plan Analytics             |
  | 8443  | Pterodactyl Panel          |
  | 2022  | SFTP (Pterodactyl)         |
  | 9090  | Cockpit / Server Panels    |
- [ ] Service banner grabbing on discovered ports

---

## Phase 4 — Player Intelligence

Track and correlate player identities across the Minecraft ecosystem.

### 4.1 UUID & Username Resolution

- [x] Mojang API integration:
  - Username → UUID: `GET /users/profiles/minecraft/<username>`
  - UUID → Profile: `GET /session/minecraft/profile/<uuid>?unsigned=false`
  - Bulk username → UUID: `POST /profiles/minecraft` (up to 10 per call)
- [x] In-memory cache (1-hour TTL for found players, 5-min TTL for not-found)
- [x] `MojangClient` async context manager with connection reuse
- [x] Rate-limiting per endpoint key (minimum inter-request interval)
- [x] Detect "cracked" (offline-mode) servers by UUID format:
  - Version 4 (random) → premium/online-mode account
  - Version 3 (name-based MD5) → offline/cracked UUID
- [x] `offline_uuid(username)` — compute offline-mode UUID matching Minecraft's algorithm
- [x] Module-level convenience functions: `lookup_uuid`, `lookup_profile`, `lookup_profile_by_username`

### 4.2 Username History

- [x] `player_username_history` table schema (per-player, deduped by username)
- [x] `player_sightings` table schema (server × player × ping observations)
- [ ] Populate history from SLP `players.sample[]` during pings (scheduler job)
- [ ] Correlate UUID sightings across multiple servers
- [ ] Build a timeline: "Player X was seen on Server A on date Y"

### 4.3 Skin & Cape Analysis

- [x] Download and decode skin/cape texture URLs from `textures` property
  - Base64 → JSON → SKIN/CAPE URL extraction
  - Skin model variant detection (`"classic"` / `"slim"`)
- [x] Cape type classification by URL pattern:
  - `textures.minecraft.net` → Mojang
  - `optifine.net` → OptiFine
  - `labymod.net` → LabyMod
  - `minecraftcapes.co.uk` / `minecraftcapes.net` → MinecraftCapes
  - Unknown domain → `"unknown"`
- [x] `skin_url`, `cape_url`, `skin_variant` fields on `Player` model
- [ ] Download and persist raw skin PNG bytes
- [ ] SHA-256 + perceptual hash of skin texture
- [ ] Skin change history tracking (detect skin swaps over time)

### 4.4 Player-Server Association Graph

- [x] `player_sightings` table schema
- [ ] Build a graph of which players frequent which servers
- [ ] Identify "bridge" players that connect otherwise unrelated servers
- [ ] Detect alt accounts by analyzing co-occurrence patterns
- [ ] Staff/admin detection (same players appear across a network's servers)

### 4.5 NameMC & Third-Party Profile Enrichment

- [ ] Scrape or integrate NameMC profile data (friends, servers, capes)
- [ ] Cross-reference with other Minecraft profile sites
- [ ] Respect robots.txt and ToS — use APIs where available

---

## Phase 5 — Data Aggregation & Visualization

Make the collected data useful and explorable.

### 5.1 Player Count Graphs

- [ ] Time-series graphs of `players.online` per server
- [ ] Configurable time ranges (24h, 7d, 30d, 1y, all-time)
- [ ] Peak hours analysis (what time of day is the server busiest?)
- [ ] Overlay multiple servers for comparison
- [ ] Detect anomalies (sudden spikes/drops, possible bot attacks or raids)

### 5.2 Server Timeline

- [ ] Visual timeline of a server's history:
  - IP changes (with DNS records)
  - Version upgrades / downgrades
  - MOTD changes
  - Favicon changes
  - Player count trends
  - Uptime/downtime windows

### 5.3 Network Topology Maps

- [ ] Visualize BungeeCord/Velocity networks (shared IPs, linked servers)
- [ ] Map server clusters owned by the same operator
- [ ] IP neighborhood analysis (other servers on the same host/subnet)

### 5.4 Dashboards & Reports

- [ ] Per-server intelligence report (single-page summary of everything known)
- [ ] Per-player dossier (all observed activity and associations)
- [ ] Exportable reports (PDF, JSON, CSV)
- [ ] RSS/Atom feeds for tracked server changes

---

## Phase 6 — Mass Reconnaissance

Scale up from single-target lookups to broad discovery.

### 6.1 Internet-Wide Scanning Integration

- [ ] **Shodan** integration: search for `Minecraft` service banners
- [ ] **Censys** integration: query for port 25565 services
- [ ] **ZoomEye** integration as an alternative source
- [ ] Import scan results and enrich with SLP data
- [ ] Schedule recurring imports from these sources

### 6.2 Targeted Range Scanning

- [ ] Scan specific IP ranges / CIDR blocks for Minecraft servers
- [ ] Scan known hosting provider ranges (OVH, Hetzner, Contabo, etc.)
- [ ] Masscan / ZMap integration for high-speed port discovery
- [ ] SLP probe only confirmed-open ports (two-phase scan)

### 6.3 Passive Discovery

- [ ] Ingest Certificate Transparency logs for `*.minecraft*` domains
- [ ] Monitor DNS zone data from public datasets
- [ ] Parse public server lists and voting sites for new targets

---

## Phase 7 — Web Surface Discovery

Find web-facing assets tied to Minecraft servers.

### 7.1 Live Map Detection

- [ ] Probe for Dynmap (`/tiles/`, `/up/world/` endpoints)
- [ ] Probe for BlueMap (`/settings.json`, `/maps/`)
- [ ] Probe for Pl3xMap / Squaremap
- [ ] Screenshot and archive discovered maps
- [ ] Extract world data (seed leaks, POI locations) from map tiles

### 7.2 Server Panel Detection

- [ ] Detect Pterodactyl / Pelican Panel instances
- [ ] Detect Multicraft, AMP, McMyAdmin, Crafty Controller
- [ ] Detect cPanel/Plesk on the same host (shared hosting indicator)
- [ ] Check for exposed admin panels with default credentials pages

### 7.3 Related Web Presence

- [ ] Discover associated websites (same IP, linked from MOTD)
- [ ] Find Discord server invites from MOTDs, websites, server lists
- [ ] Detect wiki / documentation sites (e.g., Fandom/Wikia, GitBook)
- [ ] Store link → find forum posts, social media profiles tied to the server

### 7.4 Certificate Transparency

- [ ] Query CT logs (crt.sh) for certificates issued to server domains
- [ ] Discover subdomains (play.*, hub.*, lobby.*, survival.*, etc.)
- [ ] Historical certificate analysis (when was the domain first used?)

---

## Phase 8 — Community & Server List Intelligence

Monitor the server listing ecosystem.

### 8.1 Server List Scraping

- [ ] Scrape and track listings on major server list sites:
  - minecraft-server-list.com
  - minecraft-mp.com
  - topminecraftservers.org
  - minecraft-server.net
  - And others
- [ ] Track voting counts, rankings, and rating changes over time
- [ ] Detect vote botting (suspicious vote patterns)
- [ ] Archive listing descriptions and metadata

### 8.2 Minecraft Marketplace / Hosting Correlation

- [ ] Identify which hosting provider a server uses (via IP ranges, ASN)
- [ ] Track migrations between hosting providers
- [ ] Identify shared hosting (multiple servers behind one IP, different ports)

### 8.3 Ban List & Reputation

- [ ] Integrate with public ban lists (MCBans, etc.)
- [ ] Cross-reference known griefer/malicious player UUIDs
- [ ] Server reputation scoring based on collected data

---

## Phase 9 — Advanced Analysis & Correlation

Higher-order intelligence from the data collected in previous phases.

### 9.1 Ownership Correlation

- [ ] Cluster servers likely run by the same person/team:
  - Shared player samples (admins/staff appear on all)
  - Shared IP space or hosting account
  - Similar MOTDs, favicons, or configuration patterns
  - Linked via DNS (same nameservers, WHOIS data)
  - Shared website/Discord

### 9.2 Behavioral Analysis

- [ ] Server uptime patterns (hosted at home? reboot schedules?)
- [ ] Player count patterns vs. timezone → estimate player base region
- [ ] Detect when a server is likely running automated/fake player counts
- [ ] Version adoption tracking (how fast does the community update?)

### 9.3 Threat Intelligence

- [ ] Track known malicious servers (login credential stealers, malware distributors)
- [ ] Detect suspicious mod lists (known malicious mods/plugins)
- [ ] Monitor for compromised servers (defaced MOTDs, unusual behavior changes)
- [ ] Flag servers with known-exploitable software versions

### 9.4 Historical Forensics

- [ ] Full change history for any tracked server (immutable audit log)
- [ ] "What did this server look like on date X?" — point-in-time reconstruction
- [ ] Detect server identity changes (new name/MOTD but same IP → rebrand)
- [ ] Track server "deaths" and "rebirths" (domain reuse)

---

## Phase 10 — API & Frontend

Make it accessible.

### 10.1 REST API

- [ ] `/api/server/{address}` — full intel report for a server
- [ ] `/api/server/{address}/history` — historical data (ping, DNS, MOTD, etc.)
- [ ] `/api/server/{address}/players` — player sightings
- [ ] `/api/player/{uuid}` — player dossier
- [ ] `/api/player/{username}` — resolve and redirect to UUID-based endpoint
- [ ] `/api/search` — search across servers, players, MOTDs, IPs
- [ ] `/api/network/{ip}` — all servers on an IP address or subnet
- [ ] API key authentication & rate limiting
- [ ] Webhook support for alerts (server goes down, IP changes, etc.)

### 10.2 Web Frontend (mcin.tel)

- [ ] Landing page with server/player search
- [ ] Server detail page (all collected intel, graphs, timeline)
- [ ] Player detail page (sightings, associations, skin history)
- [ ] Interactive network graph visualization
- [ ] World map of server locations
- [ ] Comparison view (overlay multiple servers' stats)
- [ ] Dark mode (obviously)

### 10.3 CLI Tool

- [x] `mcintel lookup <address>` — full server intelligence report (ping + DNS + geo)
  - `--bedrock` flag for Bedrock servers
  - `--json` flag for machine-readable output
  - `--no-dns` / `--no-geo` flags to skip subsystems
- [x] `mcintel scan <host> [--port] [--bedrock]` — scan a single server
- [x] `mcintel player <username|uuid>` — player lookup (UUID, skin, cape, premium/offline)
  - `--json` flag for machine-readable output
- [x] `mcintel dns <domain>` — full DNS chain analysis with optional geo
  - `--port`, `--no-geo`, `--json` flags
- [x] `mcintel version` — print version and exit
- [ ] `mcintel watch <address>` — continuous monitoring with live output
- [ ] `mcintel export <address> --format json|csv|pdf` — export reports
- [ ] `mcintel daemon` — run the scheduler/collector in the background

---

## Ideas Backlog

Unscoped ideas that don't fit neatly into a phase yet.

- **Minecraft protocol version history database** — map protocol numbers to release names
- **Server JAR fingerprinting** — identify exact server software from protocol quirks
- **Honeypot detection** — identify servers that are likely honeypots (unusual behavior)
- **Cracked server enumeration** — detect offline-mode servers (UUID format analysis) ✓ (UUID v3 detection implemented)
- **Resource pack URL extraction** — servers can push resource packs; URL may leak info
- **Chat protocol analysis** — join servers to passively observe chat (ethical/legal considerations)
- **Velocity modern forwarding detection** — distinguish proxy types by handshake behavior
- **Plugin message channel enumeration** — detect registered plugin channels (reveals plugins)
- **SRV record hijack monitoring** — alert if a tracked domain's SRV record changes unexpectedly
- **Minecraft Realms lookup** — discover and track Realms servers via the Realms API
- **Bedrock server intelligence** — full parity with Java edition features ✓ (ping implemented)
- **WHOIS integration** — domain ownership data for servers using custom domains
- **Email/OSINT pivoting** — from a server domain, find registrant info → other domains
- **Screenshot service** — join a server briefly, capture spawn screenshot, archive it
- **Tor/VPN exit node detection** — flag server IPs that are known anonymization endpoints
- **Discord bot** — `/mcintel lookup play.example.com` for quick lookups in Discord
- **Telegram bot** — same as above for Telegram users
- **Public dataset exports** — periodic anonymized data dumps for researchers
- **Alembic migrations** — set up production-grade schema migrations

---

## Technical Considerations

### Language & Stack

| Component    | Status / Choice                                         |
|-------------|--------------------------------------------------------|
| Core engine  | Python 3.12 + asyncio (prototype); Rust/Go for scale   |
| API server   | FastAPI (planned, foundation in place)                  |
| Frontend     | Next.js / SvelteKit / Astro (TBD)                      |
| Database     | PostgreSQL (prod), SQLite+aiosqlite (dev/test)         |
| ORM          | SQLAlchemy 2.0 async                                   |
| Migrations   | Alembic (schema ready; migration scripts pending)      |
| Task queue   | Redis-backed (Celery, Bull, or custom) — pending       |
| Time-series  | TimescaleDB extension or ClickHouse — pending          |
| Search       | Meilisearch or Elasticsearch — pending                 |
| Graphs       | Chart.js, D3.js, or Grafana embeds — pending           |
| DNS          | dnspython (async)                                      |
| HTTP         | httpx (async)                                          |
| CLI          | Typer + Rich                                           |

### Ethical Guidelines

- **No exploitation** — detection only, never attempt to exploit or gain unauthorized access
- **No credential brute-forcing** — RCON detection is port-open detection, nothing more
- **Rate limiting** — respect server resources; don't flood targets with requests
- **Opt-out mechanism** — server owners can request exclusion from the index
- **Data retention policy** — define and enforce how long data is stored
- **Legal compliance** — review GDPR, CFAA, and local laws before deployment
- **Responsible disclosure** — if a critical vulnerability is discovered, notify the server owner
- **Transparency** — clearly document what data is collected and how it's used on mcin.tel

---

## Progress Log

### Branch: `feature/phase-1-2-core-infrastructure`

**Completed (2025):**

| Area | What was built |
|---|---|
| Project scaffold | `pyproject.toml`, `.gitignore`, `.env.example`, `src/` layout, `data/.gitkeep` |
| Config | `mcintel/config.py` — typed pydantic-settings `Settings` singleton |
| Logging | `mcintel/logging.py` — structured text/JSON logging with keyword extras |
| DB session | `mcintel/db/session.py` — async SQLAlchemy, auto-create for dev, FastAPI dep |
| DB models | `mcintel/db/models.py` — 9 tables: `Server`, `ServerPing`, `ServerMotdHistory`, `ServerFaviconHistory`, `Player`, `PlayerUsernameHistory`, `PlayerSighting`, `DnsRecord`, `IpMetadata`, `PortScanResult` |
| Java SLP | `mcintel/scanner/slp.py` — modern (1.7+) + legacy (1.4–1.6) protocols, full JSON parsing, Chat component parsing, mod detection, software fingerprinting, `ping_many` |
| Bedrock ping | `mcintel/scanner/bedrock.py` — RakNet Unconnected Ping/Pong, full MCPE advertisement parsing, `ping_bedrock_many` |
| DNS resolver | `mcintel/dns/resolver.py` — SRV, A/AAAA, CNAME chain, PTR, NS, TXT; ipinfo.io geo integration; in-memory cache |
| Player intel | `mcintel/players/mojang.py` — UUID lookup, bulk lookup, full profile+textures, offline UUID, cape classification, `MojangClient` |
| CLI | `mcintel/cli/commands.py` — `lookup`, `scan`, `player`, `dns`, `version` commands with Rich output and `--json` flag |
| Tests | `tests/test_slp.py` (130+ tests), `tests/test_dns.py` (100+ tests), `tests/test_players.py` (65+ tests) — **295 tests, 0 failures** |

*Last updated: 2025*