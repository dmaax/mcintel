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

- [ ] Project scaffolding (monorepo layout, linting, CI)
- [ ] Database schema design (PostgreSQL / SQLite for dev)
  - Servers table (ip, port, first_seen, last_seen, etc.)
  - Pings table (timestamped SLP responses)
  - Players table (uuid, username, first_seen)
  - DNS records table (historical A, SRV, CNAME entries)
  - IP metadata table (geo, ASN, hosting provider)
- [ ] Configuration system (YAML/TOML config, env vars, CLI flags)
- [ ] Logging & structured output (JSON logs for pipeline use)
- [ ] Job scheduler / task queue for recurring scans
- [ ] Rate-limiting & politeness layer (respect targets, configurable delays)

---

## Phase 2 — Server Intelligence

The bread and butter — query Minecraft servers and store everything.

### 2.1 Server List Ping (SLP)

- [ ] Implement modern SLP protocol (1.7+)
  - Handshake → Status Request → Status Response → Ping/Pong
- [ ] Parse full JSON response and persist:
  - `version.name` and `version.protocol`
  - `players.max`, `players.online`, `players.sample[]` (UUIDs + usernames)
  - `description` (MOTD — supports Chat component JSON and legacy `§` codes)
  - `favicon` (base64 PNG)
  - `modinfo` / `forgeData` (mod loader + mod list)
  - `enforcesSecureChat`, `preventsChatReports` flags
- [ ] Legacy SLP for servers < 1.7 (0xFE ping)
- [ ] Bedrock Edition ping (RakNet unconnected ping)
- [ ] Scheduled pinging at configurable intervals (e.g., every 5 min, 15 min, 1 hr)

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

- [ ] Forge handshake to enumerate server-side mods and versions
- [ ] Detect server software from `version.name` patterns:
  - Vanilla, Spigot, Paper, Purpur, Folia, Fabric, Forge, NeoForge, Sponge, etc.
- [ ] Detect proxy layers:
  - BungeeCord, Waterfall, Velocity (via protocol behavior or error messages)
  - GeyserMC (Bedrock-to-Java bridge detection)
- [ ] Known vulnerability flagging based on detected software + version

### 2.5 Favicon Tracking

- [ ] Store favicon hashes (perceptual hash + SHA-256)
- [ ] Track favicon changes over time
- [ ] Cluster servers sharing identical or visually similar favicons
- [ ] Reverse-search: "find all servers using this icon"

### 2.6 MOTD Analysis

- [ ] Strip formatting codes, store both raw and plaintext
- [ ] Extract potential contact information (Discord invite links, URLs, emails)
- [ ] Track MOTD changes over time (diff history)
- [ ] Cluster servers by similar MOTD text (fuzzy matching)

---

## Phase 3 — DNS & Network Intelligence

Map the network footprint of a Minecraft server.

### 3.1 DNS Resolution Chain

- [ ] **SRV record lookup**: `_minecraft._tcp.<domain>` → target host + port
- [ ] **A / AAAA record fallback** when no SRV exists
- [ ] **CNAME chain following** — record the full chain
- [ ] Store historical DNS records with timestamps (DNS history)
- [ ] Detect DNS changes / migrations over time
- [ ] Reverse DNS (PTR) lookups on server IPs
- [ ] TXT record inspection (SPF, verification tokens — can reveal hosting info)
- [ ] NS record tracking (identify DNS provider: Cloudflare, etc.)

### 3.2 IP Intelligence

- [ ] **ipinfo.io integration** — `https://ipinfo.io/{ip}/json`
  - Geolocation (city, region, country, coordinates)
  - ASN & organization name
  - Hosting provider detection (is this a datacenter or residential?)
- [ ] Support for alternative providers (MaxMind GeoLite2, ip-api.com) as fallback
- [ ] Historical IP tracking — when did the server change IPs?
- [ ] Map visualization of server locations (GeoJSON export)

### 3.3 DDoS Protection & Proxy Detection

- [ ] Detect common Minecraft DDoS protection services:
  - TCPShield, Cosmic Guard, NeoProtect, OVH Game DDoS Protection
- [ ] Identify if IP belongs to a known proxy/protection network
- [ ] Attempt to discover origin IP behind protection layers (via DNS history, certificate transparency, etc.)

### 3.4 Port Fingerprinting

- [ ] Scan for common Minecraft-adjacent ports on the same host:
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

- [ ] Mojang API integration:
  - Username → UUID: `https://api.mojang.com/users/profiles/minecraft/<username>`
  - UUID → Profile: `https://sessionserver.mojang.com/session/minecraft/profile/<uuid>`
- [ ] Cache results locally to avoid rate limits
- [ ] Detect "cracked" (offline-mode) servers by checking UUID format (v3 vs v4)

### 4.2 Username History

- [ ] Track usernames observed in SLP `players.sample[]` over time
- [ ] Correlate UUID sightings across multiple servers
- [ ] Build a timeline: "Player X was seen on Server A on date Y"

### 4.3 Skin & Cape Analysis

- [ ] Download and store player skin textures from session server
- [ ] Detect cape types (Mojang, OptiFine, MinecraftCapes, LabyMod)
- [ ] Skin change history tracking
- [ ] Perceptual hashing for finding similar/identical skins

### 4.4 Player-Server Association Graph

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

- [ ] `mcintel lookup <address>` — quick single-server lookup
- [ ] `mcintel scan <cidr>` — scan an IP range
- [ ] `mcintel watch <address>` — continuous monitoring with live output
- [ ] `mcintel player <username|uuid>` — player lookup
- [ ] `mcintel dns <domain>` — full DNS chain analysis
- [ ] `mcintel export <address> --format json|csv|pdf` — export reports
- [ ] `mcintel daemon` — run the scheduler/collector in the background

---

## Ideas Backlog

Unscoped ideas that don't fit neatly into a phase yet.

- **Minecraft protocol version history database** — map protocol numbers to release names
- **Server JAR fingerprinting** — identify exact server software from protocol quirks
- **Honeypot detection** — identify servers that are likely honeypots (unusual behavior)
- **Cracked server enumeration** — detect offline-mode servers (UUID format analysis)
- **Resource pack URL extraction** — servers can push resource packs; URL may leak info
- **Chat protocol analysis** — join servers to passively observe chat (ethical/legal considerations)
- **Velocity modern forwarding detection** — distinguish proxy types by handshake behavior
- **Plugin message channel enumeration** — detect registered plugin channels (reveals plugins)
- **SRV record hijack monitoring** — alert if a tracked domain's SRV record changes unexpectedly
- **Minecraft Realms lookup** — discover and track Realms servers via the Realms API
- **Bedrock server intelligence** — full parity with Java edition features
- **WHOIS integration** — domain ownership data for servers using custom domains
- **Email/OSINT pivoting** — from a server domain, find registrant info → other domains
- **Screenshot service** — join a server briefly, capture spawn screenshot, archive it
- **Tor/VPN exit node detection** — flag server IPs that are known anonymization endpoints
- **Discord bot** — `/mcintel lookup play.example.com` for quick lookups in Discord
- **Telegram bot** — same as above for Telegram users
- **Public dataset exports** — periodic anonymized data dumps for researchers

---

## Technical Considerations

### Language & Stack

| Component    | Candidates                                      |
|-------------|------------------------------------------------|
| Core engine  | Rust or Go (performance for mass scanning)      |
| API server   | Rust (Axum), Go (Gin/Echo), or Python (FastAPI) |
| Frontend     | Next.js / SvelteKit / Astro                     |
| Database     | PostgreSQL (primary), Redis (caching/queues)    |
| Task queue   | Redis-backed (Celery, Bull, or custom)          |
| Time-series  | TimescaleDB extension or ClickHouse             |
| Search       | Meilisearch or Elasticsearch                    |
| Graphs       | Chart.js, D3.js, or Grafana embeds              |

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

*Last updated: 2026*
