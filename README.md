<div align="center">

# 🔍 mcintel

### Minecraft Open-Source Intelligence Toolkit

**[mcin.tel](https://mcin.tel)**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)]()
[![Minecraft](https://img.shields.io/badge/minecraft-java%20%26%20bedrock-green.svg)]()

*Gather, track, and analyze intelligence on Minecraft servers, players, and infrastructure.*

</div>

---

## About

**mcintel** is an open-source intelligence (OSINT) platform purpose-built for the Minecraft ecosystem. It provides tools to query, monitor, and analyze Minecraft servers and their surrounding infrastructure — DNS records, IP history, player activity, mod/plugin fingerprints, and more.

Whether you're a server administrator investigating copycat servers, a security researcher studying the Minecraft threat landscape, or just curious about the infrastructure behind your favorite server — mcintel gives you the tools to dig deeper.

## Features

### 🖥️ Server Intelligence
- **Server List Ping (SLP)** — Query any Java Edition server using the native protocol to retrieve MOTD, version, player count, sample player list, favicon, and mod info.
- **Bedrock Ping** — Query Bedrock Edition servers via the RakNet protocol.
- **Historical Tracking** — Store and compare server responses over time to detect changes in configuration, branding, or player base.
- **Player Count Graphs** — Visualize online player counts over hours, days, weeks, and months.
- **Uptime Monitoring** — Track server availability and response latency over time.

### 🌐 DNS & Network Intelligence
- **SRV Record Lookup** — Resolve `_minecraft._tcp.<domain>` SRV records to find the true host and port, with automatic A/AAAA record fallback.
- **DNS History** — Track how a server's DNS records change over time, revealing hosting migrations and infrastructure changes.
- **IP Geolocation** — Integration with [ipinfo.io](https://ipinfo.io) for IP-to-location mapping, ASN data, and hosting provider identification.
- **Reverse DNS** — Map IPs back to hostnames to discover related services and shared hosting.
- **Port Fingerprinting** — Scan for Minecraft-related ports (25565, 25575/RCON, 19132/Bedrock, 8123/Dynmap, etc.).

### 👤 Player Intelligence
- **UUID Lookup** — Resolve usernames to UUIDs and vice versa via the Mojang API.
- **Username History** — Track past usernames associated with a UUID.
- **Skin & Cape Analysis** — Retrieve and archive player skins and capes.
- **Player-Server Association** — Map which servers a player has been observed on via SLP sample data.
- **NameMC Integration** — Pull public profile data, friends lists, and server affiliations.

### 🔌 Plugin & Mod Detection
- **Forge Handshake** — Perform a Forge mod loader handshake to enumerate installed server-side mods.
- **Query Protocol** — Use the Minecraft query protocol (when enabled) to extract plugin lists, map names, and game types.
- **Version Fingerprinting** — Identify server software (Spigot, Paper, Purpur, Fabric, etc.) from protocol behavior and response patterns.
- **BungeeCord / Velocity Detection** — Identify proxy-based server networks.

### 📡 Mass Reconnaissance
- **Range Scanning** — Scan IP ranges for active Minecraft servers.
- **Shodan / Censys Integration** — Leverage existing internet-wide scan data to discover Minecraft servers at scale.
- **Server List Scraping** — Aggregate data from public server list websites to build a comprehensive server database.

### 🖼️ Favicon & MOTD Analysis
- **Favicon Tracking** — Archive and diff server favicons over time.
- **Favicon Clustering** — Group servers that share identical or similar favicons (potential network identification).
- **MOTD Parsing** — Extract and index MOTD text, detect contact info, Discord links, and branding patterns.

### 🗺️ Web Panel Discovery
- **Dynmap / BlueMap / Pl3xMap** — Detect live map services exposed on common ports.
- **Admin Panel Detection** — Identify Pterodactyl, AMP, Multicraft, or other management panels.

## Quick Start

> **⚠️ Work in Progress** — mcintel is under active development. See [PLAN.md](PLAN.md) for the feature roadmap.

```
git clone https://github.com/dmaax/mcintel.git
cd mcintel
```

*Full setup instructions will be added as core modules are implemented.*

## Project Structure

```
mcintel/
├── README.md
├── PLAN.md            # Feature roadmap and development plan
├── src/               # Core source code
│   ├── scanner/       # SLP, query protocol, and port scanning
│   ├── dns/           # DNS resolution, SRV lookups, history
│   ├── players/       # Player UUID, username, skin lookups
│   ├── plugins/       # Mod and plugin detection
│   ├── web/           # Web panel and API
│   └── db/            # Database models and storage
├── data/              # Collected intelligence data
└── docs/              # Extended documentation
```

## Legal & Ethics

mcintel is intended for **legitimate OSINT research, server administration, and security analysis**. All data collected by mcintel is either:

- Publicly accessible via documented Minecraft protocols (SLP, Query, Forge handshake)
- Available through public APIs (Mojang API, ipinfo.io, NameMC)
- Obtained from public server list websites

**Do not** use mcintel to:
- Harass, dox, or stalk individuals
- Attack, exploit, or disrupt Minecraft servers
- Violate any applicable laws or terms of service

You are solely responsible for how you use this tool. Always act within the law and respect the privacy of others.

## Contributing

Contributions are welcome! Whether it's a bug fix, new feature, documentation improvement, or just an idea — feel free to open an issue or pull request.

## License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

**[mcin.tel](https://mcin.tel)** — See the bigger picture.

</div>
