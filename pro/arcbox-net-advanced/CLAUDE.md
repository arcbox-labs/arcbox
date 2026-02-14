# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-net-advanced crate.

## Overview

Advanced networking features for ArcBox Pro. Extends arcbox-net with:

- **VPN awareness**: Auto-detect VPN and route traffic appropriately
- **Advanced DNS**: Split DNS, custom resolvers
- **Traffic shaping**: QoS and bandwidth limits
- **Network policies**: Fine-grained access control

## License

BSL-1.1 (converts to MIT after 4 years)

## Architecture

```
arcbox-net-advanced/src/
├── lib.rs      # Main exports, AdvancedNetConfig, SplitDnsRule
├── dns.rs      # DnsResolver, SplitDnsResolver, DnsRecord, DnsResponse
└── vpn.rs      # VpnDetector, VpnInterface, VpnType
```

### Dependency

This crate extends `arcbox-net` (Core layer):
```
arcbox-net-advanced → arcbox-net
```

## Key Types

| Type | Description |
|------|-------------|
| `AdvancedNetConfig` | Configuration with VPN/DNS/split-DNS settings |
| `SplitDnsRule` | Domain-to-DNS-server mapping for split DNS |
| `VpnDetector` | Detects active VPN connections |
| `VpnInterface` | VPN interface information |
| `VpnType` | VPN protocol type (WireGuard, OpenVPN, etc.) |
| `DnsResolver` | Custom DNS resolver |
| `SplitDnsResolver` | Resolver with domain-based routing |
| `DnsRecord` | DNS record types (A, AAAA, CNAME, etc.) |
| `DnsRecordData` | DNS record data payload |
| `DnsResponse` | DNS query response |
| `RecordType` | DNS record type enum |

## Status

Pro layer is partially implemented. Current implementation includes:
- VPN detection module structure
- Split DNS resolver framework
- Configuration types

TODO:
- Full VPN detection for all platforms
- Traffic shaping implementation
- Network policy engine
- QoS implementation

## Common Commands

```bash
# Build
cargo build -p arcbox-net-advanced

# Test
cargo test -p arcbox-net-advanced

# Build with release optimizations
cargo build -p arcbox-net-advanced --release
```
