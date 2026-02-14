# arcbox-net-advanced

Advanced networking features for ArcBox Pro with VPN awareness and split DNS.

## Overview

This crate extends `arcbox-net` (Core layer) with enterprise-grade networking capabilities. It provides automatic VPN detection, split DNS for corporate environments, traffic shaping, and fine-grained network policies.

## Features

- **VPN awareness**: Auto-detect VPN connections and route traffic appropriately
- **Advanced DNS**: Split DNS with domain-based resolver routing
- **Traffic shaping**: QoS and bandwidth limits
- **Network policies**: Fine-grained access control

## Usage

```rust
use arcbox_net_advanced::{AdvancedNetConfig, SplitDnsRule, VpnDetector, SplitDnsResolver};

// Configure advanced networking
let config = AdvancedNetConfig {
    vpn_aware: true,
    dns_servers: vec!["8.8.8.8".to_string()],
    split_dns: vec![
        SplitDnsRule {
            domain: "corp.example.com".to_string(),
            servers: vec!["10.0.0.1".to_string()],
        },
    ],
};

// Detect active VPN connections
let detector = VpnDetector::new();
let vpn_interfaces = detector.detect();

// Use split DNS resolver
let resolver = SplitDnsResolver::new(config.split_dns);
```

## License

BSL-1.1 (converts to MIT after 4 years)
