# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-perf crate.

## Overview

Performance monitoring for ArcBox Pro. Features:

- **Real-time metrics**: CPU, memory, disk I/O, network
- **Historical data**: Time-series storage with configurable retention
- **Container metrics**: Per-container resource usage
- **VM metrics**: Per-VM resource usage (vCPU, VirtIO devices)
- **Platform support**: macOS and Linux

## License

BSL-1.1 (converts to MIT after 4 years)

## Architecture

```
arcbox-perf/src/
└── lib.rs      # PerfMonitor, SystemMetrics, ContainerMetrics, VmMetrics
```

### Platform-Specific Collection

| Platform | CPU | Memory | Disk I/O | Network |
|----------|-----|--------|----------|---------|
| macOS | `top -l 1` | `sysctl` + `vm_stat` | `iostat` | `netstat -ib` |
| Linux | `/proc/stat` | `/proc/meminfo` | `/proc/diskstats` | `/proc/net/dev` |

## Key Types

| Type | Description |
|------|-------------|
| `PerfMonitor` | Main collector with history storage |
| `SystemMetrics` | CPU, memory, disk, network, load average |
| `ContainerMetrics` | Container-specific metrics (CPU, memory, block I/O, net) |
| `VmMetrics` | VM-specific metrics (vCPU, VirtIO block/net) |
| `HistoryConfig` | Max samples, sample interval |

## Key Operations

```rust
// Create monitor
let monitor = PerfMonitor::new(1000); // 1 second interval

// Collect metrics (automatically stored in history)
let system = monitor.collect_system();
let container = monitor.collect_container(id, name);
let vm = monitor.collect_vm(id);

// Query history
let history = monitor.system_history();
let container_history = monitor.container_history(id);
let vm_history = monitor.vm_history(id);

// Clear history
monitor.clear_history();
```

## Metrics Details

### SystemMetrics
- `cpu_percent`, `cpu_per_core` - CPU usage (0-100)
- `memory_used/total/available/cached` - Memory in bytes
- `disk_read_bps/write_bps` - Disk throughput
- `disk_read_iops/write_iops` - Disk operations
- `net_rx_bps/tx_bps` - Network throughput
- `net_rx_pps/tx_pps` - Network packets
- `load_1/5/15` - Load averages

### ContainerMetrics
- CPU/memory usage with limits
- Block I/O totals
- Network totals
- PID count

### VmMetrics
- Per-vCPU usage
- Guest memory usage
- VirtIO block/net statistics

## Status

Pro layer is substantially implemented:
- Full PerfMonitor with collection and history
- Platform-specific collectors for macOS and Linux
- Rate calculations for I/O metrics
- Configurable history retention

TODO:
- Threshold-based alerts
- Container/VM profiling integration
- Export to external metrics systems (Prometheus, etc.)

## Common Commands

```bash
# Build
cargo build -p arcbox-perf

# Test
cargo test -p arcbox-perf

# Build with release optimizations
cargo build -p arcbox-perf --release
```
