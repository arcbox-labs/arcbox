# arcbox-perf

Performance monitoring for ArcBox Pro.

## Overview

This crate provides real-time performance monitoring for ArcBox VMs and containers. It collects system metrics (CPU, memory, disk I/O, network), stores historical data, and supports per-container and per-VM metrics. Platform-specific collectors are implemented for both macOS and Linux.

## Features

- **Real-time metrics**: CPU, memory, disk I/O, network throughput
- **Historical data**: Time-series storage with configurable retention
- **Container metrics**: Per-container CPU, memory, block I/O, network
- **VM metrics**: Per-VM vCPU usage, VirtIO device statistics
- **Cross-platform**: Native collectors for macOS and Linux

## Usage

```rust
use arcbox_perf::{PerfMonitor, HistoryConfig};

// Create monitor with 1 second sample interval
let monitor = PerfMonitor::new(1000);

// Collect system metrics (automatically stored in history)
let system = monitor.collect_system();
println!("CPU: {:.1}%, Memory: {} MB used",
    system.cpu_percent,
    system.memory_used / 1024 / 1024);

// Collect container/VM metrics
let container = monitor.collect_container("container-id", "my-app");
let vm = monitor.collect_vm("vm-id");

// Query history
let history = monitor.system_history();
let container_history = monitor.container_history("container-id");
```

## License

BSL-1.1 (converts to MIT after 4 years)
