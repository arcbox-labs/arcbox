# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-core crate.

## Overview

Core coordination layer - the central orchestrator that manages VMs, machines, containers, images, and volumes. All higher-level operations (CLI, API, Docker) go through this layer.

## Architecture

```
arcbox-core/src/
├── lib.rs              # Crate entry, Runtime struct
├── runtime.rs          # Runtime - singleton orchestrator
├── config.rs           # Configuration (paths, defaults)
├── vm.rs               # VmManager - VM lifecycle
├── machine.rs          # MachineManager - named machine management
├── vm_lifecycle.rs     # VmLifecycleManager - auto start/stop
├── agent_client.rs     # AgentClient - guest agent RPC
├── agent_pool.rs       # AgentPool - connection pooling
├── event.rs            # EventBus - system events
├── error.rs            # CoreError
└── boot_assets.rs      # Kernel/initramfs management
```

## Runtime Singleton

```rust
pub struct Runtime {
    config: Config,
    event_bus: EventBus,
    vm_manager: Arc<VmManager>,
    machine_manager: Arc<MachineManager>,
    container_manager: Arc<ContainerManager>,
    image_store: Arc<ImageStore>,
    volume_manager: Arc<RwLock<VolumeManager>>,
    network_manager: Arc<NetworkManager>,
    exec_manager: Arc<ExecManager>,
    agent_pool: Arc<AgentPool>,
    vm_lifecycle: Arc<VmLifecycleManager>,
}
```

## Key Flows

### Container Creation
```
Runtime::create_container()
    → VmLifecycleManager::ensure_vm_ready()
    → ContainerManager::create()
    → AgentClient::create_container()
    → EventBus::publish(ContainerCreated)
```

### VM Lifecycle
```
VmLifecycleManager
    → on first container: start default VM
    → on last container exit: stop VM (after idle timeout)
    → handles restart on failure (RecoveryPolicy)
```

## Configuration

```rust
pub struct Config {
    pub data_dir: PathBuf,          // ~/.local/share/arcbox
    pub socket_path: PathBuf,       // ~/.arcbox/arcbox.sock
    pub docker_socket: PathBuf,     // ~/.arcbox/docker.sock
    pub vm: VmDefaults,             // CPU, memory defaults
    pub network: NetworkConfig,
}
```

## Data Directories

```
~/.local/share/arcbox/
├── images/         # OCI image layers
├── containers/     # Container state
├── machines/       # Machine configs
├── volumes/        # Named volumes
└── boot/           # Kernel, initramfs
```

## Common Commands

```bash
cargo build -p arcbox-core
cargo test -p arcbox-core
RUST_LOG=arcbox_core=debug cargo test
```

## Integration

- **arcbox-vmm**: Creates and manages VMs
- **arcbox-container**: Container state management
- **arcbox-image**: Image pulling and storage
- **arcbox-docker**: Docker API compatibility
- **arcbox-api**: gRPC API
- **arcbox-cli**: CLI commands
