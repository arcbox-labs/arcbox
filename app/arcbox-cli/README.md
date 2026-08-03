# arcbox-cli

Command-line interface for ArcBox.

## Overview

This crate provides a thin command-line interface for ArcBox machine management and local integration helpers. Runtime and Docker API serving are handled by the separate `arcbox-daemon` binary.

## Features

- **Machine Management**: Create and manage Linux VMs
- **Runtime Migration**: Import local workloads from Docker Desktop or OrbStack
- **Daemon Lifecycle**: Start/stop daemon process
- **Docker Context Integration**: Seamless switching between Docker and ArcBox
- **Native Kubernetes Integration**: Manage the ArcBox k3s cluster and bundled `kubectl`
- **Boot Asset & DNS Helpers**: Manage boot cache and resolver setup

## Usage

```bash
# Machine (VM) operations
abctl machine create myvm
abctl machine start myvm
abctl machine list
abctl machine stop myvm

# Runtime migration
abctl migrate from orbstack --dry-run          # inspect the plan, change nothing
abctl migrate from orbstack --dry-run --json   # same plan, machine-readable
abctl migrate from docker-desktop
abctl migrate from orbstack --source-socket ~/.orbstack/run/docker.sock --yes
abctl migrate from orbstack --no-start         # recreate but leave stopped

# Daemon management
abctl daemon start              # Start daemon in background
abctl daemon stop               # Stop daemon
abctl info                      # System info
abctl version                   # Version info

# Docker context integration
abctl docker enable             # Set ArcBox as Docker context
abctl docker disable            # Reset to default context

# Native Kubernetes integration
abctl k8s start                  # Start the ArcBox Kubernetes cluster
abctl k8s enable                 # Install kubectl + activate ArcBox kube context
kubectl get nodes

# Run containers through Docker CLI
docker run hello-world
```

## Configuration

Socket path resolution order:
1. `ARCBOX_SOCKET` environment variable
2. `DOCKER_HOST` (with `unix://` prefix stripped)
3. Default: `~/.arcbox/docker.sock`

## License

MIT OR Apache-2.0
