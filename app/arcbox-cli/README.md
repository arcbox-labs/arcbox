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

## Output formats

`--format` is global but validated for the selected command before any command
I/O. Unsupported `json` or `quiet` combinations exit nonzero instead of
falling back to decorated text.

Read-only JSON schemas are available for `doctor`, `top`, `disk usage`,
`boot status`, `boot list`, `setup status`, `machine inspect`,
`sandbox inspect`, and, on macOS, `dns status`.
Disk and boot sizes use raw `*_bytes` fields. For read-only commands, quiet
output is limited to `setup status`, which prints `installed`, `partial`, or
`unknown`.

Status exit codes are health contracts: `doctor`, `dns status`, `boot status`,
and `setup status` exit nonzero when their report is unhealthy or incomplete.
A check that could not be run is reported as `unknown` rather than failed —
`doctor` counts it separately and `setup status` still exits zero, because a
login-shell probe that times out says nothing about the integration itself.
Drift the daemon repairs on its next start is likewise reported as a detail,
not as an incomplete cache: `boot status` says so for a runtime binary missing
its executable bit instead of asking for a re-download.
If Docker is unavailable, `disk usage` keeps host image facts, sets runtime
reclaimable fields to `null`, reports the query error, and exits nonzero.

## Exit status

- `0`: command succeeded.
- `1`: an `abctl` operation or daemon connection failed.
- `2`: command-line arguments were invalid.
- Remote commands (`machine exec`, `sandbox run` / `exec`, and `claude`) propagate the
  command's exit status; sandbox signal exits use the shell convention `128 + signal`.

## Configuration

Socket path resolution order:
1. `ARCBOX_SOCKET` environment variable
2. The active profile or `ARCBOX_DATA_DIR` layout (`<data-dir>/run/docker.sock`)

The production default is `~/.arcbox/run/docker.sock`. `DOCKER_HOST` is
honored by the Docker CLI, not by ArcBox's direct socket clients.

## License

MIT OR Apache-2.0
