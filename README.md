<div align="center">

# ArcBox

**A fast, open-source container runtime for macOS — built from scratch in Rust, from hypervisor to CLI.**

**Drop-in Docker · Native Kubernetes · Full Linux machines.**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.96+-orange.svg)](https://www.rust-lang.org)
[![Desktop](https://img.shields.io/github/v/release/arcboxlabs/arcbox-desktop?label=desktop&color=green)](https://github.com/arcboxlabs/arcbox-desktop/releases)
[![Discord](https://img.shields.io/discord/1234567890?logo=discord&label=discord&color=5865F2)](https://arcbox.link/discord)
[![Telegram](https://img.shields.io/badge/telegram-chat-26A5E4?logo=telegram)](https://arcbox.link/telegram)
[![Docs](https://img.shields.io/badge/docs-arcbox.dev-blueviolet?logo=gitbook)](https://arcbox.link/docs)

</div>

---

## Why ArcBox

ArcBox is an open-source alternative to Docker Desktop and OrbStack for macOS.
Docker Desktop is the incumbent; OrbStack set the bar for running Docker on a Mac
fast and light, but it's closed-source. ArcBox aims at that bar — and is open
source under MIT/Apache-2.0.

The whole stack is written in Rust, top to bottom: our own virtual machine
monitor built directly on Apple's **Hypervisor.framework**, a custom VirtIO
device stack, a custom macOS networking datapath, a VirtioFS/FUSE filesystem, and
a guest agent that talks to the host over vsock. Owning the runtime end to end is
what makes it fast, lean, and fully under our control.

ArcBox is in **public beta** — [join the community](https://arcbox.link/discord)
and [tell us what to build next](https://github.com/arcboxlabs/arcbox/issues).

## Containers

The core of ArcBox is a drop-in Docker engine. It exposes a Docker-compatible
socket and proxies to a guest `dockerd`, so your existing CLI, scripts, and
Compose files keep working unchanged.

```bash
abctl docker enable        # creates and activates the "arcbox" Docker context
docker run -d -p 8080:80 nginx
docker compose up
docker build -t myapp .
```

Containers, images, Compose, port forwarding, bind mounts, named volumes, and
interactive `exec`/terminal flows all work today.

### amd64 and arm64 images

ArcBox runs `linux/amd64` images right alongside native arm64 on Apple Silicon,
translated transparently inside the guest by [FEX](https://github.com/FEX-Emu/FEX)
— an open-source x86 emulator, with nothing to configure.

```bash
docker run --platform linux/amd64 alpine uname -m
# x86_64
```

### Native Kubernetes

A local Kubernetes cluster (k3s) managed by the daemon, with host integration
for `kubectl`.

```bash
abctl k8s start
abctl k8s kubeconfig >> ~/.kube/config
kubectl get nodes
```

### Migrate from Docker Desktop or OrbStack

Import your existing local workloads in place.

```bash
abctl migrate from docker-desktop
abctl migrate from orbstack
```

## Quick start

```bash
# Install (Homebrew)
brew install --cask arcboxlabs/tap/arcbox

# …or via the install script
curl -fsSL https://get.arcbox.dev | bash

# Start the daemon and enable Docker compatibility
abctl daemon start
abctl docker enable

# Run a container
docker run -d -p 8080:80 nginx
curl http://localhost:8080
```

Run `abctl doctor` to check the runtime, and `abctl --help` to explore all
commands.

## Sandboxes

Need more isolation than a container? ArcBox runs **disposable microVMs** — each
its own VM, ideal for untrusted code, CI jobs, and ephemeral test environments.
Snapshot a booted-and-idle sandbox and restore clones from it to skip cold boot
entirely.

```bash
abctl sandbox create --memory 512
abctl sandbox run <id> -- ./untrusted-binary
abctl sandbox checkpoint <id> --name clean   # capture a ready snapshot
abctl sandbox restore clean                  # clone a new sandbox from it
```

Sandboxes are engineered for sub-200 ms cold boots, near-instant restore from
snapshot, and tens of megabytes of overhead — disposable enough to spin up per
job and throw away.

## Machines

When you want a complete environment rather than a container, spin up a full
Linux VM with its own kernel, persistent disk, and the distro of your choice.

```bash
abctl machine create dev --distro ubuntu
abctl machine start dev
abctl machine list
```

Ubuntu and Alpine machines boot today, with first-class shell and SSH access
landing as we round out the beta.

## Built from scratch

ArcBox's performance-critical paths are all custom-built rather than vendored:

- **Custom VMM on Hypervisor.framework** — manual vCPU execution and a device
  model we own end to end, rather than Apple's managed Virtualization.framework.
- **Custom VirtIO stack** — `virtio-net`, `virtio-blk`, `virtio-fs`,
  `virtio-console`, `virtio-vsock`, and a balloon device.
- **Custom macOS networking datapath** — userspace DHCP, DNS forwarding, TCP via
  `smoltcp`, and host socket proxying, without `pf` NAT or a `utun` device.
- **VirtioFS/FUSE** filesystem sharing and a vsock guest agent speaking protobuf.
- **Transparent x86 translation** via FEX so `linux/amd64` images run on Apple Silicon.

Here's the bar we're building toward, measured against OrbStack:

| Metric | ArcBox | OrbStack |
|--------|--------|----------|
| Cold boot | <1.5 s | ~2 s |
| Warm boot | <500 ms | <1 s |
| Idle memory | <150 MB | ~200 MB |
| File I/O (vs native) | >90% | 75–95% |
| Network throughput | >50 Gbps | ~45 Gbps |

## Desktop app

ArcBox Desktop is a native SwiftUI app that talks to the daemon over gRPC and the
Docker-compatible API. It covers Docker (containers, images, volumes, networks)
and Kubernetes (pods, services), with live log streaming, an interactive
terminal, and a container file browser. Source:
[arcboxlabs/arcbox-desktop](https://github.com/arcboxlabs/arcbox-desktop).

## What's next

- First-class shell and SSH access for machines
- Even faster x86 translation
- Linux host support (macOS first)
- Deeper Docker Engine API coverage

## Requirements

- macOS on Apple Silicon (Intel support in progress)
- Docker CLI — ArcBox replaces the engine, not the CLI (`abctl docker setup`
  can install it for you)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, code standards,
and development setup. The runtime is open source under MIT/Apache-2.0; personal
use is free forever, and commercial use is free during the public beta.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)

---

<div align="center">

**[Website](https://arcbox.dev)** · **[Docs](https://arcbox.link/docs)** · **[Discord](https://arcbox.link/discord)**

</div>
