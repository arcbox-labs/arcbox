<div align="center">

# ArcBox

**A fast, open-source container runtime for macOS.**

**Built from scratch in Rust. Drop-in Docker, native Kubernetes, and full Linux VMs.**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.96+-orange.svg)](https://www.rust-lang.org)
[![Desktop](https://img.shields.io/github/v/release/arcboxlabs/arcbox-desktop?label=desktop&color=green)](https://github.com/arcboxlabs/arcbox-desktop/releases)
[![Discord](https://img.shields.io/discord/1234567890?logo=discord&label=discord&color=5865F2)](https://arcbox.link/discord)
[![Telegram](https://img.shields.io/badge/telegram-chat-26A5E4?logo=telegram)](https://arcbox.link/telegram)
[![Docs](https://img.shields.io/badge/docs-arcbox.dev-blueviolet?logo=gitbook)](https://arcbox.link/docs)

</div>

## Why ArcBox

ArcBox is an open-source alternative to Docker Desktop and OrbStack on macOS.
OrbStack set the bar for running Docker on a Mac quickly and with little overhead,
but it is closed-source. ArcBox is open source under MIT/Apache-2.0, written from
scratch in Rust, and aims to match it.

The same runtime gives each AI agent, CI job, or piece of untrusted code its own
real microVM. The sandbox you run locally is the same primitive ArcBox Platform
runs in the cloud, so you can build against local sandboxes and scale to a fleet
without changing your code. ArcBox is in public beta. Join us on
[Discord](https://arcbox.link/discord), or
[open an issue](https://github.com/arcboxlabs/arcbox/issues).

## Quick start

```bash
# Install with Homebrew
brew install --cask arcboxlabs/tap/arcbox

# or with the install script
curl -fsSL https://get.arcbox.dev | bash

# Start the daemon and enable Docker compatibility
abctl daemon start
abctl docker enable

# Run a container
docker run -d -p 8080:80 nginx
curl http://localhost:8080
```

Run `abctl doctor` to check the runtime, and `abctl --help` to see every command.

## Containers

ArcBox is a drop-in Docker engine. It exposes a Docker-compatible socket and
proxies to a guest `dockerd`, so the Docker CLI, your scripts, and your Compose
files work without changes.

```bash
abctl docker enable        # creates and activates the "arcbox" Docker context
docker run -d -p 8080:80 nginx
docker compose up
docker build -t myapp .
```

Containers, images, Compose, port forwarding, bind mounts, named volumes, and
interactive `exec` all work today.

### amd64 and arm64 images

ArcBox runs `linux/amd64` images on Apple Silicon next to native arm64. x86-64 is
translated inside the guest by [FEX](https://github.com/FEX-Emu/FEX), an
open-source emulator, with nothing to configure.

```bash
docker run --platform linux/amd64 alpine uname -m
# x86_64
```

### Native Kubernetes

A local k3s cluster, managed by the daemon, with host integration for `kubectl`.

```bash
abctl k8s start
abctl k8s kubeconfig >> ~/.kube/config
kubectl get nodes
```

### Migrate from Docker Desktop or OrbStack

Import your workloads from another local runtime.

```bash
abctl migrate from docker-desktop
abctl migrate from orbstack
```

## Sandboxes

ArcBox can also run disposable microVMs, each with its own kernel, for AI agents,
untrusted code, and CI jobs. You can snapshot a booted, idle sandbox and restore
copies of it to skip a cold boot.

```bash
abctl sandbox create --memory 512
abctl sandbox run <id> -- ./untrusted-binary
abctl sandbox checkpoint <id> --name clean   # capture a ready snapshot
abctl sandbox restore clean                  # start a new sandbox from it
```

Create, run, exec, snapshot, and restore work today. We are aiming for cold boots
under 200 ms, near-instant restore from a snapshot, and roughly 10–30 MB of
overhead per sandbox.

## Bring your own machine

ArcBox Platform turns hardware you already own into cloud capacity. Enroll your
Macs and Linux machines into a fleet, and they become on-demand compute for your
team's sandboxes, builds, and CI, at the cost of your own hardware instead of
premium cloud pricing. Apple Silicon is first-class, so the Mac capacity that the
big clouds meter at a steep markup is simply yours to pool. (In development.)

## Machines

When you want a complete environment instead of a container, ArcBox can create
full Linux VMs, each with its own kernel, persistent disk, and a distro you
choose.

```bash
abctl machine create dev --distro ubuntu
abctl machine start dev
abctl machine list
```

Creating, starting, and managing Ubuntu and Alpine machines works today. Shell
and SSH access into a running machine is coming.

## Built from scratch

Most of ArcBox's performance-critical code is custom rather than vendored:

- A VMM on Hypervisor.framework, with manual vCPU execution and a device model we
  maintain ourselves.
- VirtIO devices: `virtio-net`, `virtio-blk`, `virtio-fs`, `virtio-console`,
  `virtio-vsock`, and a balloon device.
- A macOS networking datapath in userspace: DHCP, DNS forwarding, TCP via
  `smoltcp`, and host socket proxying, with no `pf` NAT or `utun` device.
- VirtioFS/FUSE filesystem sharing, and a vsock guest agent that speaks protobuf.
- x86 translation through FEX, so `linux/amd64` images run on Apple Silicon.

These are the numbers we are working toward, with OrbStack for comparison:

| Metric | ArcBox | OrbStack |
|--------|--------|----------|
| Cold boot | <1.5 s | ~2 s |
| Warm boot | <500 ms | <1 s |
| Idle memory | <150 MB | ~200 MB |
| File I/O (vs native) | >90% | 75–95% |
| Network throughput | >50 Gbps | ~45 Gbps |

## Desktop app

ArcBox Desktop is a native SwiftUI app. It talks to the daemon over gRPC and uses
the Docker-compatible API for Docker resources. It covers Docker (containers,
images, volumes, networks) and Kubernetes (pods, services), and includes log
streaming, a terminal, and a file browser for a container's filesystem. Source:
[arcboxlabs/arcbox-desktop](https://github.com/arcboxlabs/arcbox-desktop).

## What's next

- Shell and SSH access for machines
- Faster x86 translation
- Linux host support (macOS first)
- Wider Docker Engine API coverage

## Requirements

- macOS on Apple Silicon. Intel support is in progress.
- The Docker CLI. ArcBox replaces the engine, not the CLI; `abctl docker setup`
  can install it for you.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions, code standards, and
development setup. The runtime is open source under MIT/Apache-2.0. Personal use
is free, and commercial use is free during the public beta.

## License

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)

---

<div align="center">

[Website](https://arcbox.dev) · [Docs](https://arcbox.link/docs) · [Discord](https://arcbox.link/discord)

</div>
