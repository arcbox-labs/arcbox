<div align="center">

# ArcBox

**A fast, open-source container and VM runtime for macOS.**

**Built from scratch in Rust. Drop-in Docker, agent sandboxes, native
Kubernetes, and full Linux and macOS VMs.**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/rust-1.96+-orange.svg)](https://www.rust-lang.org)
[![Runtime](https://img.shields.io/github/v/release/arcboxlabs/arcbox?label=runtime&color=green)](https://github.com/arcboxlabs/arcbox/releases)
[![Desktop](https://img.shields.io/github/v/release/arcboxlabs/arcbox-desktop?label=desktop&color=green)](https://github.com/arcboxlabs/arcbox-desktop/releases)
[![Discord](https://img.shields.io/badge/discord-chat-5865F2?logo=discord)](https://arcbox.link/discord)
[![Telegram](https://img.shields.io/badge/telegram-chat-26A5E4?logo=telegram)](https://arcbox.link/telegram)
[![Docs](https://img.shields.io/badge/docs-arcbox.dev-blueviolet?logo=gitbook)](https://arcbox.link/docs)

</div>

## Why ArcBox

ArcBox is an open-source alternative to Docker Desktop and OrbStack on macOS.
OrbStack set the bar for running Docker on a Mac quickly and with little
overhead, but it is closed-source. ArcBox is open source under MIT/Apache-2.0
and written from scratch in Rust — its own VMM, VirtIO devices, filesystem
sharing, and network datapath — and aims to match it.

One daemon, one CLI, four kinds of workload on the same runtime:

| Tier | What it is | Where to start |
|------|------------|----------------|
| **Containers** | A drop-in Docker engine, plus native Kubernetes | `docker …`, `abctl k8s` |
| **Sandboxes** | Disposable microVMs for AI agents and untrusted code | `abctl claude`, `abctl sandbox` |
| **Linux machines** | Full VMs with their own kernel, disk, and distro | `abctl machine` |
| **macOS guests** | Throwaway macOS VMs, cloned from a base image | `abctl macos` |

The sandbox you run locally is the same primitive ArcBox Platform runs in the
cloud, so you can build against local sandboxes and scale to a fleet without
changing your code.

ArcBox is in public beta. Join us on [Discord](https://arcbox.link/discord), or
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

Containers, images, builds (BuildKit/Buildx), Compose, port forwarding, bind
mounts, named volumes, and interactive `exec` all work today. ArcBox manages the
matching `docker`, `buildx`, `compose`, and `kubectl` binaries for you
(`abctl docker setup`).

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
abctl k8s enable                     # point kubectl at the ArcBox cluster
abctl k8s kubeconfig >> ~/.kube/config
kubectl get nodes
```

### Container files in Finder

The guest's Docker data is mounted read-only on the host at `~/ArcBox`, served
over NFSv4 through a vsock relay. Named volumes, container state, and image
layers are browsable in Finder and readable by any host tool — no `docker cp`.

```bash
open ~/ArcBox
grep -r "panic" ~/ArcBox/volumes/my-app-data/_data
```

### Live resource usage

```bash
abctl top          # streaming CPU, memory, disk, and network for the System VM
abctl disk usage   # Docker data image usage; `abctl disk compact` reclaims free blocks
```

Per-container stats are available over the API and in the desktop app.

### Migrate from Docker Desktop or OrbStack

```bash
abctl migrate from docker-desktop
abctl migrate from orbstack
```

## Sandboxes and coding agents

ArcBox runs disposable microVMs — each with its own kernel, booted by Firecracker
nested inside the guest — for AI agents, untrusted code, and CI jobs.
`abctl claude` is that primitive with the ergonomics finished: it builds a sandbox
from a built-in template and attaches your terminal to Claude Code inside it,
with the agent's permission prompts switched off, because the microVM is the
isolation boundary instead.

```bash
export ANTHROPIC_API_KEY=sk-...
abctl claude                    # first run builds the image; later runs start in ~1s
abctl claude --id review        # a second, independent session
abctl claude -- --model opus    # everything after -- goes to the agent
```

Nothing on the host is mounted into the sandbox: `/workspace` starts empty, the
agent clones what it needs, and you copy results back out. See
[docs/agent-sandbox.md](docs/agent-sandbox.md).

Build sandboxes from a template, an existing Docker image, or a Dockerfile, and
snapshot a booted, idle sandbox to skip a cold boot on the next one:

```bash
abctl sandbox templates                            # built-in images
abctl sandbox create --from-image myapp:latest --memory 512 --ttl 3600
abctl sandbox run <id> -- ./untrusted-binary       # or `exec` for interactive
abctl sandbox cp <id>:/tmp/out.tgz .               # files in and out
abctl sandbox expose <id> 8080                     # reach a sandbox port on the host
abctl sandbox checkpoint <id> --name clean         # capture a ready snapshot
abctl sandbox restore <snapshot-id>                # new sandbox, near-zero boot
```

> Sandboxes need nested virtualization: Apple Silicon **M3 or newer** with
> **macOS 15+**, on the default VZ backend. On other hosts sandbox commands fail
> fast with a clear error.

Everything the CLI does is a gRPC call on the daemon socket, with server
reflection enabled, so SDKs and your own tooling can drive sandboxes directly —
create, exec, file transfer, port exposure, lifecycle events, snapshots. The
integration reference is [docs/sandbox-api.md](docs/sandbox-api.md).

## Linux machines

When you want a complete environment instead of a container, ArcBox creates full
Linux VMs, each with its own kernel, persistent disk, and a distro you choose.

```bash
abctl machine create dev --distro ubuntu --disk 50 --mount ~/code:/code
abctl machine start dev
abctl machine ssh dev                   # interactive shell
abctl machine exec dev -- cargo build   # one-shot command
abctl machine ls
```

Create, start, stop, inspect, directory mounts, interactive shells, and command
execution work today for Ubuntu and Alpine.

## macOS guests

On Apple Silicon, ArcBox also runs disposable macOS VMs: pull a published base
image once, then copy-on-write clone it to boot clean, throwaway guests in
seconds — the same "clone, use, discard" model, extended to macOS. A CoW clone of
a 64 GiB disk takes microseconds on APFS.

```bash
abctl macos image pull tahoe-base        # once (multi-GB, progress streams)
abctl macos create ci --image tahoe-base --cpus 4 --memory 8192
abctl macos start ci
abctl macos ip ci --wait 30              # reach it over the network
```

macOS guests run through Virtualization.framework only — Apple permits booting
macOS no other way — need an APFS data directory, and are capped at **2 guests
per host** by Apple's license. Details in
[docs/macos-guest.md](docs/macos-guest.md).

## Bring your own machine

ArcBox Platform turns hardware you already own into cloud capacity. Enroll your
Macs and Linux boxes into a fleet and they become on-demand runners for your
team's CI, builds, and sandboxes, at the cost of your own hardware instead of
premium cloud pricing. The fleet agent takes GitHub Actions jobs: Linux jobs run
in containers, macOS jobs get a fresh ephemeral macOS guest per job, and Windows
capability is served through WSL interop. Apple Silicon is first-class, so the
Mac capacity the big clouds meter at a steep markup is simply yours to pool.
(In development.)

## Built from scratch

Most of ArcBox's performance-critical code is custom rather than vendored:

- **Two hypervisor backends.** ArcBox's own VMM on Hypervisor.framework, with
  manual vCPU execution and a device model we maintain, plus a
  Virtualization.framework backend through a Swift shim. Switch with
  `abctl system backend hv|vz`.
- **VirtIO devices**: `virtio-net`, `virtio-blk`, `virtio-fs`, `virtio-console`,
  `virtio-vsock`, `virtio-rng`, and a balloon device.
- **A userspace network datapath on macOS**: DHCP, DNS forwarding, NAT and
  connection tracking, batched socket I/O, and userspace TCP termination that
  splices guest flows onto real host sockets — no `pf` NAT and no `utun` device.
  Containers are reachable by IP, and `abctl dns install` adds
  `*.arcbox.local` name resolution.
- **VirtioFS/FUSE filesystem sharing**, an NFSv4 export for `~/ArcBox`, and a
  vsock guest agent that speaks protobuf.
- **x86 translation through FEX**, so `linux/amd64` images run on Apple Silicon.
- A privileged helper with code-signature-based peer authentication for the few
  operations that need root, so the daemon itself does not run as root.

Measured, and documented in [docs/net-perf-limits.md](docs/net-perf-limits.md):
single-stream host→VM throughput of 22.7 Gbps on the custom backend, about twice
Apple's VirtIO-net in the same test (multi-flow saturation currently tops out at
10–12 Gbps combined).

These are the numbers we are working toward, with OrbStack for comparison:

| Metric | ArcBox target | OrbStack |
|--------|---------------|----------|
| Cold boot | <1.5 s | ~2 s |
| Warm boot | <500 ms | <1 s |
| Idle memory | <150 MB | ~200 MB |
| File I/O (vs native) | >90% | 75–95% |
| Network throughput | >50 Gbps | ~45 Gbps |

## Desktop app

ArcBox Desktop is a native SwiftUI app. It talks to the daemon over gRPC and uses
the Docker-compatible API for Docker resources. It covers Docker (containers,
images, volumes, networks) and Kubernetes (pods, services), and includes log
streaming, a terminal, live resource monitoring, and a file browser for
container, image, and volume filesystems. Source:
[arcboxlabs/arcbox-desktop](https://github.com/arcboxlabs/arcbox-desktop).

## What's next

- Sandbox SDKs and ArcBox Platform general availability
- Faster x86 translation
- Linux host support (macOS first)
- Wider Docker Engine API coverage
- Lower idle footprint

## Requirements

- macOS on Apple Silicon. Intel support is in progress.
- Sandboxes (and therefore `abctl claude`) additionally need M3 or newer on
  macOS 15+; macOS guests need an APFS data directory.
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
