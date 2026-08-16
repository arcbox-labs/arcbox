# Boot Assets

## Overview

ArcBox boot assets are built and released from the dedicated
repository [`arcboxlabs/boot-assets`](https://github.com/arcboxlabs/boot-assets).

Each release contains per-architecture artifacts plus a unified multi-target manifest:

- `kernel` — pre-built Linux kernel (all drivers built-in, `CONFIG_MODULES=n`)
- `rootfs.erofs` — minimal read-only EROFS rootfs (busybox + mkfs.btrfs + iptables-legacy + ebtables + ethtool + socat + CA certs)
- `manifest.json` — manifest with SHA256 checksums and kernel cmdline (`schema_version` = major of `asset_version`)
- Runtime binaries — dockerd, containerd-shim-runc-v2, runc, docker-init (from the Docker 29.7.2 static package, shipping runc 1.4.3) plus k3s, firecracker/jailer, and the microVM vmlinux
- `containerd` — the one runtime binary **not** taken from Docker's package. boot-assets builds it from the same upstream tag Docker bundles (v2.3.3) plus [containerd#13805](https://github.com/containerd/containerd/pull/13805), which stops the overlay snapshotter appending `index=off` over a configured `index=on` — without it the `index=on,nfs_export=on` mount options the `~/ArcBox` live-container view needs are silently overridden and every overlay mount fails with `EINVAL`. It is versioned `29.7.2-arcbox.<patch>-<release>` and reports `v2.3.3-arcbox.<patch>-<release>` for itself, so a guest log names both the patch set and the build. It goes back to the stock package once the fix reaches a containerd release Docker ships

No initramfs. The kernel boots directly into the EROFS rootfs (`root=/dev/vda ro rootfstype=erofs`).
Agent and runtime binaries reach the guest through VirtioFS. Runtime binaries
are checksum-verified against the pinned manifest, copied into a
version-keyed generation on the guest Btrfs data disk, and executed only from
that local generation.

`abctl boot status` requires the effective kernel, rootfs, and every manifest
runtime binary selected for the current architecture. A configured
`vm.kernel_path` replaces the managed release kernel; the custom path must be a
non-empty regular file, while only the managed kernel is checked against the
release checksum. Runtime binaries are checked at their manifest-defined paths
for checksum, regular-file type, and executable permissions.

Manifests published before this guest-cache design may still contain a legacy
`runtime` entry. Current `arcbox-boot` consumers preserve that metadata for
compatibility but do not use or cache `runtime.erofs`; `abctl boot status`
lists it as a non-required legacy artifact.

## Responsibilities In This Repository

1. Download, verify, and cache boot assets at runtime:
   `engine/arcbox-image/src/boot_assets/` (thin wrapper around `arcbox-boot` crate)
2. Wire boot assets into VM lifecycle:
   `engine/arcbox-engine/src/vm_lifecycle/`
3. Provide CLI operations (`prefetch` / `status` / `list` / `clear`):
   `app/arcbox-cli/src/commands/boot/`

## Responsibilities In boot-assets Repository

1. Build EROFS rootfs from Alpine static binaries
2. Download pre-built kernels from `arcboxlabs/kernel`
3. Sync upstream runtime binaries (Docker 29.7.2 static package)
4. Package tarball + checksum + manifest
5. Publish to GitHub Releases and the Backblaze B2-backed CDN

## CDN Layout

```
https://boot.arcboxcdn.com/
├── latest.json                     # {"version":"x.y.z"}
├── asset/
│   └── v0.2.3/
│       ├── manifest.json           # unified manifest
│       ├── arm64/kernel
│       ├── arm64/rootfs.erofs
│       ├── x86_64/kernel
│       └── x86_64/rootfs.erofs
└── bin/
    └── {name}/{version}/{arch}/{name}
```

## Version Pinning

The daemon pins the boot asset version in the root `assets.lock`, loaded by
`engine/arcbox-image/src/boot_assets/lockfile.rs`. This can be overridden at
runtime with the `ARCBOX_BOOT_ASSET_VERSION` environment variable.

`abctl boot list` sorts cached versions by SemVer precedence, including
prereleases; invalid version directory names appear afterward in lexical order.
