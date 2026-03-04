# Boot Assets

## Overview

ArcBox boot assets are built and released from the dedicated
repository [`arcboxlabs/boot-assets`](https://github.com/arcboxlabs/boot-assets).

Each release contains per-architecture artifacts plus a unified multi-target manifest:

- `kernel` — pre-built Linux kernel (all drivers built-in, `CONFIG_MODULES=n`)
- `rootfs.erofs` — minimal read-only EROFS rootfs (busybox + mkfs.btrfs + iptables-legacy + CA certs)
- `manifest.json` — manifest with SHA256 checksums and kernel cmdline (`schema_version` = major of `asset_version`)
- Runtime binaries — dockerd, containerd, containerd-shim-runc-v2, runc (from Docker 27.5.1 static package)

No initramfs. The kernel boots directly into the EROFS rootfs (`root=/dev/vda ro rootfstype=erofs`).
Agent and runtime binaries are distributed via VirtioFS from the host.

## Responsibilities In This Repository

1. Download, verify, and cache boot assets at runtime:
   `app/arcbox-core/src/boot_assets.rs` (thin wrapper around `arcbox-boot` crate)
2. Wire boot assets into VM lifecycle:
   `app/arcbox-core/src/vm_lifecycle.rs`
3. Provide CLI operations (`prefetch` / `status` / `list` / `clear`):
   `app/arcbox-cli/src/commands/boot.rs`

## Responsibilities In boot-assets Repository

1. Build EROFS rootfs from Alpine static binaries
2. Download pre-built kernels from `arcboxlabs/kernel`
3. Sync upstream runtime binaries (Docker 27.5.1 static package)
4. Package tarball + checksum + manifest
5. Publish to GitHub Releases and Cloudflare R2 CDN

## CDN Layout

```
https://dl.arcbox.dev/boot-assets/
├── latest.json                     # {"version":"x.y.z"}
└── v0.2.3/
    ├── manifest.json               # unified manifest
    ├── arm64/kernel
    ├── arm64/rootfs.erofs
    ├── x86_64/kernel
    └── x86_64/rootfs.erofs
```

## Version Pinning

The daemon pins the boot asset version via `BOOT_ASSET_VERSION` in
`app/arcbox-core/src/boot_assets.rs`. This can be overridden at runtime
with the `ARCBOX_BOOT_ASSET_VERSION` environment variable.
