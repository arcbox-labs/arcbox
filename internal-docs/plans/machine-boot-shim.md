# Machine Boot Shim

Boot a user machine from a pulled distro rootfs (squashfs, mirrored from
images.linuxcontainers.org via `image.arcboxcdn.com/linux`) into the distro's
own init, with the ArcBox agent reachable over vsock — the OrbStack-style
"real Linux machine" experience on ArcBox's own kernel.

Stacked on `feat/machine-image-pull` (arcbox#431: image pull + block-device
attach) and `arcboxlabs/kernel#10` (`CONFIG_SQUASHFS` + xz/zstd).

## Constraints that shape the design

1. **The distro image is immutable and byte-identical to upstream.** No agent
   or init can be baked into it; everything ArcBox needs must arrive via block
   devices, VirtioFS, or the kernel command line.
2. **No initramfs.** The ArcBox kernel boots `root=` directly and execs the
   root filesystem's init; our first code must therefore live on a block
   device the kernel can mount as root.
3. **`switch_root` must run as PID 1.** The System VM's busybox-inittab path
   (rcS runs as a *child* of busybox init) cannot hand PID 1 to the distro's
   init. The machine path instead boots with `init=/sbin/arcbox-machine-init`,
   so the shim script itself is PID 1 and can `exec switch_root`.
4. **The readiness gate needs both vsock and an IP.**
   `MachineManager::wait_for_machine_ready` polls agent ping + a routable IP,
   so the shim must guarantee the agent runs and DHCP happens even on distros
   whose image doesn't auto-configure networking (the mirror drops the incus
   metadata tarball that normally does this).

## Device and cmdline contract

| Device | Content | Mode |
| --- | --- | --- |
| vda | boot-assets EROFS (the shim: busybox, mkfs.btrfs, machine-init) | ro |
| vdb | distro rootfs (`rootfs.squashfs` from the image registry) | ro |
| vdc | per-machine sparse `data.img` (btrfs, first-boot formatted) | rw |

Kernel: the boot-assets kernel (same as the System VM). Command line:

```
console=hvc0 root=/dev/vda ro rootfstype=erofs earlycon \
  init=/sbin/arcbox-machine-init \
  arcbox.machine_rootfs=/dev/vdb arcbox.machine_rootfs_type=squashfs \
  arcbox.machine_data=/dev/vdc
```

The `arcbox.machine_*` keys live in `arcbox-constants` (host side) and are
parsed by the shim script from `/proc/cmdline`, so boot-assets and arcbox
cannot drift silently. `rootfs_type` is carried from the image manifest —
a future EROFS/zstd recompression on the mirror changes only the manifest.

A machine created *without* a distro keeps the plain path from #431 (caller
kernel + devices verbatim) for custom-kernel testing.

## Shim flow (`/sbin/arcbox-machine-init`, PID 1, busybox sh)

1. Mount `/proc`, `/sys`, `/dev` (devtmpfs); honor `arcbox.debug_console`
   exactly like rcS.
2. Mount VirtioFS `arcbox` share at `/arcbox` (agent binary, logs).
3. `mount -t $rootfs_type -o ro $machine_rootfs /lower`.
4. Data disk: if `$machine_data` has no btrfs superblock, `mkfs.btrfs` it
   (same first-boot pattern as the System VM data disk). Mount at `/data`,
   create `upper/`, `work/`.
5. `mount -t overlay overlay -o lowerdir=/lower,upperdir=/data/upper,workdir=/data/work /newroot` —
   the machine's writable root; all distro writes land on the btrfs disk,
   the squashfs stays pristine (and shared across machines of the same
   image version).
6. Stage host bits into the new root: `mkdir -p /newroot/arcbox` and move-mount
   `/arcbox` there; copy the shim's static busybox to `/newroot/bin/busybox`
   only if absent (the agent's DHCP path shells out to `/bin/busybox udhcpc`;
   Alpine already ships one, systemd distros don't).
7. One-shot machine init inside the new root:
   `chroot /newroot /arcbox/bin/arcbox-agent machine-init` — brings up eth0
   via DHCP and writes `/etc/resolv.conf` when the distro left none. Unlike
   the System VM's `agent init`, this must NOT tmpfs-over `/etc`/`/var`
   (the overlay already provides writable state and the distro owns those
   trees).
8. Spawn the long-running agent, detached, inside the new root:
   `chroot /newroot /arcbox/bin/arcbox-agent serve &` — it survives
   `switch_root` (reparented to the distro init) and serves ping /
   system-info / future exec over vsock.
9. Move `/proc`, `/sys`, `/dev` into `/newroot`, then
   `exec switch_root /newroot /sbin/init` — the distro's systemd (or
   OpenRC on Alpine) becomes PID 1.

Failure policy mirrors rcS: any load-bearing step failing prints a console
marker and powers off (`poweroff -f`), so the host sees a clean boot failure
instead of a half-configured guest.

## Change inventory

- **arcboxlabs/kernel#10** — squashfs (xz today, zstd headroom). Merged
  first; boot-assets picks it up on its next release bump.
- **boot-assets** — `scripts/machine-init.sh` packaged at
  `/sbin/arcbox-machine-init` in the EROFS. Pure addition: the System VM
  path (inittab → rcS → agent) is untouched.
- **arcbox (this branch)** —
  - `arcbox-constants`: `arcbox.machine_*` cmdline keys + shim init path.
  - `machine.rs`: `MachineRootfs.shim` (kernel + EROFS from boot assets);
    shim-aware device/cmdline assembly in `create`.
  - `grpc/machine.rs`: resolve `BootAssetProvider` (same `data_dir/boot`
    cache the daemon already populates) and fill the shim for distro
    machines.
  - `guest/arcbox-agent`: `machine-init` mode — networking + resolv.conf
    only; no System-VM mount setup.

## Agent supervision (phase 2)

The spawned agent has no supervisor after `switch_root`. Once the base flow
is proven, the shim can drop a generated systemd unit (or OpenRC script)
into the overlay upper (`/etc/systemd/system/arcbox-agent.service` +
`multi-user.target.wants` symlink) so the distro's init owns restarts. Not
load-bearing for v1: the agent is stable, and a crashed agent only degrades
host-side visibility, not the machine itself.

## Testing

1. Unit: shim device order / cmdline assembly in `machine::tests`.
2. boot-assets QEMU e2e gains a machine-mode boot: shim EROFS + a tiny
   squashfs fixture + blank data disk, asserting the guest reaches the
   fixture's `/sbin/init` (observable via console marker) — same harness as
   `qemu_boots_x86_64_linux`.
3. arcbox e2e (ignored, macOS): `machine create --distro alpine` +
   `machine start` reaching Running with an IP, once the kernel release with
   squashfs lands in boot-assets.

## Open questions

- Multi-machine CID collisions (`machine.rs:517`, `3 + running_count`) —
  pre-existing bug that bites as soon as two machines run; fix alongside
  phase 2.
- Per-machine VirtioFS: today every machine shares the System VM's `arcbox`
  tag (fine: agent + logs) plus `/Users` — revisit mount scoping when
  machine-specific mounts (`--mount host:guest`) are implemented.
- systemd's `/` remount: systemd may remount root rw — harmless on overlay,
  verify on first ubuntu boot.
