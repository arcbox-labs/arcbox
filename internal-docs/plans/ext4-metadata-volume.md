# ext4 Metadata Volume — snapshot-prepare fsync fix (ABX-496)

Status: **Planned** (design locked, awaiting implementation)
Owner: ABX-496 (docker build performance vs Colima)
Companion fix already shipped separately: `rcu_expedited` for runc-create (arcbox#496).

## 1. Problem and evidence

Container start on ArcBox spends ~182 ms in containerd snapshot-prepare vs ~20 ms
on Colima. Profiling (static strace with `-y` fd resolution, dockerd debug
lifecycle timeline, `dd conv=fsync` microbench) pinned the cost:

- A single `fsync` on the guest data volume costs **9.5 ms on ArcBox (btrfs)**
  vs **1.0 ms on Colima (ext4)** on the same virtio-blk stack. The cost is the
  btrfs commit path (`write_all_supers`: superblock write + FLUSH barriers),
  not COW extent allocation — `chattr +C` (NOCOW) was measured at 9.5 ms vs
  10.5 ms, i.e. no help.
- ~90 % of the fsyncs during a container start hit small boltdb metadata
  files: containerd `io.containerd.metadata.v1.bolt/meta.db` (dominant),
  overlayfs snapshotter `metadata.db`, dockerd `network/files/local-kv.db`
  and `image/*.db`. Content-store blobs and snapshot dirs are a small
  minority of fsyncs.

The fsync-hot files are small, incompressible, and rewritten in place; the
bulk data (extracted layers, blobs, volumes) is large and benefits from btrfs
zstd compression. They have opposite filesystem needs — so we split them.

## 2. Locked design

Add a second, small disk image formatted **ext4 (journaled, fast_commit)**
that carries only the fsync-hot metadata directories, bind-mounted over their
current btrfs locations. Everything else stays on btrfs unchanged.

| Decision | Choice | Rationale / rejected alternatives |
|---|---|---|
| Storage for ext4 | Second virtio-blk disk image | Loop file on btrfs rejected: loop FLUSH re-enters the btrfs commit path, keeping the 9.5 ms cost. GPT-partitioning docker.img rejected: destructive migration of existing whole-disk btrfs images. |
| Image name | `<data-stem>-meta.img` derived from the data image (`docker.img` → `docker-meta.img`, `docker-rosetta.img` → `docker-rosetta-meta.img`) | Follows the existing per-VM data-image parameterization (`vm_lifecycle/mod.rs::for_machine`). |
| Virtual size | 2 GiB, sparse (`ensure_sparse_block_image`), no resize path | Holds only bolt DBs + small configs; 2 GiB is ~100× headroom. No resize2fs in guest; fixed size avoids that dependency. |
| Guest device | `/dev/vdc` (third `BlockDeviceConfig` in the Vec; both backends attach in Vec order) + cmdline override key `arcbox.docker_metadata_device=` mirroring the existing data-device pattern | HV additionally exposes serial `arcbox-blk-docker-meta.img` via GET_ID, but ordering is already the load-bearing contract for vdb. No HVC fast-path analogue — metadata I/O is tiny. |
| Formatter | `mkfs.ext4` (static e2fsprogs) added to the guest rootfs via boot-assets, invoked guest-side like `mkfs.btrfs` | `arcbox-ext4` crate rejected: its formatter sets no `HAS_JOURNAL` (registry source, `formatter.rs:1107-1111`), and journal-less ext4 has no crash replay — VM force-stop is a routine event and these DBs are the system of record. Host-side formatting impossible (no mke2fs on macOS). |
| mkfs options | `mkfs.ext4 -F -O fast_commit -E lazy_itable_init=0,lazy_journal_init=0 -L arcbox-meta` | fast_commit reduces exactly our fsync pattern (small metadata commits); kernel is 6.x with `CONFIG_EXT4_FS=y` on both arches. Lazy init off: one-time cost at first format, no background trickle. |
| Mount options | `noatime` (defaults otherwise: `data=ordered`, barriers on) | `discard` skipped — bolt files are stable in size, few deletes. |
| Recovery | Ship static `e2fsck` alongside; on mount failure run `e2fsck -y` once, retry mount once, then fail hard | Journal replay is in-kernel; e2fsck covers the residual corruption class. |

### Directories moved to ext4 (the profiled hot set, nothing more)

| ext4 volume path | Bind target | Kind |
|---|---|---|
| `containerd-bolt/` | `/var/lib/containerd/io.containerd.metadata.v1.bolt` | dir bind |
| `snapshotter-metadata.db` | `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/metadata.db` | **file** bind (the dir also holds `snapshots/`, which stays on btrfs) |
| `docker-network/` | `/var/lib/docker/network` | dir bind |
| `docker-image/` | `/var/lib/docker/image` | dir bind |
| `docker-buildkit/` | `/var/lib/docker/buildkit` | dir bind |

The file bind is safe for boltdb: bolt opens, mmaps, writes in place and
fsyncs — it never renames or recreates its DB file. Both sides of the bind
are pre-created (empty files) before containerd starts; bolt initializes a
0-byte file as a fresh DB.

EXDEV audit: none of the five targets receives cross-boundary renames. Bolt
never renames; libnetwork and docker's image store use same-directory
tmp+rename atomic writes; buildkit DBs are bolt. Content-store ingest→blobs
and snapshotter tmp→snapshots renames stay entirely within btrfs subtrees.
Any regression here fails loudly (EXDEV errors the operation) and is covered
by the validation suite.

### Explicitly excluded (with reasons)

- `/var/lib/docker/containers` — config fsyncs are a minor cost; the dir also
  holds json-file logs, which are unbounded and would risk filling the 2 GiB
  volume.
- `/var/lib/docker/volumes/metadata.db`, `builder/`, `trust/` — cold paths,
  not in the profile.
- Distro machines (`data.img`, machine-init.sh) — out of scope; System VM
  and Rosetta VM only (both go through `create_default_machine`).

### NOCOW removal rides along

`btrfs.rs::disable_cow_on_metadata_dirs` is removed in the same change. Its
premise (NOCOW reduces bolt fsync amplification) is disproven by measurement
(9.5 vs 10.5 ms), the dirs it targeted either move to ext4 or are cold, and
its inherited NOCOW flag on `io.containerd.snapshotter.v1.overlayfs` silently
disables zstd compression for every extracted layer file — the one thing
btrfs is being kept for. Existing installs keep the on-disk flag on old dirs
(only re-flagging stops); new snapshot dirs regain compression.

## 3. Guest changes (`guest/arcbox-agent`)

New module `agent/linux/metadata_volume.rs`, called from
`try_start_bundled_runtime` (`runtime.rs`) immediately after
`ensure_data_mount()` — i.e. after btrfs targets exist, before the NFS export
and before containerd/dockerd start (bolt files guaranteed closed):

1. Resolve device: cmdline override → `/dev/vdc`; wait up to 5 s for the node
   (same loop as `btrfs.rs`).
2. Probe ext4 superblock magic (0xEF53 at offset 0x438). If absent →
   `mkfs.ext4` with the locked options.
3. Mount at `/run/arcbox/metadata` (`noatime`). On failure: `e2fsck -y`,
   retry once, else hard-fail.
4. Per-mapping migrate-then-bind, idempotent and crash-safe per entry:
   1. If the ext4-side final entry is absent: if the btrfs-side source
      exists at its canonical path, copy it (recursive, pure Rust) to
      `<entry>.partial` on the volume, fsync, then rename to final —
      an interrupted copy leaves only a `.partial` that is discarded and
      redone next boot, never a half-populated final that would get bound.
      If no source exists, create the entry empty (fresh install).
   2. If the ext4-side final exists AND the btrfs-side source is still at
      its canonical path, rename the source to `<name>.pre-ext4` (covers a
      crash between step 1 and this rename). The rename — rather than
      leaving the source in place — is load-bearing: it is what prevents a
      later blank metadata volume (user deleted the image; host recreated
      it) from silently re-migrating stale pre-upgrade metadata against a
      data store that has moved on. The renamed copy doubles as a manual
      recovery artifact.
   3. Ensure an empty mountpoint stub exists at the canonical path
      (dir, or 0-byte file for the metadata.db mapping), then bind.

Failure policy (version-skew safe):

| Condition | Behavior |
|---|---|
| Device node absent (older daemon without the third disk) | warn + continue on btrfs — perf-only degradation |
| mkfs binary absent AND device blank (older rootfs) | warn + continue — nothing was ever migrated, no split-brain possible |
| Device present with ext4 but mount/fsck fails | **hard fail** runtime start — booting dockerd against the stale shadowed btrfs DBs would fork state |

Constants: `DOCKER_METADATA_BLOCK_DEVICE = "/dev/vdc"`
(`arcbox-constants/src/devices.rs`) and the cmdline key
(`arcbox-constants/src/cmdline.rs`), mirroring the data-device pair.

The Kubernetes path (`kubernetes.rs`) is untouched — k3s state lives under
`/var/lib/rancher` and none of the five targets.

### User migration matrix

| Scenario | Outcome |
|---|---|
| Fresh install | Format + empty entries; no migration. |
| Upgrade with populated docker.img | Atomic per-mapping migration (above); docker state fully preserved; sources renamed to `*.pre-ext4` on btrfs. |
| metadata.img deleted or corrupted by the user after migration | Host recreates a blank image; guest formats; sources are renamed away, so the result is a clean **empty** docker state (images re-pull; orphaned blobs/snapshots leak on btrfs but state is consistent) — never a resurrection of stale pre-upgrade metadata. |
| Downgrade to a pre-feature release | **Unsupported (one-way door).** Old binaries mount btrfs only and see the empty mountpoint stubs → empty docker state, consistent. Manual recovery: rename the `*.pre-ext4` dirs back, restoring the state as of the moment of upgrade. Document this in the release notes. |
| Backups / moving data dirs by hand | `docker.img` and `docker-meta.img` are a paired set; copying one without the other loses metadata or orphans data. Documented in `docs/data-directories.md`; `resource_cleanup` already treats them as a unit. |

## 4. Host changes (`app/`)

- `vm_lifecycle/mod.rs`: `DOCKER_METADATA_IMAGE_SIZE_BYTES` (2 GiB);
  metadata filename derived next to `data_image_filename`.
- `vm_lifecycle/boot.rs::create_default_machine`:
  `ensure_sparse_block_image` + third `block_devices.push` (rw); update the
  vda/vdb doc comment to cover vdc.
- `arcbox-daemon/src/startup/resource_cleanup.rs::DISK_IMAGE_NAMES`: add
  `docker-meta.img`, `docker-rosetta-meta.img` (the pair is a unit — deleting
  one without the other orphans state).
- `arcbox-core/src/config.rs`: `docker_meta_img_path()` accessor;
  `arcbox-cli/commands/disk.rs`: include it in usage reporting.
- `docs/data-directories.md`: add the `data/docker-meta.img` row.

No dockerd/containerd config changes — the split is invisible to both.

## 5. boot-assets changes (sibling repo)

- `src/build/scripts/build-rootfs-binaries.sh`: static e2fsprogs build from
  the upstream source tarball with `LDFLAGS=-static`, mirroring the
  btrfs-progs recipe (e2fsprogs vendors its own libuuid/libblkid); stage
  `mke2fs` (installed as `/sbin/mkfs.ext4`) and `/sbin/e2fsck`.
- `src/build/rootfs.rs`: extend `CORE_STATIC_BINARIES` + `copy_executable`
  lines; the static-check loop picks them up.
- Tag `v0.6.11` → release publishes → arcbox bumps `assets.lock`
  (`[boot] version` + `manifest_sha256`) in the same PR that ships the
  daemon/agent changes (the lock is compile-time embedded; daemon rebuild
  required).

## 6. NFS / `~/ArcBox` interplay

None required. The docker export is a **non-recursive** read-only bind
(`nfs.rs::bind_readonly`, plain `MS_BIND`), so the new submounts do not
surface over NFS; `~/ArcBox/network|image|buildkit` show the (empty,
shadowed) underlying @docker dirs. These are internal dirs with no browsing
use case. No new exports, no fsid allocation.

## 7. Validation and acceptance

1. Unit: migrate-then-bind decision logic and superblock probe
   (pure functions, `cargo test -p arcbox-agent` host-side where possible;
   musl cross-compile for the rest). Must cover every crash window of the
   migration algorithm: interruption during copy (`.partial` present),
   between ext4 rename and btrfs source rename, and re-entry after each —
   each replay must converge on the same final state.
2. e2e: `docker_build` suite D1–D10 green (VZ), `boot_assets` green on VZ
   **and** HV (`ARCBOX_VM_BACKEND=hv`) — covers full Docker lifecycle over
   the new mounts; any EXDEV or bind mistake fails these loudly.
3. Migration: boot a data dir populated by current master (images +
   containers present) with the new build; `docker images` / `docker ps -a`
   intact; bolt DBs physically on the ext4 volume (`findmnt`, file sizes).
4. Version-skew: new agent + two-disk-less daemon boots with the warn path;
   fresh install formats and mounts cleanly.
5. Perf acceptance (the point of it all), measured via dockerd debug
   lifecycle timeline as in the ABX-496 campaign:
   - guest `dd conv=fsync` on the metadata mount ≈ 1 ms (vs 9.5 ms);
   - snapshot-prepare 182 ms → **< 60 ms**;
   - combined with the shipped rcu_expedited fix, `docker run` container
     start approaches Colima parity; re-run the bench table in
     `internal-docs/plans/docker-build-e2e-matrix.md` and record the delta
     on ABX-496.

## 8. Rollout sequence

1. **PR 1 (boot-assets)**: e2fsprogs in rootfs; tag `v0.6.11`. Inert for
   existing arcbox releases.
2. **PR 2 (arcbox)**: constants + host attach/cleanup/CLI + guest
   `metadata_volume.rs` + NOCOW removal + `assets.lock` bump + doc updates,
   as separate atomic commits.
3. Bench + record results on ABX-496; close the snapshot-prepare half of the
   issue.
