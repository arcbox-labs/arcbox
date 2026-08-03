# ABX-375 FEX validation harness

Reproducible validation for running `linux/amd64` containers through **FEX**
inside the single HV utility VM (ABX-375), instead of routing them to a
VZ/Rosetta runtime VM (ABX-374).

This harness is **executed by a developer on Apple Silicon macOS** — it cannot
run in CI that lacks Virtualization/Hypervisor entitlements, and it cannot run
where the daemon cannot boot a VM.

## Prerequisites

1. Apple Silicon Mac, macOS 15.0+ (Sequoia). Record the exact version — the
   hardware-TSO path (`HV_SYS_REG_ACTLR_EL1`) had a regression on 15.1.1; see
   "Performance / TSO" below.
2. A Developer-ID-signed `arcbox-daemon` running (ad-hoc signing is killed by
   the restricted entitlements — see root `CLAUDE.md`).
3. The FEX interpreter provisioned in the guest runtime assets and registered
   via `binfmt_misc` (see "What must be in the guest" below).
4. The `arcbox` Docker context active, or pass `--context arcbox` (the script
   does this automatically). The context endpoint is
   `unix:///<home>/.arcbox/run/docker.sock`.

## Run

```bash
./tests/fex/validate-fex.sh
```

Result tags:

- `PASS` — required behavior held.
- `FAIL` — a real FEX/routing failure. **Per PLAN.md, a Gate A `FAIL` means
  stop ABX-375 and resume ABX-374.**
- `UNSUPPORTED` — a known FEX compatibility gap. Record it in
  `PLAN.md` "known incompatibilities" before merging; it is not a harness bug.
- `INFRA` — the harness could not run the check (daemon down, image pull
  failed). Not a verdict on FEX.

Exit status: `0` no FAIL, `1` any FAIL, `2` only INFRA (nothing validated).

## Decision gates (from PLAN.md)

- **Gate A — basic viability:** `docker run --platform linux/amd64 alpine
  uname -m` returns `x86_64` from the HV VM, and no VZ runtime VM is started.
- **Gate B — runtime default viability:** representative amd64 images
  (alpine/musl, debian/glibc, busybox, node, python, go, an `apt` workload)
  run; networking, bind mounts, DNS, ports, stdout/stderr, exit status, and
  signals behave.
- **Gate C — build/compose viability:** `docker build --platform linux/amd64`
  works through HV/FEX with no `/session` cross-VM routing, and a mixed
  arm64/amd64 Compose project stays inside the single HV VM.

## What must be in the guest

ABX-375 provisions FEX like the other guest runtime binaries (dockerd,
containerd, runc): a single aarch64 static-PIE `FEX` binary ships in the
boot-asset runtime bin set. `/arcbox/runtime` is a read-only VirtioFS source;
the guest agent verifies the current architecture's manifest checksums, copies
the generation onto the Btrfs data disk, and publishes
`/run/arcbox/runtime/bin/FEX` (sibling `boot-assets` repo + `assets.lock`; this
is a coordinated two-repo change, not a local edit).
ArcBox's FEX carries a small patch making it **binfmt-only**: it drops the
FEXServer requirement, so nothing else needs to be running in the guest — no
daemon to reach across container mount namespaces. Before Docker, Kubernetes,
or Sandbox startup, the guest agent materializes the runtime and registers the
local FEX path as the x86_64 ELF handler in `binfmt_misc` with `POCF` flags.
The `F` (fix-binary) flag loads the Btrfs-backed interpreter at registration
time so containers inherit it across mount namespaces. A repaired generation
is unregistered and registered again so the pinned interpreter inode cannot
refer to superseded content.

Manual guest-side confirmation (until `abctl exec` diag is wired):

```bash
# inside the HV guest:
cat /proc/sys/fs/binfmt_misc/FEX-x86_64     # handler present + enabled
/run/arcbox/runtime/bin/FEX --version       # FEX version
# direct x86_64 exec (no Docker):
./some-x86_64-binary                         # runs via FEX
```

## Performance / TSO (Gate "good enough")

FEX's dominant cost is emulating x86's strong memory ordering. Apple Silicon's
hardware TSO mode removes it. Inside a Hypervisor.framework guest, the VMM
enables it per-vCPU via `hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ACTLR_EL1, 2)`
(macOS 15.0+). This is **gated behind a config flag and OFF by default** until
empirically confirmed on the target macOS versions, because whole-VM TSO costs
~10% on native arm64 code.

Go/no-go TSO probe (records A vs B scenario):

1. Enable the VMM EnTSO flag; boot the guest.
2. Confirm the VMM-side `hv_vcpu_set_sys_reg(...ACTLR_EL1...)` returned
   `HV_SUCCESS` (logged). Do **not** rely on an in-guest `mrs ACTLR_EL1` read —
   the guest sysreg path is RAZ/WI unless a proxy handler is added.
3. Confirm FEX took the hardware-TSO path (FEX logs `TSO: hardware`).

If `HV_SYS_REG_ACTLR_EL1` returns `HV_BAD_ARGUMENT` on the target macOS,
FEX runs software-TSO (still well ahead of QEMU, behind Rosetta). Record
startup latency, steady-state runtime, build time, CPU, and memory for
FEX/HV vs Rosetta/VZ vs QEMU, plus single-HV vs dual-HV+VZ idle memory.

## Honest scope of this harness

This directory provides the **reproducible procedure and pass/fail contract**.
The live gate execution requires Apple Silicon hardware and a signed, bootable
daemon. The ArcBox-side routing change (amd64 → HV/FEX, fail-closed) is
implemented and unit/compile-tested in this repo; the FEX binary provisioning
and manifest live in the sibling `boot-assets` repo. Runtime materialization
and Btrfs-backed binfmt registration live in this repo's guest agent. The FEX
binary provisioning (boot-assets) and the live A/B/C runs are the remaining
hardware/sibling-repo steps.
