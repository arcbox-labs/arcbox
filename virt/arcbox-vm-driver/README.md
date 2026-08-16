# arcbox-vm-driver

The VM driver port: the vocabulary of "a VM on this host" — the
serializable `VmSpec`, the `VmDriver`/`VmHandle` traits, the capability
traits, and the `GuestNetwork` port — that VMM adapters (Firecracker,
Virtualization.framework, the in-process HV engine, Cloud Hypervisor)
implement and orchestrators consume. No `arcbox-*` dependency: it sits
below every adapter, and only a composition root names both sides.

## The mandatory surface

`VmDriver` boots a `VmSpec` into a `Box<dyn VmHandle>` (or restores one
from a `CheckpointImage`). A handle's mandatory verbs are:

| Verb | What it is |
|------|------------|
| `id()` / `record()` | identify — the `VmRecord` is durable and stable for the handle's life |
| `state()` / `events()` | observe — `Running` / `Quiesced` / `Exited(status)`; `Exited` is broadcast once; neither blocks |
| `shutdown(mode)` | stop — `Kill` always succeeds; `Graceful { timeout }` asks the guest and kills at the deadline |

Dropping a handle kills the VM unless a `Detach` released it.

## Capabilities

Everything else is optional and reached through an `Option<&dyn Cap>`
accessor; `None` means "this driver cannot" or "this VM was not built with
the device", never an error at call time. `DriverCapabilities` says which
accessors a driver's handles can return `Some` for, and the contract checks
that the flags and the accessors agree.

| Capability | Accessor | Does |
|------------|----------|------|
| `Vsock` | `handle.vsock()` | dial a guest vsock port → `VsockConn { fd, mode }` |
| `VsockListen` | `handle.vsock_listener()` | accept guest-initiated vsock connections |
| `Checkpoint` | `handle.checkpoint()` | capture to disk; `Resume` or `HoldQuiesced` afterwards |
| `Adopt` / `Detach` | `driver.adopt()` / `handle.detach()` | VMs that outlive the process (external VMMs) |
| `Prepare` | `driver.prepare()` | spawn the VMM ahead of a boot: pid journaled and READY listener bound before the guest starts; `boot` is exactly prepare-then-boot |
| `Balloon` | `handle.balloon()` | set/read the memory balloon |
| `Console` | `handle.console()` | read guest console output |
| `DebugSnapshot` | `handle.debug()` | driver-specific JSON for post-mortems |

`net::GuestNetwork` is the second port: reserve a lease, activate it into
a `NicSpec`, quarantine/release, and the `NetworkReconcile` cleanup-token
protocol.

## Usage

```rust
let driver: Arc<dyn VmDriver> = root.pick_driver();          // composition root
let vm = driver.boot(spec, &runtime_dir).await?;              // Box<dyn VmHandle>
let mut events = vm.events();
if let Some(vsock) = vm.vsock() {
    let conn = vsock.dial(AGENT_PORT).await?;                 // conn.mode picks the transport
}
if let Some(cp) = vm.checkpoint() {
    let image = cp.checkpoint(&dir, CheckpointOptions::default()).await?;
}
vm.shutdown(ShutdownMode::Graceful { timeout: Duration::from_secs(5) }).await?;
```

## Running the contract against an adapter

Enable the `testkit` feature in the adapter's dev-dependencies, implement
`ContractHarness` (driver, a spec asking for every device the driver
claims, fresh runtime dirs, the agent port to dial, and how to wait for
guest readiness), and instantiate the macro in a test target:

```rust
use arcbox_vm_driver::driver_contract;
driver_contract!(fc, FcHarness::new());   // → mod fc { #[tokio::test] async fn ... }
```

`FakeHarness` is the reference implementation, and `tests/fake_contract.rs`
runs the same checks against `FakeDriver`, both fully claimed and with no
capabilities claimed. `FakeDriver` and `FakeNetwork` are what runtime unit
tests build their real actors and state machines on — no hypervisor needed.

Design: company repo `engineering/arcbox/architecture/vm-stack-redesign.md`
(D-VM1, D-VM7, D-VM9).
