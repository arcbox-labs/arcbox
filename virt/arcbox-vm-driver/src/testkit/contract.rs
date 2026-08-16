//! The driver contract: what every adapter must do the same way.
//!
//! An adapter instantiates [`driver_contract!`](crate::driver_contract) in
//! its own (usually `#[ignore]`d, hardware-backed) test crate with a
//! [`ContractHarness`] that knows how to build a spec for that VMM and how
//! to tell when its guest is usable; the macro expands to one `#[tokio::test]`
//! per check below.
//!
//! Each check is also a plain `pub async fn` here, so an adapter can run one
//! of them by hand under a custom setup.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::capability::{
    AfterCheckpoint, CheckpointFormat, CheckpointImage, CheckpointKind, CheckpointOptions,
};
use crate::driver::{RestoreSpec, ShutdownMode, VmDriver, VmEvent, VmHandle, VmState};
use crate::error::Error;
use crate::spec::{VmId, VmSpec};

/// How long a check waits for something the guest or VMM must do.
const DEADLINE: Duration = Duration::from_secs(60);

/// What the contract needs from an adapter's test setup.
#[async_trait]
pub trait ContractHarness: Send + Sync {
    /// The driver under test.
    fn driver(&self) -> Arc<dyn VmDriver>;

    /// A bootable spec for `id` that asks for every device the driver
    /// claims a capability for (vsock, balloon, console, ...), so the
    /// capability agreement check sees each accessor at its `Some`.
    fn spec(&self, id: &VmId) -> VmSpec;

    /// A fresh, empty per-VM runtime directory; a new one on every call.
    fn runtime_dir(&self) -> PathBuf;

    /// A guest vsock port that answers a dial once the guest is ready, if
    /// the guest has one (an agent port). `None` skips the dial check.
    fn dial_port(&self) -> Option<u32>;

    /// Waits until the guest behind `handle` is usable. A no-op for the fake.
    async fn ready(&self, handle: &dyn VmHandle);
}

fn id(name: &str) -> VmId {
    VmId::new(format!("contract-{name}")).expect("contract vm id")
}

async fn boot(h: &dyn ContractHarness, name: &str) -> Box<dyn VmHandle> {
    let spec = h.spec(&id(name));
    let handle = h.driver().boot(spec, &h.runtime_dir()).await.expect("boot");
    h.ready(&*handle).await;
    handle
}

/// A booted VM reports `Running`, `shutdown(Kill)` succeeds with a status
/// that is not clean, and the handle then reports `Exited` with it.
pub async fn boot_reports_running_then_exits_on_kill(h: &dyn ContractHarness) {
    let vm = boot(h, "boot").await;
    assert_eq!(*vm.id(), id("boot"));
    assert_eq!(vm.state(), VmState::Running);
    let status = vm.shutdown(ShutdownMode::Kill).await.expect("kill");
    assert!(!status.is_clean(), "a kill reported a clean exit: {status}");
    assert_eq!(vm.state(), VmState::Exited(status));
}

/// `events()` delivers `Exited` once, with the shutdown's status, and
/// nothing after it.
pub async fn events_deliver_exit_exactly_once(h: &dyn ContractHarness) {
    let vm = boot(h, "events").await;
    let mut events = vm.events();
    let status = vm.shutdown(ShutdownMode::Kill).await.expect("kill");
    let event = tokio::time::timeout(DEADLINE, events.recv())
        .await
        .expect("an exit event before the deadline")
        .expect("the events channel is open");
    assert_eq!(event, VmEvent::Exited(status));
    tokio::time::sleep(Duration::from_millis(50)).await;
    match events.try_recv() {
        Ok(VmEvent::Exited(again)) => panic!("Exited delivered twice: {again}"),
        Ok(other) => panic!("unexpected event after exit: {other:?}"),
        Err(_) => {}
    }
}

/// Every flag in `capabilities()` agrees with the matching accessor on a
/// handle booted from a spec that asks for everything the driver claims.
pub async fn capabilities_agree_with_accessors(h: &dyn ContractHarness) {
    let driver = h.driver();
    let caps = driver.capabilities();
    let vm = boot(h, "caps").await;
    assert_eq!(caps.vsock, vm.vsock().is_some(), "vsock");
    assert_eq!(
        caps.vsock_listen,
        vm.vsock_listener().is_some(),
        "vsock_listen"
    );
    assert_eq!(caps.checkpoint, vm.checkpoint().is_some(), "checkpoint");
    assert!(
        caps.checkpoint || !caps.diff_checkpoint,
        "diff without checkpoint"
    );
    assert_eq!(caps.adopt, vm.detach().is_some(), "detach");
    assert_eq!(caps.adopt, driver.adopt().is_some(), "adopt");
    assert_eq!(caps.balloon, vm.balloon().is_some(), "balloon");
    assert_eq!(caps.console, vm.console().is_some(), "console");
    assert_eq!(caps.debug, vm.debug().is_some(), "debug");
    vm.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// A checkpoint with `Resume` leaves the VM running and yields an image
/// in `dst` in the driver's own format.
pub async fn checkpoint_resume_keeps_running(h: &dyn ContractHarness) {
    let vm = boot(h, "ckpt-resume").await;
    let Some(cp) = vm.checkpoint() else {
        assert!(!h.driver().capabilities().checkpoint);
        return;
    };
    let dst = h.runtime_dir().join("checkpoint");
    let image = cp
        .checkpoint(&dst, CheckpointOptions::default())
        .await
        .expect("checkpoint");
    assert_eq!(image.dir, dst);
    assert_eq!(image.kind, CheckpointKind::Full);
    assert!(image.dir.is_dir(), "image dir exists");
    assert_eq!(vm.state(), VmState::Running);
    vm.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// A checkpoint with `HoldQuiesced` leaves the VM `Quiesced` until it is
/// shut down.
pub async fn checkpoint_hold_quiesces(h: &dyn ContractHarness) {
    let vm = boot(h, "ckpt-hold").await;
    let Some(cp) = vm.checkpoint() else {
        assert!(!h.driver().capabilities().checkpoint);
        return;
    };
    let opts = CheckpointOptions {
        after: AfterCheckpoint::HoldQuiesced,
        kind: CheckpointKind::Full,
    };
    cp.checkpoint(&h.runtime_dir().join("checkpoint"), opts)
        .await
        .expect("checkpoint");
    assert_eq!(vm.state(), VmState::Quiesced);
    let status = vm.shutdown(ShutdownMode::Kill).await.expect("kill");
    assert_eq!(vm.state(), VmState::Exited(status));
}

/// A checkpoint restores into a new, running VM under a new id.
pub async fn restore_yields_a_live_vm(h: &dyn ContractHarness) {
    let source = boot(h, "restore-src").await;
    let Some(cp) = source.checkpoint() else {
        assert!(!h.driver().capabilities().checkpoint);
        return;
    };
    let opts = CheckpointOptions {
        after: AfterCheckpoint::HoldQuiesced,
        kind: CheckpointKind::Full,
    };
    let image = cp
        .checkpoint(&h.runtime_dir().join("checkpoint"), opts)
        .await
        .expect("checkpoint");
    source
        .shutdown(ShutdownMode::Kill)
        .await
        .expect("kill source");

    let restore = RestoreSpec {
        id: id("restore-dst"),
        nics: h.spec(&id("restore-dst")).nics,
        isolation: h.spec(&id("restore-dst")).isolation,
    };
    let restored = h
        .driver()
        .restore(&image, restore, &h.runtime_dir())
        .await
        .expect("restore");
    assert_eq!(*restored.id(), id("restore-dst"));
    assert_eq!(restored.state(), VmState::Running);
    h.ready(&*restored).await;
    restored.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// `detach` leaves the VM running for `adopt` to pick up; after that VM
/// is gone, `adopt` reports `None`.
pub async fn detach_then_adopt_round_trip(h: &dyn ContractHarness) {
    let driver = h.driver();
    let vm = boot(h, "adopt").await;
    let Some(adopt) = driver.adopt() else {
        assert!(!driver.capabilities().adopt);
        assert!(vm.detach().is_none(), "detach without adopt");
        return;
    };
    let record = vm
        .detach()
        .expect("detach accessor")
        .detach()
        .await
        .expect("detach");
    assert_eq!(record, vm.record());
    drop(vm);

    let adopted = adopt
        .adopt(&record)
        .await
        .expect("adopt")
        .expect("the detached vm survived");
    assert_eq!(*adopted.id(), record.id);
    assert_eq!(adopted.state(), VmState::Running);
    adopted.shutdown(ShutdownMode::Kill).await.expect("kill");
    assert!(
        adopt
            .adopt(&record)
            .await
            .expect("adopt after exit")
            .is_none(),
        "adopt found a vm that was killed"
    );
}

/// `Vsock::dial` to the harness's agent port succeeds on a ready guest.
pub async fn vsock_dial_reaches_the_guest(h: &dyn ContractHarness) {
    let Some(port) = h.dial_port() else {
        return;
    };
    let vm = boot(h, "dial").await;
    let Some(vsock) = vm.vsock() else {
        assert!(!h.driver().capabilities().vsock);
        return;
    };
    let conn = tokio::time::timeout(DEADLINE, vsock.dial(port))
        .await
        .expect("dial before the deadline")
        .expect("dial");
    assert!(std::os::fd::AsRawFd::as_raw_fd(&conn.fd) >= 0);
    drop(conn);
    vm.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// `restore` refuses an image in a format the driver did not write.
pub async fn foreign_checkpoint_is_refused(h: &dyn ContractHarness) {
    let format = CheckpointFormat::new("contract/never-written");
    let image = CheckpointImage {
        dir: h.runtime_dir(),
        format: format.clone(),
        kind: CheckpointKind::Full,
    };
    let restore = RestoreSpec {
        id: id("foreign"),
        nics: vec![],
        isolation: Default::default(),
    };
    match h.driver().restore(&image, restore, &h.runtime_dir()).await {
        Err(Error::ForeignCheckpoint(refused)) => assert_eq!(refused, format),
        Err(other) => panic!("expected ForeignCheckpoint, got {other}"),
        Ok(_) => panic!("a foreign checkpoint was restored"),
    }
}

/// `record()` is the same value before, during, and after the VM runs,
/// and names the driver and runtime dir it was booted with.
pub async fn record_is_stable(h: &dyn ContractHarness) {
    let driver = h.driver();
    let dir = h.runtime_dir();
    let vm = driver
        .boot(h.spec(&id("record")), &dir)
        .await
        .expect("boot");
    let first = vm.record();
    assert_eq!(first.id, id("record"));
    assert_eq!(first.driver, driver.name());
    assert_eq!(first.runtime_dir, dir);
    h.ready(&*vm).await;
    assert_eq!(vm.record(), first);
    vm.shutdown(ShutdownMode::Kill).await.expect("kill");
    assert_eq!(vm.record(), first);
}

/// Instantiates the driver contract as a test module.
///
/// `driver_contract!(fc, FcHarness::new())` expands to `mod fc` holding one
/// `#[tokio::test]` per contract check; each test evaluates the harness
/// expression afresh and runs the check against it. The invoking crate
/// needs `tokio` (with `macros` and `rt`) as a dev-dependency.
#[macro_export]
macro_rules! driver_contract {
    ($mod:ident, $harness:expr) => {
        mod $mod {
            #[allow(
                unused_imports,
                reason = "the harness expression may or may not name items of the enclosing module"
            )]
            use super::*;

            $crate::__driver_contract_checks! {
                $harness;
                boot_reports_running_then_exits_on_kill,
                events_deliver_exit_exactly_once,
                capabilities_agree_with_accessors,
                checkpoint_resume_keeps_running,
                checkpoint_hold_quiesces,
                restore_yields_a_live_vm,
                detach_then_adopt_round_trip,
                vsock_dial_reaches_the_guest,
                foreign_checkpoint_is_refused,
                record_is_stable,
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __driver_contract_checks {
    ($harness:expr; $($check:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $check() {
                let harness = $harness;
                $crate::testkit::contract::$check(&harness).await;
            }
        )*
    };
}
