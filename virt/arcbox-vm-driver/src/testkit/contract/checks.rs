//! The contract checks, one `pub async fn` each; [`driver_contract!`]
//! wraps every one of them in a `#[tokio::test]`.
//!
//! [`driver_contract!`]: crate::driver_contract

use std::time::Duration;

use super::ContractHarness;
use crate::capability::{
    AfterCheckpoint, CheckpointFormat, CheckpointImage, CheckpointKind, CheckpointOptions,
    DiskSource,
};
use crate::driver::{RestoreSpec, ShutdownMode, VmEvent, VmHandle, VmRecord, VmState};
use crate::error::Error;
use crate::spec::{BootSpec, VmId};

/// How long a check waits for something the guest or VMM must do.
const DEADLINE: Duration = Duration::from_secs(60);

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
    assert_eq!(caps.prepare, driver.prepare().is_some(), "prepare");
    // Staging is reached through a prepared VM, so its accessor is checked
    // in `a_staged_spec_boots`; claiming it without `Prepare` leaves no way
    // to reach it at all.
    assert!(caps.prepare || !caps.staging, "staging without prepare");
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

    let template = h.spec(&id("restore-dst"));
    let restore = RestoreSpec {
        id: id("restore-dst"),
        nics: template.nics,
        disks: template.disks,
        isolation: template.isolation,
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
        disks: vec![],
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

/// `prepare` then `PreparedVm::boot` yields the same kind of handle as a
/// plain `boot`: same state, same record shape, same capabilities.
pub async fn prepare_then_boot_matches_boot(h: &dyn ContractHarness) {
    let driver = h.driver();
    let plain = boot(h, "prep-plain").await;
    let Some(prepare) = driver.prepare() else {
        assert!(!driver.capabilities().prepare);
        plain.shutdown(ShutdownMode::Kill).await.expect("kill");
        return;
    };
    let spec = h.spec(&id("prep-two-phase"));
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, &h.runtime_dir())
        .await
        .expect("prepare");
    assert!(prepared.alive());
    assert_eq!(*prepared.id(), spec.id);
    let record = prepared.record();
    assert_eq!(record.id, spec.id);
    let two_phase = prepared.boot(spec).await.expect("boot on the prepared vm");
    h.ready(&*two_phase).await;
    assert_eq!(two_phase.record(), record, "the handle shares the process");
    assert!(prepared.alive());
    assert_eq!(two_phase.state(), plain.state());
    assert_same_shape(&plain.record(), &two_phase.record());
    assert_same_capabilities(&*plain, &*two_phase);
    two_phase.shutdown(ShutdownMode::Kill).await.expect("kill");
    assert!(!prepared.alive(), "alive after the vm exited");
    plain.shutdown(ShutdownMode::Kill).await.expect("kill");
}

fn assert_same_shape(a: &VmRecord, b: &VmRecord) {
    assert_eq!(a.driver, b.driver);
    assert_eq!(a.process.is_some(), b.process.is_some(), "process record");
}

fn assert_same_capabilities(a: &dyn VmHandle, b: &dyn VmHandle) {
    assert_eq!(a.vsock().is_some(), b.vsock().is_some(), "vsock");
    assert_eq!(
        a.vsock_listener().is_some(),
        b.vsock_listener().is_some(),
        "vsock_listen"
    );
    assert_eq!(
        a.checkpoint().is_some(),
        b.checkpoint().is_some(),
        "checkpoint"
    );
    assert_eq!(a.detach().is_some(), b.detach().is_some(), "detach");
    assert_eq!(a.balloon().is_some(), b.balloon().is_some(), "balloon");
    assert_eq!(a.console().is_some(), b.console().is_some(), "console");
    assert_eq!(a.debug().is_some(), b.debug().is_some(), "debug");
}

/// A listener bound on a prepared VM is live before the guest starts:
/// the guest's boot-time dial-out is accepted, never missed.
pub async fn prepared_listener_is_live_before_boot(h: &dyn ContractHarness) {
    let driver = h.driver();
    let Some(prepare) = driver.prepare() else {
        assert!(!driver.capabilities().prepare);
        return;
    };
    // A guest that makes no dial-out at boot has nothing for this check to
    // catch; the harness says so by naming no port.
    let Some(port) = h.guest_dial_out_port() else {
        return;
    };
    let spec = h.spec(&id("prep-listen"));
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, &h.runtime_dir())
        .await
        .expect("prepare");
    let Some(listen) = prepared.vsock_listener() else {
        assert!(!driver.capabilities().vsock_listen);
        return;
    };
    let mut listener = listen.listen(port).await.expect("listen before boot");
    let vm = prepared.boot(spec).await.expect("boot");
    h.ready(&*vm).await;
    tokio::time::timeout(DEADLINE, listener.accept())
        .await
        .expect("the guest's dial-out before the deadline")
        .expect("accept");
    vm.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// `discard` kills a prepared VM before or after its boot; a second call
/// is fine.
pub async fn discard_kills_a_prepared_vm(h: &dyn ContractHarness) {
    let driver = h.driver();
    let Some(prepare) = driver.prepare() else {
        assert!(!driver.capabilities().prepare);
        return;
    };
    let spec = h.spec(&id("prep-discard"));
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, &h.runtime_dir())
        .await
        .expect("prepare");
    assert!(prepared.alive());
    let status = prepared.discard().await.expect("discard");
    assert!(!prepared.alive());
    assert_eq!(prepared.discard().await.expect("second discard"), status);
    assert!(
        prepared.boot(spec.clone()).await.is_err(),
        "boot after discard"
    );

    let spec = h.spec(&id("prep-discard-booted"));
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, &h.runtime_dir())
        .await
        .expect("prepare");
    let vm = prepared.boot(spec).await.expect("boot");
    prepared.discard().await.expect("discard after boot");
    assert!(!prepared.alive());
    assert!(matches!(vm.state(), VmState::Exited(_)), "{}", vm.state());
}

/// A restore names the image's disks at new host paths (a copy here, a
/// fresh CoW device in production) and comes up under the new id.
///
/// The source boots from private copies of the harness's disks, and those
/// copies are removed once they have been copied again for the restore, so
/// a driver that reopens the paths recorded in the checkpoint instead of
/// the ones in `RestoreSpec::disks` fails here rather than passing by
/// accident.
pub async fn restore_reattaches_disks(h: &dyn ContractHarness) {
    let driver = h.driver();
    if !driver.capabilities().checkpoint {
        // Nothing to restore from; skip before copying disks a hardware
        // harness may measure in gigabytes. The accessor half of the
        // agreement is `capabilities_agree_with_accessors`'s job.
        return;
    }
    let mut source_spec = h.spec(&id("reattach-src"));
    let source_dir = h.runtime_dir();
    for disk in &mut source_spec.disks {
        let private = source_dir.join(format!("{}.src", disk.id));
        std::fs::copy(&disk.path, &private).expect("copy the disk for the source");
        disk.path = private;
    }
    let source = driver
        .boot(source_spec.clone(), &source_dir)
        .await
        .expect("boot");
    h.ready(&*source).await;
    let Some(cp) = source.checkpoint() else {
        assert!(!driver.capabilities().checkpoint);
        source.shutdown(ShutdownMode::Kill).await.expect("kill");
        return;
    };
    let opts = CheckpointOptions {
        after: AfterCheckpoint::HoldQuiesced,
        kind: CheckpointKind::Full,
    };
    let image = cp
        .checkpoint(&source_dir.join("checkpoint"), opts)
        .await
        .expect("checkpoint");
    source
        .shutdown(ShutdownMode::Kill)
        .await
        .expect("kill source");

    let restore_dir = h.runtime_dir();
    let disks = source_spec
        .disks
        .into_iter()
        .map(|mut disk| {
            let copy = restore_dir.join(format!("{}.restored", disk.id));
            std::fs::copy(&disk.path, &copy).expect("copy the disk for the restore");
            std::fs::remove_file(&disk.path).expect("remove the source disk");
            disk.path = copy;
            disk
        })
        .collect();
    let template = h.spec(&id("reattach-dst"));
    let restore = RestoreSpec {
        id: id("reattach-dst"),
        nics: template.nics,
        disks,
        isolation: template.isolation,
    };
    let restored = driver
        .restore(&image, restore, &restore_dir)
        .await
        .expect("restore onto the copied disks");
    assert_eq!(*restored.id(), id("reattach-dst"));
    assert_eq!(restored.record().id, id("reattach-dst"));
    assert_eq!(restored.state(), VmState::Running);
    h.ready(&*restored).await;
    restored.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// A spec that names what [`Staging`](crate::Staging) brought in boots:
/// the paths it hands back are the ones the VM's own spec must carry.
///
/// The capability's accessor and the driver's claim agree here rather than
/// in `capabilities_agree_with_accessors`, which has a handle and not the
/// prepared VM this one lives on.
pub async fn a_staged_spec_boots(h: &dyn ContractHarness) {
    let driver = h.driver();
    let Some(prepare) = driver.prepare() else {
        assert!(!driver.capabilities().prepare);
        return;
    };
    let mut spec = h.spec(&id("staged-boot"));
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, &h.runtime_dir())
        .await
        .expect("prepare");
    let staging = prepared.staging();
    assert_eq!(driver.capabilities().staging, staging.is_some(), "staging");
    let Some(staging) = staging else {
        return;
    };

    // Exactly what an orchestrator does before it boots: bring the spec's
    // own files in, and let each answer replace the path it was named by.
    if let BootSpec::Kernel { image, .. } = &mut spec.boot {
        *image = staging.stage_kernel(image).await.expect("stage the kernel");
    }
    for disk in &mut spec.disks {
        let staged = staging
            .stage_disk(&disk.id, DiskSource::Image(&disk.path))
            .await
            .expect("stage a disk");
        disk.path = staged;
    }

    let vm = prepared.boot(spec).await.expect("boot from staged paths");
    h.ready(&*vm).await;
    assert_eq!(vm.state(), VmState::Running);
    vm.shutdown(ShutdownMode::Kill).await.expect("kill");
}

/// `unstage_disk` takes a staged disk back out intact, and
/// [`DiskSource::Handover`] puts it back by moving it.
///
/// The way anything survives the VM it was staged for: the area belongs to
/// the VM, and a disk that must outlive it leaves first. A driver that
/// stages nothing answers the identity instead — nothing to take out, and
/// the caller's own file where it always was.
pub async fn a_staged_disk_can_be_taken_back_out(h: &dyn ContractHarness) {
    const CONTENT: &[u8] = b"a disk staged by the contract";

    let driver = h.driver();
    let Some(prepare) = driver.prepare() else {
        assert!(!driver.capabilities().prepare);
        return;
    };
    let spec = h.spec(&id("staged-unstage"));
    let dir = h.runtime_dir();
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, &dir)
        .await
        .expect("prepare");
    let Some(staging) = prepared.staging() else {
        assert!(!driver.capabilities().staging);
        return;
    };

    // A file of the check's own, outside anything the VM was given.
    let source = dir.join("staging-source.ext4");
    tokio::fs::write(&source, CONTENT)
        .await
        .expect("a file to stage");
    let staged = staging
        .stage_disk("data", DiskSource::Image(&source))
        .await
        .expect("stage a disk");
    assert!(
        tokio::fs::try_exists(&source).await.unwrap_or(false),
        "an Image source is the caller's to keep"
    );
    assert_eq!(
        tokio::fs::read(&staged)
            .await
            .expect("read the staged disk"),
        CONTENT
    );

    // A disk id names a file the driver writes, replaces and moves, so one
    // that is not a plain name is refused rather than resolved.
    assert!(
        staging
            .stage_disk("../escape", DiskSource::Image(&source))
            .await
            .is_err(),
        "a traversing disk id was staged"
    );
    assert!(
        staging.unstage_disk("../escape", &dir).await.is_err(),
        "a traversing disk id was unstaged"
    );

    let parked = dir.join("parked.ext4");
    if staged == source {
        // Identity staging: the file was already where the VM reads it, so
        // there is nothing to take out and nothing was moved.
        assert!(
            !staging
                .unstage_disk("data", &parked)
                .await
                .expect("unstage what was never staged")
        );
        assert!(tokio::fs::try_exists(&source).await.unwrap_or(false));
        return;
    }

    // Staging what is already in the VM's area names it where it is —
    // never a copy of a file onto itself, which would truncate it.
    assert_eq!(
        staging
            .stage_disk("data", DiskSource::Image(&staged))
            .await
            .expect("stage what is already staged"),
        staged
    );
    assert_eq!(
        tokio::fs::read(&staged)
            .await
            .expect("read the staged disk"),
        CONTENT
    );

    assert!(
        staging
            .unstage_disk("data", &parked)
            .await
            .expect("unstage the disk"),
        "a staged disk is reported as taken out"
    );
    assert_eq!(
        tokio::fs::read(&parked)
            .await
            .expect("read the parked disk"),
        CONTENT
    );
    assert!(
        !tokio::fs::try_exists(&staged).await.unwrap_or(true),
        "the disk is gone from the vm's area"
    );
    assert!(
        !staging
            .unstage_disk("data", &parked)
            .await
            .expect("unstage twice"),
        "nothing is left to take out"
    );

    // And back in, consuming the parked copy.
    let back = staging
        .stage_disk("data", DiskSource::Handover(&parked))
        .await
        .expect("hand the disk back in");
    assert!(
        !tokio::fs::try_exists(&parked).await.unwrap_or(true),
        "a handed-over disk is moved, not copied"
    );
    assert_eq!(
        tokio::fs::read(&back).await.expect("read the disk back in"),
        CONTENT
    );
    prepared.discard().await.expect("discard");
}

/// A checkpoint staged into a prepared VM restores from where it landed.
///
/// The warm-pool path, and the reason [`Staging::stage_checkpoint`] is a
/// verb of its own: a slot brings the image in — the memory file is the
/// guest's entire RAM — long before any restore is asked for, and the
/// restore then loads what is already there. Nothing else in this
/// contract touches that verb, so an image that comes back naming a
/// directory the files never reached would pass everything else.
///
/// [`Staging::stage_checkpoint`]: crate::Staging::stage_checkpoint
pub async fn a_staged_checkpoint_restores(h: &dyn ContractHarness) {
    let driver = h.driver();
    if !driver.capabilities().checkpoint || !driver.capabilities().staging {
        return;
    }
    let Some(prepare) = driver.prepare() else {
        assert!(!driver.capabilities().prepare);
        return;
    };

    let source = boot(h, "staged-restore-src").await;
    let Some(cp) = source.checkpoint() else {
        assert!(!driver.capabilities().checkpoint);
        source.shutdown(ShutdownMode::Kill).await.expect("kill");
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

    // The slot: prepared, then handed the image and the disks it will run
    // on, with nothing left for the restore to bring in.
    let template = h.spec(&id("staged-restore-dst"));
    let prepared = prepare
        .prepare(&template.id, &template.isolation, &h.runtime_dir())
        .await
        .expect("prepare");
    let staging = prepared.staging().expect("the driver claims staging");
    let staged = staging
        .stage_checkpoint(&image)
        .await
        .expect("stage the checkpoint");
    assert_eq!(staged.format, image.format);
    assert_eq!(staged.kind, image.kind);
    let mut disks = Vec::new();
    for mut disk in template.disks {
        disk.path = staging
            .stage_disk(&disk.id, DiskSource::Image(&disk.path))
            .await
            .expect("stage a disk for the restore");
        disks.push(disk);
    }

    let restored = prepared
        .restore(
            &staged,
            RestoreSpec {
                id: id("staged-restore-dst"),
                nics: template.nics,
                disks,
                isolation: template.isolation,
            },
        )
        .await
        .expect("restore from the staged image");
    assert_eq!(*restored.id(), id("staged-restore-dst"));
    assert_eq!(restored.state(), VmState::Running);
    h.ready(&*restored).await;
    restored.shutdown(ShutdownMode::Kill).await.expect("kill");
}
