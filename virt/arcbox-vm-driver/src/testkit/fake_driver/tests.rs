//! Unit tests for the fake driver: what the contract does not cover.

use std::io::{Read as _, Write as _};
use std::time::Duration;

use super::*;
use crate::capability::{AfterCheckpoint, CheckpointFormat, CheckpointKind, CheckpointOptions};
use crate::driver::{ExitStatus, IoMode, ShutdownMode, VmEvent};
use crate::spec::{BootSpec, ConsoleSpec, DiskSpec, IsolationSpec, VsockSpec};

fn spec(id: &str) -> VmSpec {
    VmSpec {
        id: VmId::new(id).unwrap(),
        cpus: 1,
        memory_mib: 64,
        boot: BootSpec::Kernel {
            image: "/fake/vmlinux".into(),
            cmdline: String::new(),
            initrd: None,
        },
        disks: vec![],
        nics: vec![],
        vsock: None,
        shares: vec![],
        console: Default::default(),
        balloon: false,
        entropy: false,
        dirty_tracking: false,
        isolation: Default::default(),
    }
}

/// A spec asking for every device the fake implements.
fn full_spec(id: &str) -> VmSpec {
    VmSpec {
        vsock: Some(VsockSpec { guest_cid: 3 }),
        console: ConsoleSpec::File("/fake/console.log".into()),
        balloon: true,
        ..spec(id)
    }
}

#[tokio::test]
async fn shutdown_is_idempotent_and_reports_the_first_status() {
    let driver = FakeDriver::new();
    let vm = driver
        .boot(spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    let graceful = ShutdownMode::Graceful {
        timeout: Duration::from_secs(1),
    };
    assert_eq!(vm.shutdown(graceful).await.unwrap(), ExitStatus::exited(0));
    assert_eq!(
        vm.shutdown(ShutdownMode::Kill).await.unwrap(),
        ExitStatus::exited(0)
    );
    assert_eq!(vm.state(), VmState::Exited(ExitStatus::exited(0)));
}

#[tokio::test]
async fn dropping_the_handle_kills_the_vm_and_frees_the_id() {
    let driver = FakeDriver::new();
    let vm = driver
        .boot(spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    let mut events = vm.events();
    drop(vm);
    assert_eq!(
        events.try_recv().unwrap(),
        VmEvent::Exited(ExitStatus::signaled(9))
    );
    // The id is free again: the exited entry is pruned on the way in.
    driver
        .boot(spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_live_id_cannot_be_booted_twice() {
    let driver = FakeDriver::new();
    let _vm = driver
        .boot(spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    let Err(err) = driver.boot(spec("vm-1"), Path::new("/run/vm-1")).await else {
        panic!("second boot of a live id succeeded");
    };
    assert!(
        matches!(
            err,
            Error::WrongState {
                state: VmState::Running,
                ..
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn accessors_follow_the_spec_and_the_claims() {
    let driver = FakeDriver::new();
    let bare = driver
        .boot(spec("bare"), Path::new("/run/bare"))
        .await
        .unwrap();
    assert!(bare.vsock().is_none() && bare.vsock_listener().is_none());
    assert!(bare.balloon().is_none() && bare.console().is_none());
    assert!(bare.debug().is_some());

    let full = driver
        .boot(full_spec("full"), Path::new("/run/full"))
        .await
        .unwrap();
    assert!(full.vsock().is_some() && full.vsock_listener().is_some());
    assert!(full.balloon().is_some() && full.console().is_some());

    let narrow = FakeDriver::builder()
        .capabilities(DriverCapabilities::default())
        .build();
    let vm = narrow
        .boot(full_spec("narrow"), Path::new("/run/narrow"))
        .await
        .unwrap();
    assert!(vm.vsock().is_none() && vm.debug().is_none() && vm.balloon().is_none());
}

#[tokio::test]
async fn dial_reaches_an_echoing_guest() {
    let driver = FakeDriver::new();
    let vm = driver
        .boot(full_spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    let conn = vm.vsock().unwrap().dial(1024).await.unwrap();
    assert_eq!(conn.mode, IoMode::Async);
    let mut stream = UnixStream::from(conn.fd);
    stream.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    vm.shutdown(ShutdownMode::Kill).await.unwrap();
    assert!(matches!(
        vm.vsock().unwrap().dial(1024).await,
        Err(Error::WrongState { .. })
    ));
}

#[tokio::test]
async fn guest_dial_is_accepted_by_the_listener_in_order() {
    let driver = FakeDriver::new();
    let vm = driver
        .boot(full_spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    // Pushed before `listen`: the queue is per port, not per listener.
    let mut early = driver.guest_dial(vm.id(), 7).unwrap();
    early.write_all(b"early").unwrap();
    let mut listener = vm.vsock_listener().unwrap().listen(7).await.unwrap();
    let mut first = UnixStream::from(listener.accept().await.unwrap().fd);
    let mut buf = [0u8; 5];
    first.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"early");

    let accept = tokio::spawn(async move { listener.accept().await.map(|c| c.mode) });
    tokio::task::yield_now().await;
    let _late = driver.guest_dial(vm.id(), 7).unwrap();
    assert_eq!(accept.await.unwrap().unwrap(), IoMode::Async);

    vm.shutdown(ShutdownMode::Kill).await.unwrap();
    assert!(matches!(
        driver.guest_dial(vm.id(), 7),
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn console_hands_out_pushed_bytes_once() {
    let driver = FakeDriver::new();
    let vm = driver
        .boot(full_spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    driver.push_console(vm.id(), b"hello world").unwrap();
    let console = vm.console().unwrap();
    assert_eq!(console.read_output(5).await.unwrap(), b"hello");
    assert_eq!(console.read_output(64).await.unwrap(), b" world");
    assert!(console.read_output(64).await.unwrap().is_empty());
}

fn restore_spec(id: &str) -> RestoreSpec {
    RestoreSpec {
        id: VmId::new(id).unwrap(),
        nics: vec![],
        disks: vec![],
        isolation: IsolationSpec::None,
    }
}

#[tokio::test]
async fn checkpoint_writes_an_image_restore_reads_back_with_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let driver = FakeDriver::new();
    let vm = driver.boot(full_spec("vm-1"), dir.path()).await.unwrap();
    vm.balloon().unwrap().set_target(8 << 20).await.unwrap();

    let hold = CheckpointOptions {
        after: AfterCheckpoint::HoldQuiesced,
        kind: CheckpointKind::Full,
    };
    let image = vm
        .checkpoint()
        .unwrap()
        .checkpoint(&dir.path().join("ckpt"), hold)
        .await
        .unwrap();
    assert_eq!(vm.state(), VmState::Quiesced);
    assert_eq!(image.format, CheckpointFormat::new("fake/v1"));
    assert!(image.dir.join("vmstate").is_file());
    assert!(image.dir.join("mem").is_file());
    // A quiesced VM can be checkpointed again and resumed.
    let resume = CheckpointOptions::default();
    vm.checkpoint()
        .unwrap()
        .checkpoint(&dir.path().join("ckpt2"), resume)
        .await
        .unwrap();
    assert_eq!(vm.state(), VmState::Running);
    vm.shutdown(ShutdownMode::Kill).await.unwrap();

    let restored = driver
        .restore(&image, restore_spec("vm-2"), dir.path())
        .await
        .unwrap();
    assert_eq!(restored.id().as_str(), "vm-2");
    assert_eq!(restored.state(), VmState::Running);
    assert_eq!(restored.record().driver, "fake");
    // Everything the restore spec does not override comes from the image.
    assert!(restored.vsock().is_some() && restored.console().is_some());
    assert_eq!(
        restored
            .balloon()
            .unwrap()
            .stats()
            .await
            .unwrap()
            .target_bytes,
        8 << 20
    );
}

#[tokio::test]
async fn restore_must_name_exactly_the_images_disks() {
    let dir = tempfile::tempdir().unwrap();
    let driver = FakeDriver::new();
    let mut with_disk = full_spec("vm-1");
    with_disk.disks.push(DiskSpec {
        id: "rootfs".into(),
        path: dir.path().join("rootfs.ext4"),
        read_only: false,
        root: true,
        cache: Default::default(),
    });
    let vm = driver.boot(with_disk, dir.path()).await.unwrap();
    let hold = CheckpointOptions {
        after: AfterCheckpoint::HoldQuiesced,
        kind: CheckpointKind::Full,
    };
    let image = vm
        .checkpoint()
        .unwrap()
        .checkpoint(&dir.path().join("ckpt"), hold)
        .await
        .unwrap();
    vm.shutdown(ShutdownMode::Kill).await.unwrap();

    // No disks named: refused; the image has one.
    let Err(err) = driver
        .restore(&image, restore_spec("vm-2"), dir.path())
        .await
    else {
        panic!("restore without the image's disks succeeded");
    };
    assert!(matches!(err, Error::InvalidSpec(_)), "{err}");

    let mut renamed = restore_spec("vm-2");
    renamed.disks.push(DiskSpec {
        id: "rootfs".into(),
        path: dir.path().join("rootfs.restored"),
        read_only: false,
        root: true,
        cache: Default::default(),
    });
    driver.restore(&image, renamed, dir.path()).await.unwrap();
}

#[tokio::test]
async fn restore_refuses_foreign_and_unclaimed_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let foreign = CheckpointImage {
        dir: dir.path().to_path_buf(),
        format: CheckpointFormat::new("firecracker/v1"),
        kind: CheckpointKind::Full,
    };
    let err = FakeDriver::new()
        .restore(&foreign, restore_spec("vm-2"), dir.path())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::ForeignCheckpoint(f) if f.as_str() == "firecracker/v1"));

    let unclaimed = FakeDriver::builder()
        .capabilities(DriverCapabilities::default())
        .build();
    let own = CheckpointImage {
        format: CheckpointFormat::new("fake/v1"),
        ..foreign
    };
    let err = unclaimed
        .restore(&own, restore_spec("vm-2"), dir.path())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, Error::ForeignCheckpoint(_)));
}

#[tokio::test]
async fn detach_keeps_the_vm_alive_for_adopt_and_only_once() {
    let driver = FakeDriver::new();
    let vm = driver
        .boot(spec("vm-1"), Path::new("/run/vm-1"))
        .await
        .unwrap();
    let record = vm.detach().unwrap().detach().await.unwrap();
    assert_eq!(record, vm.record());
    drop(vm);

    let adopt = driver.adopt().unwrap();
    let again = adopt.adopt(&record).await.unwrap().unwrap();
    assert_eq!(again.state(), VmState::Running);
    // Two owners is a caller bug, not a second handle.
    assert!(matches!(
        adopt.adopt(&record).await,
        Err(Error::Driver { .. })
    ));

    drop(again);
    assert!(adopt.adopt(&record).await.unwrap().is_none());
}

#[tokio::test]
async fn scripted_failures_fire_once() {
    let dir = tempfile::tempdir().unwrap();
    let driver = FakeDriver::new();
    driver.fail_next_boot().fail_next_checkpoint();
    assert!(matches!(
        driver.boot(spec("vm-1"), dir.path()).await.err(),
        Some(Error::Driver { .. })
    ));
    let vm = driver.boot(spec("vm-1"), dir.path()).await.unwrap();
    let cp = vm.checkpoint().unwrap();
    assert!(matches!(
        cp.checkpoint(&dir.path().join("a"), CheckpointOptions::default())
            .await
            .err(),
        Some(Error::Driver { .. })
    ));
    cp.checkpoint(&dir.path().join("b"), CheckpointOptions::default())
        .await
        .unwrap();
}

/// A frozen checkpoint failure differs from an ordinary one in the state
/// it leaves behind, and that state is the whole signal: a caller reads
/// `Quiesced` back from a capture it asked to resume and knows the port
/// has no verb left to thaw the guest.
#[tokio::test]
async fn a_frozen_checkpoint_failure_leaves_the_guest_quiesced() {
    let dir = tempfile::tempdir().unwrap();
    let driver = FakeDriver::new();
    driver.freeze_next_checkpoint();
    let vm = driver.boot(spec("vm-1"), dir.path()).await.unwrap();
    let cp = vm.checkpoint().unwrap();

    assert!(matches!(
        cp.checkpoint(&dir.path().join("a"), CheckpointOptions::default())
            .await
            .err(),
        Some(Error::Driver { .. })
    ));
    assert_eq!(vm.state(), VmState::Quiesced);
    // Armed once: the retry captures and resumes.
    cp.checkpoint(&dir.path().join("b"), CheckpointOptions::default())
        .await
        .unwrap();
    assert_eq!(vm.state(), VmState::Running);
}

/// A VM that was asked to die is distinguishable from one whose handle
/// merely went out of scope, though both end `Exited` with the same
/// status — which is what makes a teardown that forgot its shutdown
/// visible at all.
#[tokio::test]
async fn the_driver_reports_which_shutdowns_a_vm_was_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let driver = FakeDriver::new();
    let asked = VmId::new("vm-asked").unwrap();
    let dropped = VmId::new("vm-dropped").unwrap();
    assert!(driver.shutdowns(&asked).is_empty(), "no such vm yet");

    let vm = driver.boot(spec("vm-asked"), dir.path()).await.unwrap();
    vm.shutdown(ShutdownMode::Kill).await.unwrap();
    assert_eq!(driver.shutdowns(&asked), vec![ShutdownMode::Kill]);

    drop(driver.boot(spec("vm-dropped"), dir.path()).await.unwrap());
    assert!(
        driver.shutdowns(&dropped).is_empty(),
        "a killing drop is not a shutdown anyone asked for"
    );
}

#[tokio::test]
async fn a_discarded_prepared_vm_refuses_listeners_before_and_after_its_boot() {
    let driver = FakeDriver::new();
    let prepare = driver.prepare().unwrap();

    // Discarded before any boot: listen, boot and alive all say so.
    let spec = full_spec("vm-1");
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, Path::new("/run/vm-1"))
        .await
        .unwrap();
    prepared.discard().await.unwrap();
    assert!(!prepared.alive());
    assert!(matches!(
        prepared.vsock_listener().unwrap().listen(7).await.err(),
        Some(Error::WrongState { .. })
    ));
    assert!(matches!(
        prepared.boot(spec).await.err(),
        Some(Error::WrongState { .. })
    ));

    // Discarded after a boot: the same answers, and the handle agrees.
    let spec = full_spec("vm-2");
    let prepared = prepare
        .prepare(&spec.id, &spec.isolation, Path::new("/run/vm-2"))
        .await
        .unwrap();
    let vm = prepared.boot(spec.clone()).await.unwrap();
    let status = prepared.discard().await.unwrap();
    assert_eq!(vm.state(), VmState::Exited(status));
    assert!(!prepared.alive());
    assert!(matches!(
        prepared.vsock_listener().unwrap().listen(7).await.err(),
        Some(Error::WrongState { .. })
    ));
    assert!(matches!(
        vm.vsock_listener().unwrap().listen(7).await.err(),
        Some(Error::WrongState { .. })
    ));
    assert!(matches!(
        prepared.boot(spec).await.err(),
        Some(Error::WrongState { .. })
    ));
}
