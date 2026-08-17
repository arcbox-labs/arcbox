//! Handle behavior over plain children and an API socket nobody answers on.

use arcbox_vm_driver::{IsolationSpec, ProcessRecord};

use super::*;
use crate::api::fake_fc::FakeFc;
use crate::config::FcDriverConfig;
use crate::process::testing::{pid_exists, spawn};

/// A handle over a `sleep` child and an API socket nobody answers on.
fn handle(dir: &Path, isolation: IsolationSpec, vsock: bool) -> FcHandle {
    handle_over(Arc::new(spawn("sleep", &["30"])), dir, isolation, vsock)
}

/// A handle over `process` and an API socket nobody answers on.
fn handle_over(
    process: Arc<FcProcess>,
    dir: &Path,
    isolation: IsolationSpec,
    vsock: bool,
) -> FcHandle {
    let client = fc_sdk::connection::connect(dir.join("absent.sock"));
    with_client(process, client, dir, isolation, vsock, false)
}

/// A handle over `process`, talking to `client`.
fn with_client(
    process: Arc<FcProcess>,
    client: fc_sdk::Client,
    dir: &Path,
    isolation: IsolationSpec,
    vsock: bool,
    quiesced: bool,
) -> FcHandle {
    let id = VmId::new("box").unwrap();
    let mut config = FcDriverConfig::new("/opt/fc/firecracker");
    config.jailer_binary = Some("/opt/fc/jailer".into());
    let layout = VmLayout::new(&id, &isolation, &config, dir).unwrap();
    let record = VmRecord {
        id,
        driver: NAME.to_owned(),
        runtime_dir: dir.to_path_buf(),
        process: Some(ProcessRecord {
            pid: process.pid(),
            api_socket: Some(layout.api_socket()),
        }),
    };
    let vsock = vsock.then(|| VsockEndpoint::new(layout.vsock_host_uds()));
    FcHandle::new(process, client, layout, record, vsock, quiesced)
}

/// A checkpoint destination inside the VM's jail, so the capture is
/// written in place and nothing has to be moved out afterwards (the
/// scripted Firecracker writes no files).
fn in_jail(vm: &FcHandle) -> PathBuf {
    vm.layout
        .jail()
        .expect("checkpoints are taken on jailed vms")
        .root
        .join("snapshots/ckpt")
}

/// A Firecracker that pauses and describes itself happily, and answers
/// `snapshot/create` and the resume as the test asks.
fn scripted(dir: &Path, capture: u16, resume: u16, state: &'static str) -> FakeFc {
    FakeFc::start(dir, move |route, body| match route {
        "PATCH /vm" if body.contains("Resumed") => {
            (resume, r#"{"fault_message":"no resume"}"#.into())
        }
        "PATCH /vm" => (204, String::new()),
        "PUT /snapshot/create" => (capture, r#"{"fault_message":"no capture"}"#.into()),
        "GET /" => (
            200,
            format!(r#"{{"app_name":"fake","id":"box","state":"{state}","vmm_version":"1.10.1"}}"#),
        ),
        other => panic!("the driver called {other} unexpectedly"),
    })
}

fn jail(dir: &Path) -> IsolationSpec {
    IsolationSpec::Jailer {
        uid: nix::unistd::getuid().as_raw(),
        gid: nix::unistd::getgid().as_raw(),
        chroot_base: dir.join("jail"),
        netns: None,
        new_pid_ns: false,
        cgroup: None,
    }
}

#[tokio::test]
async fn state_follows_the_process_and_kill_reports_the_signal() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), jail(dir.path()), true);
    assert_eq!(vm.state(), VmState::Running);
    assert!(vm.vsock().is_some() && vm.vsock_listener().is_some());
    assert!(VmHandle::checkpoint(&vm).is_some() && VmHandle::detach(&vm).is_some());
    let mut events = vm.events();
    let status = vm.shutdown(ShutdownMode::Kill).await.unwrap();
    assert_eq!(status, ExitStatus::signaled(9));
    assert_eq!(vm.state(), VmState::Exited(status));
    assert_eq!(events.recv().await.unwrap(), VmEvent::Exited(status));
    assert!(events.try_recv().is_err());
    // Nothing to dial, listen on, or checkpoint once exited.
    assert!(matches!(
        vm.vsock().unwrap().dial(52).await,
        Err(Error::WrongState { .. })
    ));
    assert!(matches!(
        vm.vsock_listener().unwrap().listen(51).await,
        Err(Error::WrongState { .. })
    ));
    assert!(matches!(
        VmHandle::checkpoint(&vm)
            .unwrap()
            .checkpoint(&in_jail(&vm), CheckpointOptions::default())
            .await,
        Err(Error::WrongState { .. })
    ));
}

#[tokio::test]
async fn checkpoints_are_a_jailer_mode_capability() {
    // Firecracker reopens the recorded drive paths on load, so a checkpoint
    // can be restored only inside a per-VM chroot; an unjailed VM has no
    // checkpoint accessor.
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), IsolationSpec::None, true);
    assert!(VmHandle::checkpoint(&vm).is_none());
    assert!(vm.vsock().is_some() && VmHandle::detach(&vm).is_some());
}

#[tokio::test]
async fn graceful_shutdown_kills_at_the_deadline_when_the_guest_ignores_it() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), IsolationSpec::None, false);
    assert!(vm.vsock().is_none() && vm.vsock_listener().is_none());
    let status = vm
        .shutdown(ShutdownMode::Graceful {
            timeout: Duration::from_millis(300),
        })
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::signaled(9));
    assert_eq!(vm.state(), VmState::Exited(status));
}

#[tokio::test]
async fn drop_kills_unless_detached() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), IsolationSpec::None, false);
    let pid = vm.record().process.unwrap().pid;
    drop(vm);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!pid_exists(pid), "a dropped handle kills the vm");

    let vm = handle(dir.path(), IsolationSpec::None, false);
    let pid = vm.record().process.unwrap().pid;
    let record = VmHandle::detach(&vm).unwrap().detach().await.unwrap();
    assert_eq!(record, vm.record());
    drop(vm);
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(pid_exists(pid), "a detached vm keeps running");
    #[allow(clippy::cast_possible_wrap, reason = "test pid")]
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGKILL,
    )
    .unwrap();

    // An adopted vm is released the same way: detach, then drop, and it
    // keeps running for the next adopter.
    let mut child = tokio::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let adopted = Arc::new(FcProcess::adopt(pid, dir.path().join("absent.sock")));
    let vm = handle_over(adopted, dir.path(), IsolationSpec::None, false);
    VmHandle::detach(&vm).unwrap().detach().await.unwrap();
    drop(vm);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(pid_exists(pid), "a detached adopted vm keeps running");
    child.kill().await.unwrap();
    child.wait().await.unwrap();
}

#[tokio::test]
async fn diff_checkpoints_are_refused_before_touching_the_guest() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), jail(dir.path()), false);
    let opts = CheckpointOptions {
        after: AfterCheckpoint::Resume,
        kind: CheckpointKind::Diff,
    };
    assert!(matches!(
        VmHandle::checkpoint(&vm)
            .unwrap()
            .checkpoint(&in_jail(&vm), opts)
            .await,
        Err(Error::InvalidSpec(_))
    ));
    assert_eq!(vm.state(), VmState::Running);
}

#[tokio::test]
async fn snapshots_are_written_in_place_or_staged_in_the_jail() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), IsolationSpec::None, false);
    let dst = dir.path().join("ckpt");
    match vm.snapshot_site(&dst).await.unwrap() {
        SnapshotSite::Direct { vmstate, mem } => {
            assert_eq!(vmstate, dst.join("vmstate").to_str().unwrap());
            assert_eq!(mem, dst.join("mem").to_str().unwrap());
        }
        SnapshotSite::Staged { .. } => panic!("no jail, no staging"),
    }

    let vm = handle(dir.path(), jail(dir.path()), false);
    let root = vm.layout.jail().unwrap().root.clone();
    let inside = root.join("snapshots/abc");
    tokio::fs::create_dir_all(&inside).await.unwrap();
    match vm.snapshot_site(&inside).await.unwrap() {
        SnapshotSite::Direct { vmstate, mem } => {
            assert_eq!(vmstate, "/snapshots/abc/vmstate");
            assert_eq!(mem, "/snapshots/abc/mem");
        }
        SnapshotSite::Staged { .. } => panic!("inside the jail is written in place"),
    }
    let outside = dir.path().join("catalog/ckpt");
    match vm.snapshot_site(&outside).await.unwrap() {
        SnapshotSite::Staged { dir, vmstate, mem } => {
            assert!(dir.starts_with(root.join("snapshots")), "{}", dir.display());
            assert!(dir.is_dir());
            let name = dir.file_name().unwrap().to_str().unwrap().to_owned();
            assert_eq!(vmstate, format!("/snapshots/{name}/vmstate"));
            assert_eq!(mem, format!("/snapshots/{name}/mem"));
        }
        SnapshotSite::Direct { .. } => panic!("outside the jail is staged"),
    }
}

#[tokio::test]
async fn a_failed_capture_is_reported_even_when_the_resume_fails_too() {
    let dir = tempfile::tempdir().unwrap();
    let fc = scripted(dir.path(), 400, 400, "Paused");
    let vm = with_client(
        Arc::new(spawn("sleep", &["30"])),
        fc.client(),
        dir.path(),
        jail(dir.path()),
        false,
        false,
    );
    let failed = VmHandle::checkpoint(&vm)
        .unwrap()
        .checkpoint(&in_jail(&vm), CheckpointOptions::default())
        .await;
    match failed {
        Err(Error::Driver { message, .. }) => {
            assert!(message.contains("no capture"), "{message}");
        }
        other => panic!("expected the capture failure, got {other:?}"),
    }
    // The resume was attempted and did not take: the guest really is frozen.
    assert_eq!(vm.state(), VmState::Quiesced);
    let calls = fc.calls();
    assert!(
        calls.iter().any(|call| call.contains("Paused")),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|call| call.contains("Resumed")),
        "{calls:?}"
    );
}

#[tokio::test]
async fn a_failed_capture_leaves_a_resumed_guest_running() {
    let dir = tempfile::tempdir().unwrap();
    let fc = scripted(dir.path(), 400, 204, "Paused");
    let vm = with_client(
        Arc::new(spawn("sleep", &["30"])),
        fc.client(),
        dir.path(),
        jail(dir.path()),
        false,
        false,
    );
    assert!(
        VmHandle::checkpoint(&vm)
            .unwrap()
            .checkpoint(&in_jail(&vm), CheckpointOptions::default())
            .await
            .is_err()
    );
    assert_eq!(vm.state(), VmState::Running);
}

#[tokio::test]
async fn a_guest_the_handle_believes_is_frozen_is_asked_before_the_capture() {
    let dir = tempfile::tempdir().unwrap();
    // The handle thinks the guest is quiesced; Firecracker says it runs.
    let fc = scripted(dir.path(), 204, 204, "Running");
    let vm = with_client(
        Arc::new(spawn("sleep", &["30"])),
        fc.client(),
        dir.path(),
        jail(dir.path()),
        false,
        true,
    );
    assert_eq!(vm.state(), VmState::Quiesced);
    let opts = CheckpointOptions {
        after: AfterCheckpoint::HoldQuiesced,
        kind: CheckpointKind::Full,
    };
    VmHandle::checkpoint(&vm)
        .unwrap()
        .checkpoint(&in_jail(&vm), opts)
        .await
        .expect("checkpoint");
    let calls = fc.calls();
    assert_eq!(calls[0], "GET /", "{calls:?}");
    assert!(
        calls[1].contains("Paused"),
        "the stale belief was corrected: {calls:?}"
    );
    // A hold does not resume, and the guest is frozen for real this time.
    assert!(
        !calls.iter().any(|call| call.contains("Resumed")),
        "{calls:?}"
    );
    assert_eq!(vm.state(), VmState::Quiesced);
}

#[tokio::test]
async fn a_listener_fails_once_the_vm_exits() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), IsolationSpec::None, true);
    let mut listener = vm.vsock_listener().unwrap().listen(51).await.unwrap();
    assert!(dir.path().join("firecracker.vsock_51").exists());
    let killer = {
        let pid = vm.record().process.unwrap().pid;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            #[allow(clippy::cast_possible_wrap, reason = "test pid")]
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            )
            .unwrap();
        })
    };
    let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
    assert!(matches!(accepted, Ok(Err(Error::WrongState { .. }))));
    killer.await.unwrap();
    drop(listener);
    assert!(!dir.path().join("firecracker.vsock_51").exists());
}

#[tokio::test]
async fn listen_binds_next_to_the_socket_dial_uses_not_the_layout_path() {
    // A restored (or adopted) VM has its vsock where the checkpoint
    // recorded it — in direct mode the source VM's runtime dir, not this
    // one's. Guest dial-outs land next to that socket, so the listener
    // must be bound there too.
    let dir = tempfile::tempdir().unwrap();
    let recorded = dir.path().join("source").join("firecracker.vsock");
    std::fs::create_dir_all(recorded.parent().unwrap()).unwrap();
    let id = VmId::new("box").unwrap();
    let config = FcDriverConfig::new("/opt/fc/firecracker");
    let layout = VmLayout::new(&id, &IsolationSpec::None, &config, dir.path()).unwrap();
    assert_ne!(layout.vsock_host_uds(), recorded);
    let process = Arc::new(spawn("sleep", &["30"]));
    let record = VmRecord {
        id,
        driver: NAME.to_owned(),
        runtime_dir: dir.path().to_path_buf(),
        process: Some(ProcessRecord {
            pid: process.pid(),
            api_socket: Some(layout.api_socket()),
        }),
    };
    let vm = FcHandle::new(
        process,
        fc_sdk::connection::connect(dir.path().join("absent.sock")),
        layout,
        record,
        Some(VsockEndpoint::new(recorded.clone())),
        false,
    );

    let listener = vm.vsock_listener().unwrap().listen(51).await.unwrap();
    assert!(
        dir.path().join("source/firecracker.vsock_51").exists(),
        "bound next to the recorded socket"
    );
    assert!(
        !dir.path().join("firecracker.vsock_51").exists(),
        "not next to the layout's socket"
    );
    drop(listener);
    // And a kill unlinks the recorded socket, not the layout's.
    std::fs::write(&recorded, b"").unwrap();
    vm.shutdown(ShutdownMode::Kill).await.unwrap();
    assert!(!recorded.exists());
}
