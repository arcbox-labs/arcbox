//! Handle behavior over plain children and an API socket nobody answers on.

use std::path::PathBuf;

use arcbox_vm_driver::{IsolationSpec, ProcessRecord};

use super::*;
use crate::config::FcDriverConfig;
use crate::process::testing::{pid_exists, spawn};

/// A handle over a `sleep` child and an API socket nobody answers on.
fn handle(dir: &Path, isolation: IsolationSpec, vsock: bool) -> FcHandle {
    let id = VmId::new("box").unwrap();
    let mut config = FcDriverConfig::new("/opt/fc/firecracker");
    config.jailer_binary = Some("/opt/fc/jailer".into());
    let layout = VmLayout::new(&id, &isolation, &config, dir).unwrap();
    let process = Arc::new(spawn("sleep", &["30"]));
    let record = VmRecord {
        id,
        driver: NAME.to_owned(),
        runtime_dir: dir.to_path_buf(),
        process: Some(ProcessRecord {
            pid: process.pid(),
            api_socket: Some(layout.api_socket()),
        }),
    };
    let vsock_uds = vsock.then(|| layout.vsock_host_uds());
    FcHandle::new(
        process,
        fc_sdk::connection::connect(dir.join("absent.sock")),
        layout,
        record,
        vsock_uds,
        false,
    )
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
    let vm = handle(dir.path(), IsolationSpec::None, true);
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
            .checkpoint(&dir.path().join("ckpt"), CheckpointOptions::default())
            .await,
        Err(Error::WrongState { .. })
    ));
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
}

#[tokio::test]
async fn diff_checkpoints_are_refused_before_touching_the_guest() {
    let dir = tempfile::tempdir().unwrap();
    let vm = handle(dir.path(), IsolationSpec::None, false);
    let opts = CheckpointOptions {
        after: AfterCheckpoint::Resume,
        kind: CheckpointKind::Diff,
    };
    assert!(matches!(
        VmHandle::checkpoint(&vm)
            .unwrap()
            .checkpoint(&dir.path().join("ckpt"), opts)
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
    let _ = PathBuf::new();
}
