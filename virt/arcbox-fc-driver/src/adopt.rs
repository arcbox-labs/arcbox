//! Rebuilding a handle over the Firecracker [`discover`](crate::discover)
//! found.
//!
//! The process is the VM's identity and all a kill needs; the API is what
//! everything else needs. So the guard goes over the verified pid first,
//! and the API is reconnected best-effort within a short bound: a VMM
//! that answers `GET /` and `GET /vm/config` gets the full [`FcHandle`] —
//! its devices and paused state read back — and one whose socket is
//! missing, wedged, or closes gets an [`FcProcessHandle`], kill-able and
//! observable and nothing more. An adopt never fails on the API: the
//! sandbox manager's restart sweep adopts in order to `shutdown(Kill)`,
//! and an orphan whose control socket died with its booter would otherwise
//! be unkillable through the port — the blind SIGKILL by pid this replaced
//! had no such dependency.

use std::sync::Arc;
use std::time::Duration;

use arcbox_vm_driver::{ProcessRecord, Result, VmHandle, VmRecord};
use fc_sdk::Client;
use fc_sdk::types::{FullVmConfiguration, InstanceInfo, InstanceInfoState};

use crate::api;
use crate::config::FcDriverConfig;
use crate::discover::Found;
use crate::handle::{FcHandle, FcProcessHandle};
use crate::listener::VsockEndpoint;
use crate::process::FcProcess;
use crate::render::VmLayout;

/// How long an adopt gives the API to describe the VM before settling for
/// the process alone.
///
/// Two round-trips on a local socket take microseconds; a socket that has
/// not answered in this long is not going to. Well inside the sandbox
/// manager's per-orphan adopt budget (10 s), which this must stay under.
pub const API_TIMEOUT: Duration = Duration::from_secs(2);

/// A handle over `found`, the VMM `record` names, giving its API
/// `api_timeout` to answer.
///
/// The record the handle reports carries the process that was verified:
/// the recorded pid may have been recycled and the VM found by the `/proc`
/// scan instead, and the API socket may have come off its command line.
pub(crate) async fn rebuild(
    config: &FcDriverConfig,
    found: Found,
    record: &VmRecord,
    api_timeout: Duration,
) -> Result<Box<dyn VmHandle>> {
    let layout = VmLayout::new(&record.id, &found.isolation, config, &record.runtime_dir)?;
    let process = Arc::new(FcProcess::adopt(found.pid, found.api_socket.clone()));
    let record = VmRecord {
        process: Some(ProcessRecord {
            pid: found.pid,
            api_socket: Some(found.api_socket.clone()),
        }),
        ..record.clone()
    };
    let client = fc_sdk::connection::connect(&found.api_socket);
    let (info, devices) = match tokio::time::timeout(api_timeout, describe(&client)).await {
        Ok(Ok(answered)) => answered,
        Ok(Err(error)) => return Ok(process_only(process, record, &error.to_string())),
        Err(_) => {
            return Ok(process_only(
                process,
                record,
                &format!("no answer within {api_timeout:?}"),
            ));
        }
    };
    let vsock = devices
        .vsock
        .map(|vsock| VsockEndpoint::new(layout.host_view(&vsock.uds_path)));
    let quiesced = matches!(info.state, InstanceInfoState::Paused);
    Ok(Box::new(FcHandle::new(
        process, client, layout, record, vsock, quiesced,
    )))
}

/// The instance's state and its devices — what a full handle is built from.
async fn describe(client: &Client) -> crate::error::Result<(InstanceInfo, FullVmConfiguration)> {
    let info = api::describe(client).await?;
    let devices = api::vm_config(client).await?;
    Ok((info, devices))
}

/// The fallback, and the warning that says why: the VM stays a process
/// this driver can kill, and nothing more.
fn process_only(process: Arc<FcProcess>, record: VmRecord, why: &str) -> Box<dyn VmHandle> {
    tracing::warn!(vm = %record.id, pid = process.pid(), socket = %process.api_socket().display(),
        "the adopted vmm's api did not answer ({why}); adopting the process alone: kill-able, nothing else");
    Box::new(FcProcessHandle::new(process, record))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use arcbox_vm_driver::{IsolationSpec, ShutdownMode, VmId, VmState};

    use super::*;
    use crate::NAME;
    use crate::api::fake_fc::FakeFc;
    use crate::process::UNKNOWN_EXIT;

    /// A `sleep` child standing in for the orphan, its `Found`, and the
    /// record the sweep would hand over — a stale pid, no socket.
    fn orphan(api_socket: PathBuf, runtime_dir: &Path) -> (tokio::process::Child, Found, VmRecord) {
        let child = tokio::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn test child");
        let found = Found {
            pid: child.id().unwrap(),
            api_socket,
            isolation: IsolationSpec::None,
        };
        let record = VmRecord {
            id: VmId::new("box").unwrap(),
            driver: NAME.to_owned(),
            runtime_dir: runtime_dir.to_path_buf(),
            process: Some(ProcessRecord {
                pid: u32::try_from(i32::MAX - 1).unwrap(),
                api_socket: None,
            }),
        };
        (child, found, record)
    }

    fn config() -> FcDriverConfig {
        FcDriverConfig::new("/opt/fc/firecracker")
    }

    /// Kills through the handle and proves the child was reaped by it.
    async fn kill_through(vm: &dyn VmHandle, mut child: tokio::process::Child) {
        let reaper = tokio::spawn(async move { child.wait().await.unwrap() });
        assert_eq!(vm.shutdown(ShutdownMode::Kill).await.unwrap(), UNKNOWN_EXIT);
        assert_eq!(vm.state(), VmState::Exited(UNKNOWN_EXIT));
        use std::os::unix::process::ExitStatusExt as _;
        assert_eq!(reaper.await.unwrap().signal(), Some(9));
    }

    #[tokio::test]
    async fn an_orphan_whose_api_socket_is_missing_is_adopted_by_its_process() {
        let dir = tempfile::tempdir().unwrap();
        let (child, found, record) = orphan(dir.path().join("absent.sock"), dir.path());
        let pid = found.pid;
        let vm = rebuild(&config(), found, &record, API_TIMEOUT)
            .await
            .expect("a verified process is adopted whatever its api does");
        assert_eq!(vm.state(), VmState::Running);
        // The record names the process that was verified, not the stale one.
        let process = vm.record().process.unwrap();
        assert_eq!(process.pid, pid);
        assert_eq!(process.api_socket, Some(dir.path().join("absent.sock")));
        assert!(vm.vsock().is_none() && vm.vsock_listener().is_none());
        assert!(vm.checkpoint().is_none());
        assert!(vm.detach().is_some());
        kill_through(&*vm, child).await;
    }

    #[tokio::test]
    async fn an_orphan_whose_api_hangs_is_adopted_within_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        // A socket that accepts and never answers: the VMM's API thread is
        // wedged, or something else squats on the path.
        let socket = dir.path().join("wedged.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let sink = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                // Held open and never answered, for as long as the runtime.
                tokio::spawn(async move {
                    let _held = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        let (child, found, record) = orphan(socket, dir.path());
        let bound = Duration::from_millis(300);
        let started = tokio::time::Instant::now();
        let vm = rebuild(&config(), found, &record, bound)
            .await
            .expect("a wedged api does not fail the adopt");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "settled for the process within the bound, not the hang"
        );
        assert!(vm.vsock().is_none() && vm.checkpoint().is_none());
        kill_through(&*vm, child).await;
        sink.abort();
    }

    #[tokio::test]
    async fn a_vmm_that_answers_is_adopted_with_its_devices_and_state() {
        let dir = tempfile::tempdir().unwrap();
        // The vsock is where Firecracker says it bound it — after a restore
        // the checkpoint's recorded path, not this runtime dir's.
        let recorded = dir.path().join("source").join("firecracker.vsock");
        std::fs::create_dir_all(recorded.parent().unwrap()).unwrap();
        let devices = format!(
            r#"{{"vsock":{{"guest_cid":3,"uds_path":"{}"}}}}"#,
            recorded.display()
        );
        let fc = FakeFc::start(dir.path(), move |route, _| match route {
            "GET /" => (
                200,
                r#"{"app_name":"fake","id":"box","state":"Paused","vmm_version":"1.10.1"}"#.into(),
            ),
            "GET /vm/config" => (200, devices.clone()),
            other => panic!("the driver called {other} unexpectedly"),
        });
        let (child, found, record) = orphan(fc.socket().to_path_buf(), dir.path());
        let vm = rebuild(&config(), found, &record, API_TIMEOUT)
            .await
            .expect("adopt");
        assert_eq!(fc.calls(), ["GET /", "GET /vm/config"]);
        // The full handle: the paused state and the vsock device read back.
        assert_eq!(vm.state(), VmState::Quiesced);
        assert!(vm.vsock().is_some() && vm.detach().is_some());
        let listener = vm.vsock_listener().unwrap().listen(51).await.unwrap();
        assert!(dir.path().join("source/firecracker.vsock_51").exists());
        drop(listener);
        kill_through(&*vm, child).await;
    }
}
