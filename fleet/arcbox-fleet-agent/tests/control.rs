//! End-to-end test of the local control-plane API.
//!
//! `arcbox-fleet-agent` ships only a binary (no library target), so this
//! spawns the real compiled `serve` subcommand against a scratch data dir
//! and exercises `FleetLifecycleService` over the real Unix socket — the
//! same path the CLI's `enroll`/`status`/`drain`/`resume`/`unenroll` subcommands
//! and the desktop app use.

#![allow(
    clippy::float_cmp,
    reason = "settings values are moved/copied here, never computed, so exact \
              float equality is always well-defined — no rounding can occur"
)]

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arcbox_fleet_control_proto::v1::fleet_image_service_client::FleetImageServiceClient;
use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_client::FleetLifecycleServiceClient;
use arcbox_fleet_control_proto::v1::fleet_settings_service_client::FleetSettingsServiceClient;
use arcbox_fleet_control_proto::v1::fleet_state_service_client::FleetStateServiceClient;
use arcbox_fleet_control_proto::v1::{
    ConnectionState, DockerMode, DrainRequest, Enrollment, GetAgentInfoRequest, GetSettingsRequest,
    GetStatusRequest, PrepareRequest, UpdateSettingsRequest, WatchRequest,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::codegen::{Service, http::Uri};
use tonic::transport::{Channel, Endpoint};

/// Kills the spawned agent on drop, so a failing assertion can't leak it.
struct AgentProcess(Child);

impl Drop for AgentProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct TestUnixConnector(PathBuf);

impl Service<Uri> for TestUnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let path = self.0.clone();
        Box::pin(async move { Ok(TokioIo::new(UnixStream::connect(path).await?)) })
    }
}

async fn connect(socket_path: &Path) -> Channel {
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(TestUnixConnector(socket_path.to_path_buf()))
        .await
        .expect("connect to control socket")
}

/// Poll for `agent.sock` to appear, failing fast (with the exit status) if
/// the agent process dies before it does.
fn wait_for_socket(child: &mut Child, socket_path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if socket_path.exists() {
            return;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("agent exited before binding its control socket: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "agent.sock never appeared within the deadline"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[tokio::test]
async fn unenrolled_agent_reports_status_and_rejects_drain() {
    let data_dir = std::env::temp_dir().join(format!("fleet-agent-control-{}", std::process::id()));
    std::fs::create_dir_all(&data_dir).unwrap();
    let socket_path = data_dir.join("agent.sock");

    let mut agent = AgentProcess(
        Command::new(env!("CARGO_BIN_EXE_arcbox-fleet-agent"))
            .arg("serve")
            .env("ARCBOX_FLEET_DATA_DIR", &data_dir)
            // Forced to the file backend so this never touches the real OS
            // keychain; nothing listens on this gateway, but the Unenrolled
            // state this test exercises never dials out to it.
            .env("ARCBOX_FLEET_CREDENTIAL_STORE", "file")
            .env("ARCBOX_FLEET_GATEWAY", "http://127.0.0.1:1")
            .env("ARCBOX_FLEET_DOCKER", "false")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn arcbox-fleet-agent"),
    );

    wait_for_socket(&mut agent.0, &socket_path);
    let channel = connect(&socket_path).await;
    let mut client = FleetLifecycleServiceClient::new(channel.clone());
    let mut settings_client = FleetSettingsServiceClient::new(channel.clone());

    let info = client
        .get_agent_info(GetAgentInfoRequest {})
        .await
        .expect("GetAgentInfo")
        .into_inner();
    assert_eq!(info.agent_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(info.api_version, 1);

    let status = client
        .get_status(GetStatusRequest {})
        .await
        .expect("GetStatus")
        .into_inner();
    assert_eq!(
        ConnectionState::try_from(status.state).unwrap(),
        ConnectionState::Unenrolled
    );
    assert_eq!(status.machine_id, "");

    // FleetStateService.Watch: the client holds no state of its own, so the
    // very first message must already be a full, current snapshot — not
    // require a change to happen first.
    let mut watch_client = FleetStateServiceClient::new(channel.clone());
    let mut stream = watch_client
        .watch(WatchRequest {})
        .await
        .expect("Watch RPC")
        .into_inner();
    let snapshot = stream
        .message()
        .await
        .expect("watch stream")
        .expect("initial snapshot")
        .snapshot
        .expect("snapshot present");
    assert_eq!(
        Enrollment::try_from(snapshot.enrollment).unwrap(),
        Enrollment::Unenrolled
    );
    assert_eq!(snapshot.machine_id, "");
    assert!(snapshot.capabilities.is_empty());
    assert!(snapshot.in_flight.is_empty());
    assert!(snapshot.recent_verdicts.is_empty());

    // FleetSettingsService.GetSettings: a fresh agent reports current ==
    // target everywhere, seeded from its env configuration.
    let settings = settings_client
        .get_settings(GetSettingsRequest {})
        .await
        .expect("GetSettings")
        .into_inner()
        .settings
        .expect("settings present");
    let load_ceiling = settings.load_ceiling.expect("load_ceiling present");
    assert_eq!(load_ceiling.current, 0.9);
    assert_eq!(load_ceiling.current, load_ceiling.target);
    assert_eq!(
        settings
            .mem_floor_mib
            .expect("mem_floor_mib present")
            .current,
        2048
    );
    assert_eq!(
        settings.gateway.expect("gateway present").current,
        "http://127.0.0.1:1"
    );
    let docker_mode = settings.docker_mode.expect("docker_mode present");
    assert_eq!(
        DockerMode::try_from(docker_mode.current).unwrap(),
        DockerMode::Disabled
    );
    assert_eq!(docker_mode.current, docker_mode.target);
    let runner_script = settings.runner_script.expect("runner_script present");
    assert_eq!(runner_script.current, "");
    assert_eq!(runner_script.current, runner_script.target);
    let participate = settings.participate.expect("participate present");
    assert!(participate.current);
    assert!(participate.target);

    // UpdateSettings: load_ceiling applies instantly — current and target
    // both move together, with no reattach or restart involved.
    let updated = settings_client
        .update_settings(UpdateSettingsRequest {
            load_ceiling: Some(0.5),
            ..Default::default()
        })
        .await
        .expect("UpdateSettings")
        .into_inner()
        .settings
        .expect("settings present");
    let load_ceiling = updated.load_ceiling.expect("load_ceiling present");
    assert_eq!(load_ceiling.current, 0.5);
    assert_eq!(load_ceiling.target, 0.5);

    // The change reaches a fresh Watch subscription without polling —
    // settings ride the same object as everything else `Watch` streams.
    let mut confirm_stream = watch_client
        .watch(WatchRequest {})
        .await
        .expect("Watch RPC")
        .into_inner();
    let confirmed = confirm_stream
        .message()
        .await
        .expect("watch stream")
        .expect("snapshot")
        .snapshot
        .expect("snapshot present");
    assert_eq!(
        confirmed
            .settings
            .expect("settings present")
            .load_ceiling
            .expect("load_ceiling present")
            .current,
        0.5
    );

    // linux_runner_image is prepare-scoped end-to-end: UpdateSettings moves
    // only `target`; FleetImageService.Prepare is what promotes it. This
    // agent runs with Docker disabled, so preparation has nothing to verify
    // the image against and promotes directly ("skipped" then "promoted").
    let updated = settings_client
        .update_settings(UpdateSettingsRequest {
            linux_runner_image: Some("ghcr.io/acme/runner:v2".to_owned()),
            ..Default::default()
        })
        .await
        .expect("UpdateSettings")
        .into_inner()
        .settings
        .expect("settings present")
        .linux_runner_image
        .expect("linux_runner_image present");
    assert_eq!(updated.current, "ghcr.io/actions/actions-runner:latest");
    assert_eq!(updated.target, "ghcr.io/acme/runner:v2");

    let mut image_client = FleetImageServiceClient::new(channel);
    let mut prepare = image_client
        .prepare(PrepareRequest { kinds: Vec::new() })
        .await
        .expect("Prepare RPC")
        .into_inner();
    let mut stages = Vec::new();
    while let Some(event) = prepare.message().await.expect("prepare stream") {
        stages.push(event.stage);
    }
    // Empty kinds expand to every kind this host supports — the Linux image
    // everywhere, plus the macOS image on macOS hosts. With neither runtime
    // configured each kind is skipped and promoted.
    let expected: &[&str] = if cfg!(target_os = "macos") {
        &["skipped", "promoted", "skipped", "promoted"]
    } else {
        &["skipped", "promoted"]
    };
    assert_eq!(stages, expected);

    let prepared = settings_client
        .get_settings(GetSettingsRequest {})
        .await
        .expect("GetSettings")
        .into_inner()
        .settings
        .expect("settings present")
        .linux_runner_image
        .expect("linux_runner_image present");
    assert_eq!(prepared.current, "ghcr.io/acme/runner:v2");
    assert_eq!(prepared.current, prepared.target);

    // participate rides the same settings surface, target-only: the
    // supervisor's reconciler realizes it. Unenrolled, there is nothing to
    // detach, so `current` follows the target trivially — but still
    // asynchronously (the reconciler observes the watch channel), so poll
    // briefly rather than assume ordering.
    let updated = settings_client
        .update_settings(UpdateSettingsRequest {
            participate: Some(false),
            ..Default::default()
        })
        .await
        .expect("UpdateSettings")
        .into_inner()
        .settings
        .expect("settings present")
        .participate
        .expect("participate present");
    assert!(!updated.target);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let participate = settings_client
            .get_settings(GetSettingsRequest {})
            .await
            .expect("GetSettings")
            .into_inner()
            .settings
            .expect("settings present")
            .participate
            .expect("participate present");
        if !participate.current {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "reconciler never realized participate=false on an unenrolled agent"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Safety invariant enforced end-to-end: this agent already has
    // docker_mode=Disabled and no runner_script (its env-derived seed —
    // a legitimate Docker-only farm shape), so a request that explicitly
    // touches docker_mode without also supplying a runner_script is
    // rejected rather than silently leaving the host serving nothing.
    let unsafe_err = settings_client
        .update_settings(UpdateSettingsRequest {
            docker_mode: Some(DockerMode::Disabled as i32),
            ..Default::default()
        })
        .await
        .expect_err("should reject docker_mode=disabled with no runner_script");
    assert_eq!(unsafe_err.code(), tonic::Code::InvalidArgument);

    let drain_err = client
        .drain(DrainRequest {})
        .await
        .expect_err("Drain should fail while unenrolled");
    assert_eq!(drain_err.code(), tonic::Code::FailedPrecondition);

    drop(agent);
    let _ = std::fs::remove_dir_all(&data_dir);
}
