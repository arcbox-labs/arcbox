//! End-to-end test of the local control-plane API.
//!
//! `arcbox-fleet-agent` ships only a binary (no library target), so this
//! spawns the real compiled `run` binary against a scratch data dir and
//! exercises `FleetLifecycleService` over the real Unix socket — the same
//! path the CLI's `status`/`drain`/`resume`/`disconnect` subcommands and the
//! desktop app use.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_client::FleetLifecycleServiceClient;
use arcbox_fleet_control_proto::v1::{
    ConnectionState, DrainRequest, GetAgentInfoRequest, GetStatusRequest,
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

async fn connect(socket_path: &Path) -> FleetLifecycleServiceClient<Channel> {
    let channel = Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(TestUnixConnector(socket_path.to_path_buf()))
        .await
        .expect("connect to control socket");
    FleetLifecycleServiceClient::new(channel)
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
            .arg("run")
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
    let mut client = connect(&socket_path).await;

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

    let drain_err = client
        .drain(DrainRequest {})
        .await
        .expect_err("Drain should fail while unenrolled");
    assert_eq!(drain_err.code(), tonic::Code::FailedPrecondition);

    drop(agent);
    let _ = std::fs::remove_dir_all(&data_dir);
}
