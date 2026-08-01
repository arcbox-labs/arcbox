//! The daemon's control-plane socket: two RPC stacks, one endpoint.
//!
//! The sandbox API is served over Connect (CORE-53), and the daemon's own
//! services are moving there too, one at a time (CORE-68); whatever has not
//! moved yet is still on tonic. Both are `tower` services over HTTP, so they
//! compose into one axum router and share a single Unix socket: tonic
//! registers a route per service name, and anything it does not claim falls
//! through to the Connect handlers. A client therefore reaches every service
//! at the same address, and no path prefix has to be kept in sync by hand.
//!
//! Registration is what decides which stack serves a path. tonic matches
//! first, so a service listed on both would keep answering over tonic alone
//! — migrating a service means removing it from `Routes` in the same change
//! that adds it to the Connect router.
//!
//! Connections are served with hyper's protocol-detecting builder rather
//! than tonic's HTTP/2-only server, which is what makes the acceptance
//! criterion reachable: gRPC clients arrive over HTTP/2 while
//! `curl --unix-socket` posting JSON arrives over HTTP/1.1, and the same
//! handlers answer both.

use anyhow::{Context, Result};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

/// Concurrent HTTP/2 streams allowed per client connection.
///
/// tonic's server left this unlimited; hyper's builder defaults it to 200.
/// Keeping a cap is deliberate — a desktop client multiplexes every watch,
/// exec, and read stream over one connection, and a stream leak there
/// should back-pressure that client instead of growing the daemon without
/// bound — but the number is pinned here so it is a decision rather than
/// an inherited default.
const MAX_HTTP2_STREAMS: u32 = 200;

/// Accepts connections on `listener` until `shutdown` fires, serving `app`.
///
/// Returns once every in-flight connection has finished, so the socket is
/// free before the daemon drops its lock.
pub async fn serve(listener: UnixListener, app: axum::Router, shutdown: CancellationToken) {
    let graceful = GracefulShutdown::new();
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http2().max_concurrent_streams(MAX_HTTP2_STREAMS);

    loop {
        let stream = tokio::select! {
            () = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _addr)) => stream,
                Err(e) => {
                    // A single failed accept (EMFILE, a client that vanished
                    // between the SYN and the accept) must not take the
                    // control plane down with it.
                    debug!(error = %e, "control-plane accept failed");
                    continue;
                }
            },
        };

        let service = TowerToHyperService::new(app.clone());
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
        let conn = graceful.watch(conn.into_owned());
        drop(tokio::spawn(async move {
            if let Err(e) = conn.await {
                debug!(error = %e, "control-plane connection ended");
            }
        }));
    }

    info!("control plane draining in-flight connections");
    graceful.shutdown().await;
}

/// Binds the control-plane Unix socket, replacing any stale one.
///
/// Each server owns its socket (remove-before-bind) rather than relying on
/// a central cleanup pass, so a crashed predecessor cannot block startup.
pub fn bind(socket_path: &std::path::Path) -> Result<UnixListener> {
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create socket directory")?;
    }
    UnixListener::bind(socket_path).context(format!(
        "Failed to bind gRPC socket: {}",
        socket_path.display()
    ))
}

/// Composes the tonic services and the Connect services into one router.
///
/// `tonic` claims `/{service}/{method}` for each service registered on it;
/// the Connect router is the fallback, so it receives exactly the paths
/// tonic does not serve. Adding a service to either side needs no change
/// here.
pub fn compose(tonic_routes: tonic::service::Routes, connect: connectrpc::Router) -> axum::Router {
    tonic_routes
        // Lets axum flatten its route table once instead of per request.
        .prepare()
        .into_axum_router()
        .fallback_service(connect.into_axum_service())
}

/// Builds the Connect half: every service already migrated, plus reflection.
///
/// Reflection is served here rather than by tonic so that one
/// implementation covers gRPC, gRPC-Web, and Connect alike. Both `v1` and
/// the legacy `v1alpha` are registered, since `grpcurl` still asks for
/// `v1alpha` by default.
///
/// One limit is worth knowing before chasing it: `ServerReflectionInfo` is
/// bidi-streaming, and the Connect protocol carries bidi streams only over
/// HTTP/2. A plain HTTP/1.1 Connect client therefore gets `501` from
/// reflection — a property of that RPC's shape, not of this wiring. Unary
/// calls are unaffected, which is why `curl --unix-socket` still works for
/// the services themselves.
///
/// The descriptor set is the whole daemon's, not just the sandbox package:
/// it is standard protobuf wire bytes, so the same set `arcbox-grpc` emits
/// for its prost build describes every service either stack serves.
///
/// # Errors
///
/// Returns an error if the embedded descriptor set cannot be parsed, which
/// would mean the build emitted a corrupt one.
pub fn connect_router(
    runtime: arcbox_api::SharedRuntime,
    system: arcbox_api::SystemServiceImpl,
) -> Result<connectrpc::Router> {
    let reflector = connectrpc_reflection::Reflector::from_descriptor_set_bytes(
        arcbox_grpc::FILE_DESCRIPTOR_SET,
    )
    .context("parsing the embedded file descriptor set for reflection")?;
    Ok(connectrpc_reflection::install(
        arcbox_api::connect::router_with_system(runtime, system),
        reflector,
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::UnixStream;

    use super::*;

    /// Brings up the real composed control plane on a temp socket.
    ///
    /// The runtime handle is deliberately left empty: every sandbox call
    /// then answers `unavailable`, which is enough to prove the transport —
    /// the assertions below are about which wire formats reach a handler and
    /// how its error comes back, not about sandbox behaviour. Keeping it
    /// VM-free is what lets this run in CI.
    async fn spawn_control_plane() -> (tempfile::TempDir, std::path::PathBuf, CancellationToken) {
        let dir = tempfile::tempdir().expect("temp dir");
        let socket = dir.path().join("arcbox.sock");
        let runtime: arcbox_api::SharedRuntime = Arc::new(OnceLock::new());

        // The Connect half is built by the same function the daemon uses, so
        // a service or reflection wired up only in production would fail
        // here too.
        let system = arcbox_api::SystemServiceImpl::new(
            Arc::new(arcbox_api::SetupState::new()),
            Arc::clone(&runtime),
            Arc::clone(&runtime),
        );
        let connect = connect_router(runtime, system).expect("connect router");
        let app = compose(tonic::service::Routes::default(), connect);

        let listener = bind(&socket).expect("bind temp socket");
        let shutdown = CancellationToken::new();
        drop(tokio::spawn(serve(listener, app, shutdown.clone())));
        (dir, socket, shutdown)
    }

    /// Issues a raw HTTP/1.1 request and returns the whole response.
    ///
    /// Written at the byte level on purpose: this is exactly what
    /// `curl --unix-socket` puts on the wire, so a pass here is the
    /// "callers with no proto toolchain can reach us" claim, not a
    /// client-library artifact.
    async fn http1_request(socket: &std::path::Path, request: &str) -> String {
        let mut stream = UnixStream::connect(socket).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");

        let mut response = Vec::new();
        // The daemon keeps HTTP/1.1 connections alive, so read only until
        // the body arrives rather than to EOF. Transport failures panic
        // with their own message here — otherwise they surface as a JSON
        // parse error on an empty body, which points at the one thing that
        // is not broken.
        let deadline = std::time::Duration::from_secs(5);
        tokio::time::timeout(deadline, async {
            let mut buf = [0u8; 4096];
            loop {
                let n = stream.read(&mut buf).await.expect("read response");
                if n == 0 {
                    break;
                }
                response.extend_from_slice(&buf[..n]);
                if response.windows(4).any(|w| w == b"\r\n\r\n")
                    && String::from_utf8_lossy(&response).contains('}')
                {
                    break;
                }
            }
        })
        .await
        .expect("daemon did not answer within 5s");
        String::from_utf8_lossy(&response).into_owned()
    }

    /// Reassembles a `Transfer-Encoding: chunked` body from a raw response.
    ///
    /// The handler has no Content-Length to declare (the body is produced as
    /// it is encoded), so hyper chunks it — the same framing any streaming
    /// HTTP/1.1 response carries. Real clients handle this transparently;
    /// this test reads the socket directly, so it has to.
    fn dechunk(response: &str) -> String {
        let Some((_, mut rest)) = response.split_once("\r\n\r\n") else {
            return String::new();
        };
        let mut body = String::new();
        while let Some((size, tail)) = rest.split_once("\r\n") {
            let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
                break;
            };
            if size == 0 || tail.len() < size {
                break;
            }
            body.push_str(&tail[..size]);
            rest = tail[size..].trim_start_matches("\r\n");
        }
        body
    }

    /// The acceptance criterion for CORE-53: one endpoint, three formats.
    ///
    /// All three target the same path on the same socket. A format that
    /// reached no handler would surface as a 404 or a connection reset
    /// rather than a service-level `unavailable`.
    #[tokio::test]
    async fn one_endpoint_answers_connect_grpc_and_grpc_web() {
        let (_dir, socket, shutdown) = spawn_control_plane().await;
        let path = "/arcbox.sandbox.v1.SandboxService/List";

        // 1. Connect, JSON over HTTP/1.1 — the `curl` case.
        let response = http1_request(
            &socket,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
                 Content-Length: 2\r\n\r\n{{}}"
            ),
        )
        .await;
        assert!(
            response.contains("HTTP/1.1 503"),
            "Connect JSON should map unavailable to HTTP 503, got: {response}"
        );
        let body = dechunk(&response);
        let json: serde_json::Value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("Connect errors are a JSON body: {e}; got {body:?}"));
        assert_eq!(
            json.get("code").and_then(serde_json::Value::as_str),
            Some("unavailable"),
            "Connect puts the error code in the JSON body: {json}"
        );

        // 2. gRPC over HTTP/2 — the generated tonic client, unchanged.
        let channel = tonic::transport::Endpoint::try_from("http://localhost")
            .expect("endpoint")
            .connect_with_connector(tower::service_fn({
                let socket = socket.clone();
                move |_: tonic::transport::Uri| {
                    let socket = socket.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket).await?))
                    }
                }
            }))
            .await
            .expect("gRPC connect over the same socket");
        let status = arcbox_grpc::SandboxServiceClient::new(channel)
            .list(tonic::Request::new(
                arcbox_grpc::arcbox_protocol::sandbox_v1::ListSandboxesRequest::default(),
            ))
            .await
            .expect_err("empty runtime is unavailable");
        assert_eq!(
            status.code(),
            tonic::Code::Unavailable,
            "gRPC must reach the same handler and carry the same code"
        );

        // 3. gRPC-Web over HTTP/1.1 — a 5-byte-prefixed empty message.
        let body = [0u8, 0, 0, 0, 0];
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/grpc-web+proto\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(&body);
        let mut stream = UnixStream::connect(&socket).await.expect("connect");
        stream.write_all(&request).await.expect("write");
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut response),
        )
        .await;
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.contains("HTTP/1.1 200"),
            "gRPC-Web carries its status in the body, not the HTTP status: {response}"
        );
        assert!(
            response.contains("grpc-status: 14") || response.contains("grpc-status:14"),
            "gRPC-Web trailers should report unavailable: {response}"
        );

        shutdown.cancel();
    }

    /// CORE-68 moves the daemon's own services onto the Connect router one
    /// at a time. Registration is what decides which stack serves a path —
    /// tonic matches first, so a service left on both would silently keep
    /// answering over tonic only. Asserting the route directly is hermetic;
    /// driving Icon end-to-end would reach the network.
    #[test]
    fn migrated_daemon_services_are_registered_on_the_connect_router() {
        let runtime: arcbox_api::SharedRuntime = Arc::new(OnceLock::new());
        let system = arcbox_api::SystemServiceImpl::new(
            Arc::new(arcbox_api::SetupState::new()),
            Arc::clone(&runtime),
            Arc::clone(&runtime),
        );
        let router = connect_router(runtime, system).expect("connect router");

        for path in [
            "arcbox.v1.IconService/GetImageIcon",
            "arcbox.v1.StatsService/Watch",
            "arcbox.v1.SystemService/WatchSetupStatus",
            "arcbox.v1.KubernetesService/Status",
            "arcbox.v1.MigrationService/RunMigration",
            "arcbox.v1.MachineService/ExecSession",
        ] {
            assert!(
                router.has_method(path),
                "{path} has moved to Connect; available: {:?}",
                router.methods().collect::<Vec<_>>()
            );
        }
    }

    /// Reflection has to keep answering through the composed router, or
    /// `grpcurl` and `buf curl` lose the ability to discover the API without
    /// vendoring the protos.
    #[tokio::test]
    async fn reflection_answers_through_the_composed_router() {
        let (_dir, socket, shutdown) = spawn_control_plane().await;

        let channel = tonic::transport::Endpoint::try_from("http://localhost")
            .expect("endpoint")
            .connect_with_connector(tower::service_fn({
                let socket = socket.clone();
                move |_: tonic::transport::Uri| {
                    let socket = socket.clone();
                    async move {
                        Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(socket).await?))
                    }
                }
            }))
            .await
            .expect("connect");

        let mut client =
            tonic_reflection::pb::v1::server_reflection_client::ServerReflectionClient::new(
                channel,
            );
        let request = tonic_reflection::pb::v1::ServerReflectionRequest {
            host: String::new(),
            message_request: Some(
                tonic_reflection::pb::v1::server_reflection_request::MessageRequest::ListServices(
                    String::new(),
                ),
            ),
        };
        let mut stream = client
            .server_reflection_info(tokio_stream::iter(vec![request]))
            .await
            .expect("reflection call")
            .into_inner();

        let response = tokio_stream::StreamExt::next(&mut stream)
            .await
            .expect("a reflection response")
            .expect("reflection is not an error");
        let services = match response.message_response {
            Some(tonic_reflection::pb::v1::server_reflection_response::MessageResponse::ListServicesResponse(r)) => r.service,
            other => panic!("expected a service listing, got {other:?}"),
        };
        let names: Vec<_> = services.into_iter().map(|s| s.name).collect();
        assert!(
            names
                .iter()
                .any(|n| n == "arcbox.sandbox.v1.SandboxService"),
            "the sandbox services must stay discoverable: {names:?}"
        );

        shutdown.cancel();
    }
}
