//! Minimal mock guest dockerd for proxy and handler integration tests.
//!
//! A hyper HTTP/1.1 server on a Unix socket that handles:
//! - Requests matching a canned route: returns the configured status + body
//! - Other normal requests: returns status 200 with the request body echoed
//! - Upgrade requests (`Upgrade` header present): returns 101 and acts
//!   as a simple echo server, sending back any data received on the
//!   upgraded connection
//!
//! The server runs until the returned [`CancellationToken`] is cancelled.

use arcbox_docker::proxy::{GuestConnector, VsockShutdown, VsockStream};
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Test connector that dials the mock guest's Unix socket, standing in for
/// the production vsock connector. `connect_count` lets pooling tests assert
/// session reuse.
#[derive(Clone)]
pub struct UnixSocketConnector {
    pub socket_path: PathBuf,
    pub connect_count: Arc<AtomicUsize>,
}

impl UnixSocketConnector {
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            connect_count: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl GuestConnector for UnixSocketConnector {
    fn connect(
        &self,
    ) -> Pin<Box<dyn Future<Output = arcbox_docker::Result<TokioIo<VsockStream>>> + Send + '_>>
    {
        Box::pin(async {
            self.connect_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let stream = tokio::net::UnixStream::connect(&self.socket_path)
                .await
                .map_err(|e| arcbox_docker::DockerError::Server(e.to_string()))?;
            Ok(TokioIo::new(VsockStream::from_unix_stream_with_shutdown(
                stream,
                VsockShutdown::CloseOnDropOnly,
            )))
        })
    }
}

/// A canned response served for an exact (method, version-stripped path)
/// match. `path` excludes the query string.
pub struct MockRoute {
    pub method: &'static str,
    pub path: &'static str,
    pub status: u16,
    pub body: &'static str,
}

/// Handle returned by [`start`] to interact with the mock server.
pub struct MockGuest {
    pub socket_path: PathBuf,
    /// Stops the server task. Suites that simply drop the guest at test end
    /// never read it, hence the per-test-crate dead_code allowance.
    #[allow(dead_code)]
    pub cancel: CancellationToken,
    /// Body received on the most recent upgrade request (if any).
    last_upgrade_body: Arc<Mutex<Option<Bytes>>>,
}

impl MockGuest {
    /// Returns the body received on the most recent upgrade request.
    #[allow(dead_code)] // used by the proxy_integration suite only
    pub async fn last_upgrade_body(&self) -> Option<Bytes> {
        self.last_upgrade_body.lock().await.clone()
    }
}

/// Start a mock guest dockerd listening on a Unix socket (echo behavior).
#[allow(dead_code)] // used by the proxy_integration suite only
pub async fn start(dir: &Path) -> MockGuest {
    start_with_routes(dir, Vec::new()).await
}

/// Start a mock guest dockerd that serves canned responses for the given
/// routes, echoing everything else.
pub async fn start_with_routes(dir: &Path, routes: Vec<MockRoute>) -> MockGuest {
    let socket_path = dir.join("mock-guest.sock");
    let listener = UnixListener::bind(&socket_path).expect("bind mock guest socket");
    let cancel = CancellationToken::new();
    let token = cancel.clone();
    let last_upgrade_body: Arc<Mutex<Option<Bytes>>> = Arc::new(Mutex::new(None));
    let body_slot = Arc::clone(&last_upgrade_body);
    let routes = Arc::new(routes);

    tokio::spawn(async move {
        loop {
            let stream = tokio::select! {
                result = listener.accept() => match result {
                    Ok((s, _)) => s,
                    Err(_) => break,
                },
                () = token.cancelled() => break,
            };

            let slot = Arc::clone(&body_slot);
            let routes = Arc::clone(&routes);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let slot = Arc::clone(&slot);
                    let routes = Arc::clone(&routes);
                    handle(req, slot, routes)
                });
                let _ = http1::Builder::new()
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await;
            });
        }
    });

    MockGuest {
        socket_path,
        cancel,
        last_upgrade_body,
    }
}

/// Strips a `/v{major}.{minor}` Docker API version prefix, mirroring what
/// real dockerd accepts (the proxy forwards the original versioned URI).
fn strip_version_prefix(path: &str) -> &str {
    let Some(after_v) = path.strip_prefix("/v") else {
        return path;
    };
    let Some(slash) = after_v.find('/') else {
        return path;
    };
    let version = &after_v[..slash];
    let (major, minor) = match version.split_once('.') {
        Some(parts) => parts,
        None => return path,
    };
    if !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
    {
        &after_v[slash..]
    } else {
        path
    }
}

async fn handle(
    mut req: Request<Incoming>,
    upgrade_body_slot: Arc<Mutex<Option<Bytes>>>,
    routes: Arc<Vec<MockRoute>>,
) -> std::result::Result<Response<http_body_util::Full<Bytes>>, hyper::Error> {
    // Canned routes take precedence over echo behavior.
    let path = strip_version_prefix(req.uri().path()).to_owned();
    if let Some(route) = routes
        .iter()
        .find(|r| r.method == req.method().as_str() && r.path == path)
    {
        let resp = Response::builder()
            .status(StatusCode::from_u16(route.status).expect("valid mock status"))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(http_body_util::Full::new(Bytes::from_static(
                route.body.as_bytes(),
            )))
            .unwrap();
        return Ok(resp);
    }
    let wants_upgrade = req.headers().contains_key(hyper::header::UPGRADE);

    if wants_upgrade {
        let upgrade_proto = req
            .headers()
            .get(hyper::header::UPGRADE)
            .cloned()
            .unwrap_or_else(|| hyper::header::HeaderValue::from_static("tcp"));

        // Collect the request body before the upgrade so tests can verify
        // that the proxy forwarded it.
        let body_bytes = http_body_util::BodyExt::collect(req.body_mut())
            .await
            .ok()
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        *upgrade_body_slot.lock().await = Some(body_bytes);

        tokio::spawn(async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let mut io = TokioIo::new(upgraded);
                    let (mut rd, mut wr) = tokio::io::split(&mut io);
                    let _ = tokio::io::copy(&mut rd, &mut wr).await;
                }
                Err(e) => tracing::debug!("mock guest upgrade failed: {e}"),
            }
        });

        let resp = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(hyper::header::CONNECTION, "Upgrade")
            .header(hyper::header::UPGRADE, upgrade_proto)
            .body(http_body_util::Full::default())
            .unwrap();
        return Ok(resp);
    }

    // Normal request: echo the body back with 200.
    let body_bytes = http_body_util::BodyExt::collect(req.into_body())
        .await?
        .to_bytes();

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(http_body_util::Full::new(body_bytes))
        .unwrap();
    Ok(resp)
}
