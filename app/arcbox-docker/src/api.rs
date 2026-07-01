//! Docker API router.
//!
//! Implements Docker Engine API routing for all versions. Version prefixes
//! (e.g. `/v1.51/...`) are stripped by [`strip_api_version_prefix`] before
//! requests reach the Axum router, so a single set of unversioned routes
//! handles every API version.
//! See: <https://docs.docker.com/engine/api/>

use crate::handlers;
use crate::proxy;
use crate::proxy::{GuestConnector, GuestHttpClient};
use crate::trace::trace_id_middleware;
use arcbox_core::Runtime;
use axum::extract::OriginalUri;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::{
    Router, middleware,
    routing::{delete, post},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;

/// Application state shared with handlers.
#[derive(Clone)]
pub struct AppState {
    /// `ArcBox` runtime.
    pub runtime: Arc<Runtime>,
    /// Guest proxy transport state.
    pub proxy: Arc<ProxyState>,
}

/// Guest proxy transport state shared by handlers.
pub struct ProxyState {
    connector: Arc<dyn GuestConnector>,
    guest_http_client: GuestHttpClient,
    endpoint_readiness: EndpointReadiness,
}

impl ProxyState {
    fn new(connector: Arc<dyn GuestConnector>) -> Self {
        Self {
            guest_http_client: GuestHttpClient::new(Arc::clone(&connector)),
            connector,
            endpoint_readiness: EndpointReadiness::new(),
        }
    }

    pub(crate) fn connector(&self) -> &dyn GuestConnector {
        self.connector.as_ref()
    }

    pub(crate) fn client(&self) -> &GuestHttpClient {
        &self.guest_http_client
    }

    /// Ensures guest dockerd is reachable at the Docker HTTP layer.
    ///
    /// The supplied `prepare_runtime` future owns the slow VM/agent/runtime
    /// readiness path. This proxy state owns the cheaper HTTP `_ping`
    /// verification and caches it until a transport failure invalidates it.
    ///
    /// `generation` is the System VM's current incarnation counter. When it
    /// changes — the VM restarted (e.g. a backend switch) since the last call —
    /// the cached readiness and pooled connections both point at the old VM, so
    /// they are reset before verifying. Because this check is synchronous with
    /// the request, it cannot race the restart the way an out-of-band event
    /// watcher would.
    pub(crate) async fn ensure_endpoint_verified<F>(
        &self,
        generation: u64,
        prepare_runtime: F,
    ) -> crate::error::Result<()>
    where
        F: Future<Output = crate::error::Result<()>>,
    {
        if self.endpoint_readiness.observe_generation(generation) {
            // The readiness was already invalidated by `observe_generation`;
            // also drop the pooled connections, which dialed the old VM.
            self.guest_http_client.reset();
        }
        self.endpoint_readiness
            .ensure_verified(prepare_runtime, || self.ping_guest())
            .await
    }

    pub(crate) fn invalidate_endpoint(&self) {
        self.endpoint_readiness.invalidate();
    }

    async fn ping_guest(&self) -> crate::error::Result<()> {
        let response = proxy::proxy_to_guest_pooled(
            &self.guest_http_client,
            Method::GET,
            "/_ping",
            &HeaderMap::new(),
            Bytes::new(),
        )
        .await?;

        let status = response.status();
        let body = BodyExt::collect(response.into_body())
            .await
            .map_err(|e| {
                crate::error::DockerError::Server(format!(
                    "failed to read guest docker _ping response: {e}"
                ))
            })?
            .to_bytes();

        if status == StatusCode::OK {
            return Ok(());
        }

        Err(crate::error::DockerError::Server(format!(
            "guest docker _ping returned {status}: {}",
            String::from_utf8_lossy(&body).trim_end()
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointReadinessState {
    Unverified,
    Verifying,
    Verified,
}

struct EndpointReadiness {
    state: Mutex<EndpointReadinessState>,
    changed: Notify,
    /// System VM incarnation this endpoint last verified against.
    generation: AtomicU64,
}

impl EndpointReadiness {
    fn new() -> Self {
        Self {
            state: Mutex::new(EndpointReadinessState::Unverified),
            changed: Notify::new(),
            generation: AtomicU64::new(0),
        }
    }

    /// Records the current VM incarnation and, when it differs from the last
    /// one seen (the System VM restarted in between), invalidates the cached
    /// readiness and reports the change so the caller can drop stale pooled
    /// connections too.
    fn observe_generation(&self, generation: u64) -> bool {
        if self.generation.swap(generation, Ordering::AcqRel) == generation {
            return false;
        }
        self.invalidate();
        true
    }

    async fn ensure_verified<Prepare, Verify, VerifyFuture>(
        &self,
        prepare_runtime: Prepare,
        verify_endpoint: Verify,
    ) -> crate::error::Result<()>
    where
        Prepare: Future<Output = crate::error::Result<()>>,
        Verify: FnOnce() -> VerifyFuture,
        VerifyFuture: Future<Output = crate::error::Result<()>>,
    {
        loop {
            let wait_for_change = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                match *state {
                    EndpointReadinessState::Verified => return Ok(()),
                    EndpointReadinessState::Unverified => {
                        *state = EndpointReadinessState::Verifying;
                        None
                    }
                    EndpointReadinessState::Verifying => Some(self.changed.notified()),
                }
            };

            if let Some(wait_for_change) = wait_for_change {
                wait_for_change.await;
                continue;
            }

            let result = async {
                prepare_runtime.await?;
                verify_endpoint().await
            }
            .await;

            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            *state = if result.is_ok() {
                EndpointReadinessState::Verified
            } else {
                EndpointReadinessState::Unverified
            };
            self.changed.notify_waiters();
            return result;
        }
    }

    fn invalidate(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if *state != EndpointReadinessState::Unverified {
            *state = EndpointReadinessState::Unverified;
            self.changed.notify_waiters();
        }
    }

    #[cfg(test)]
    fn state(&self) -> EndpointReadinessState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Creates the Docker API router with all endpoints.
///
/// The returned Router expects version-free paths (`/containers/{id}/start`).
/// Use [`strip_api_version_prefix`] as a `MapRequestLayer` around this Router
/// so that versioned paths (`/v1.51/containers/{id}/start`) are normalised
/// *before* Axum route matching.
///
/// Only a handful of mutating operations are handled locally; everything else
/// proxies to guest dockerd via the router `fallback` (unmatched paths). The
/// `/containers/{id}` route additionally proxies unhandled *methods* on its own
/// path — see [`container_routes`] — because its `{id}` capture shadows the
/// single-segment static endpoints `GET /containers/json` and
/// `POST /containers/prune`.
pub fn create_router(runtime: Arc<Runtime>, connector: Arc<dyn GuestConnector>) -> Router {
    let state = AppState {
        runtime,
        proxy: Arc::new(ProxyState::new(connector)),
    };

    api_routes()
        .fallback(proxy::proxy_fallback)
        .layer(middleware::from_fn(trace_id_middleware))
        .with_state(state)
}

/// Strips the Docker Engine API version prefix from a request URI.
///
/// Transforms `/v1.47/containers/{id}/start` → `/containers/{id}/start` so that
/// a single set of routes handles every API version. The original versioned URI
/// is saved as [`OriginalUri`] so proxy handlers can forward it verbatim.
///
/// Must be applied as a `tower::util::MapRequestLayer` *around* the Router
/// (not via `Router::layer`) so it runs before route matching.
pub fn strip_api_version_prefix<B>(mut req: axum::http::Request<B>) -> axum::http::Request<B> {
    let path = req.uri().path().to_owned();
    if let Some(stripped) = strip_version_prefix(&path) {
        let query = req.uri().query().map(str::to_owned);
        let original_uri = req.uri().clone();
        let new_pq = query
            .as_ref()
            .map_or_else(|| stripped.to_string(), |q| format!("{stripped}?{q}"));

        // Preserve the original versioned URI for proxy forwarding.
        req.extensions_mut().insert(OriginalUri(original_uri));

        if let Ok(uri) = new_pq.parse() {
            *req.uri_mut() = uri;
        }
    }
    req
}

/// Returns the path with the `/v{major}.{minor}` prefix removed, or `None` if
/// the path does not start with a valid Docker API version prefix.
fn strip_version_prefix(path: &str) -> Option<&str> {
    let after_v = path.strip_prefix("/v")?;
    let dot = after_v.find('.')?;
    let after_dot = &after_v[dot + 1..];
    let slash = after_dot.find('/')?;

    let major = &after_v[..dot];
    let minor = &after_dot[..slash];
    if !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|b| b.is_ascii_digit())
        && minor.bytes().all(|b| b.is_ascii_digit())
    {
        Some(&after_dot[slash..])
    } else {
        None
    }
}

fn api_routes() -> Router<AppState> {
    Router::new()
        .merge(system_routes())
        .merge(container_routes())
        .merge(build_routes())
        .merge(image_routes())
        .merge(network_routes())
        .merge(volume_routes())
}

fn system_routes() -> Router<AppState> {
    Router::new()
}

fn container_routes() -> Router<AppState> {
    Router::new()
        .route("/containers/create", post(handlers::create_container))
        .route("/containers/{id}/start", post(handlers::start_container))
        .route("/containers/{id}/stop", post(handlers::stop_container))
        .route(
            "/containers/{id}/restart",
            post(handlers::restart_container),
        )
        .route("/containers/{id}/kill", post(handlers::kill_container))
        .route("/containers/{id}/rename", post(handlers::rename_container))
        // `{id}` also matches the single-segment static endpoints
        // `GET /containers/json` (list) and `POST /containers/prune`, whose
        // methods aren't DELETE. Proxy any non-DELETE method on *this* path to
        // guest dockerd so those aren't shadowed into a 405 — scoped here so the
        // lifecycle routes above still reject wrong methods locally rather than
        // proxying them. `DELETE /containers/{id}` (incl. a container literally
        // named "json"/"prune") still routes to the local remove handler.
        .route(
            "/containers/{id}",
            delete(handlers::remove_container).fallback(proxy::proxy_fallback),
        )
}

fn build_routes() -> Router<AppState> {
    Router::new().route("/build", post(handlers::build_image))
}

fn image_routes() -> Router<AppState> {
    Router::new()
}

fn network_routes() -> Router<AppState> {
    Router::new()
}

fn volume_routes() -> Router<AppState> {
    Router::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DockerError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{Duration, sleep};

    #[test]
    fn strip_standard_version_prefix() {
        assert_eq!(
            strip_version_prefix("/v1.51/containers/abc/start"),
            Some("/containers/abc/start")
        );
        assert_eq!(
            strip_version_prefix("/v1.24/images/json"),
            Some("/images/json")
        );
        assert_eq!(
            strip_version_prefix("/v1.99/containers/abc/start"),
            Some("/containers/abc/start")
        );
    }

    #[test]
    fn strip_preserves_unversioned_paths() {
        assert_eq!(strip_version_prefix("/containers/abc/start"), None);
        assert_eq!(strip_version_prefix("/_ping"), None);
        assert_eq!(strip_version_prefix("/version"), None);
    }

    #[test]
    fn strip_rejects_malformed_versions() {
        assert_eq!(strip_version_prefix("/v1x/containers/json"), None);
        assert_eq!(strip_version_prefix("/vabc.def/containers/json"), None);
        assert_eq!(strip_version_prefix("/v/containers/json"), None);
        assert_eq!(strip_version_prefix("/v1./containers/json"), None);
    }

    #[test]
    fn strip_rejects_version_only_path() {
        // No trailing slash after version → no route to strip to.
        assert_eq!(strip_version_prefix("/v1.51"), None);
    }

    #[test]
    fn strip_api_version_prefix_preserves_query_string() {
        let req = axum::http::Request::builder()
            .uri("/v1.51/containers/json?all=true&limit=10")
            .body(())
            .unwrap();
        let req = strip_api_version_prefix(req);
        assert_eq!(req.uri(), "/containers/json?all=true&limit=10");
    }

    #[test]
    fn strip_api_version_prefix_sets_original_uri() {
        let req = axum::http::Request::builder()
            .uri("/v1.51/containers/abc/start")
            .body(())
            .unwrap();
        let req = strip_api_version_prefix(req);
        assert_eq!(req.uri().path(), "/containers/abc/start");
        let original = req.extensions().get::<OriginalUri>().unwrap();
        assert_eq!(original.0.path(), "/v1.51/containers/abc/start");
    }

    #[test]
    fn strip_api_version_prefix_noop_for_unversioned() {
        let req = axum::http::Request::builder()
            .uri("/containers/abc/start")
            .body(())
            .unwrap();
        let req = strip_api_version_prefix(req);
        assert_eq!(req.uri().path(), "/containers/abc/start");
        assert!(req.extensions().get::<OriginalUri>().is_none());
    }

    #[tokio::test]
    async fn readiness_transitions_unverified_to_verified_after_success() {
        let readiness = EndpointReadiness::new();
        let prepared = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));

        assert_eq!(readiness.state(), EndpointReadinessState::Unverified);

        let prepared_current = Arc::clone(&prepared);
        let verified_current = Arc::clone(&verified);
        readiness
            .ensure_verified(
                async move {
                    prepared_current.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
                || async move {
                    verified_current.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
            )
            .await
            .unwrap();

        assert_eq!(readiness.state(), EndpointReadinessState::Verified);
        assert_eq!(prepared.load(Ordering::Relaxed), 1);
        assert_eq!(verified.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn readiness_keeps_verified_state_on_cache_hit() {
        let readiness = EndpointReadiness::new();
        let prepared = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));

        let prepared_first = Arc::clone(&prepared);
        let verified_first = Arc::clone(&verified);
        readiness
            .ensure_verified(
                async move {
                    prepared_first.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
                || async move {
                    verified_first.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
            )
            .await
            .unwrap();

        let prepared_second = Arc::clone(&prepared);
        let verified_second = Arc::clone(&verified);
        readiness
            .ensure_verified(
                async move {
                    prepared_second.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
                || async move {
                    verified_second.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
            )
            .await
            .unwrap();

        assert_eq!(prepared.load(Ordering::Relaxed), 1);
        assert_eq!(verified.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn readiness_transitions_back_to_unverified_after_failure() {
        let readiness = EndpointReadiness::new();
        let prepared = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));

        let prepared_current = Arc::clone(&prepared);
        let verified_current = Arc::clone(&verified);
        let err = readiness
            .ensure_verified(
                async move {
                    prepared_current.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                },
                || async move {
                    verified_current.fetch_add(1, Ordering::Relaxed);
                    Err::<(), DockerError>(DockerError::Server("ping failed".into()))
                },
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("ping failed"));
        assert_eq!(readiness.state(), EndpointReadinessState::Unverified);
        assert_eq!(prepared.load(Ordering::Relaxed), 1);
        assert_eq!(verified.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn readiness_invalidation_transitions_verified_to_unverified() {
        let readiness = EndpointReadiness::new();
        let verified = Arc::new(AtomicUsize::new(0));

        for _ in 0..2 {
            let verified_current = Arc::clone(&verified);
            readiness
                .ensure_verified(async { Ok::<(), DockerError>(()) }, || async move {
                    verified_current.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), DockerError>(())
                })
                .await
                .unwrap();
            readiness.invalidate();
        }

        assert_eq!(verified.load(Ordering::Relaxed), 2);
        assert_eq!(readiness.state(), EndpointReadinessState::Unverified);
    }

    #[tokio::test]
    async fn readiness_generation_change_invalidates_verified_state() {
        let readiness = EndpointReadiness::new();

        // Verify against the initial incarnation (generation 0).
        readiness
            .ensure_verified(async { Ok::<(), DockerError>(()) }, || async {
                Ok::<(), DockerError>(())
            })
            .await
            .unwrap();
        assert_eq!(readiness.state(), EndpointReadinessState::Verified);

        // Re-observing the same incarnation is a cache hit — no invalidation.
        assert!(!readiness.observe_generation(0));
        assert_eq!(readiness.state(), EndpointReadinessState::Verified);

        // A new incarnation (the VM restarted) drops the cached verification.
        assert!(readiness.observe_generation(7));
        assert_eq!(readiness.state(), EndpointReadinessState::Unverified);

        // Stable once recorded.
        assert!(!readiness.observe_generation(7));
    }

    #[tokio::test]
    async fn readiness_serializes_concurrent_verification() {
        let readiness = Arc::new(EndpointReadiness::new());
        let prepared = Arc::new(AtomicUsize::new(0));
        let verified = Arc::new(AtomicUsize::new(0));

        let first_readiness = Arc::clone(&readiness);
        let first_prepared = Arc::clone(&prepared);
        let first_verified = Arc::clone(&verified);
        let first = tokio::spawn(async move {
            first_readiness
                .ensure_verified(
                    async move {
                        first_prepared.fetch_add(1, Ordering::Relaxed);
                        sleep(Duration::from_millis(20)).await;
                        Ok::<(), DockerError>(())
                    },
                    || async move {
                        first_verified.fetch_add(1, Ordering::Relaxed);
                        sleep(Duration::from_millis(20)).await;
                        Ok::<(), DockerError>(())
                    },
                )
                .await
        });

        while readiness.state() != EndpointReadinessState::Verifying {
            sleep(Duration::from_millis(1)).await;
        }

        let second_readiness = Arc::clone(&readiness);
        let second_prepared = Arc::clone(&prepared);
        let second_verified = Arc::clone(&verified);
        let second = tokio::spawn(async move {
            second_readiness
                .ensure_verified(
                    async move {
                        second_prepared.fetch_add(1, Ordering::Relaxed);
                        Ok::<(), DockerError>(())
                    },
                    || async move {
                        second_verified.fetch_add(1, Ordering::Relaxed);
                        Ok::<(), DockerError>(())
                    },
                )
                .await
        });

        first.await.unwrap().unwrap();
        second.await.unwrap().unwrap();

        assert_eq!(readiness.state(), EndpointReadinessState::Verified);
        assert_eq!(prepared.load(Ordering::Relaxed), 1);
        assert_eq!(verified.load(Ordering::Relaxed), 1);
    }
}
