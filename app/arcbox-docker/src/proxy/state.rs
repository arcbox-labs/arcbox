//! Guest proxy transport state: connector, pooled client, and the cached
//! endpoint-readiness state machine.

use super::{GuestConnector, GuestHttpClient, proxy_to_guest_pooled};
use crate::error::{DockerError, Result};
use axum::http::{HeaderMap, Method, StatusCode};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::future::Future;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Notify;

/// Guest proxy transport state shared by handlers.
pub struct ProxyState {
    connector: Arc<dyn GuestConnector>,
    guest_http_client: GuestHttpClient,
    endpoint_readiness: EndpointReadiness,
}

impl ProxyState {
    pub(crate) fn new(connector: Arc<dyn GuestConnector>) -> Self {
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
    ) -> Result<()>
    where
        F: Future<Output = Result<()>>,
    {
        self.reset_if_restarted(generation);
        self.endpoint_readiness
            .ensure_verified(prepare_runtime, || self.ping_guest())
            .await
    }

    /// Observes the System VM incarnation counter; when it advanced since the
    /// last observation, drops the pooled connections and the cached readiness
    /// (both point at the stopped VM). Returns whether a reset happened.
    ///
    /// Shared by the request path ([`Self::ensure_endpoint_verified`]) and the
    /// host-networking reconciler, so both react to a restart through the same
    /// pool.
    pub(crate) fn reset_if_restarted(&self, generation: u64) -> bool {
        if !self.endpoint_readiness.advance_generation(generation) {
            return false;
        }
        // Drop the stale pool BEFORE flipping readiness to Unverified: a
        // concurrent verifier that observes Unverified starts its `_ping`
        // immediately, and it must dial through the fresh client — resetting
        // afterwards would let it race onto a connection to the dead VM.
        self.guest_http_client.reset();
        self.endpoint_readiness.invalidate();
        true
    }

    pub(crate) fn invalidate_endpoint(&self) {
        self.endpoint_readiness.invalidate();
    }

    async fn ping_guest(&self) -> Result<()> {
        let response = proxy_to_guest_pooled(
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
                DockerError::Server(format!("failed to read guest docker _ping response: {e}"))
            })?
            .to_bytes();

        if status == StatusCode::OK {
            return Ok(());
        }

        Err(DockerError::Server(format!(
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

    /// Records the current VM incarnation, returning whether it advanced past
    /// the last one seen (i.e. the System VM restarted in between). The caller
    /// owns the resulting reset — see [`ProxyState::reset_if_restarted`] for
    /// the required pool-then-readiness ordering.
    ///
    /// `fetch_max` (not `swap`) keeps the counter monotonic: a request that
    /// read an older incarnation before a restart and lands here late cannot
    /// regress the counter and trigger a spurious extra pool reset.
    fn advance_generation(&self, generation: u64) -> bool {
        self.generation.fetch_max(generation, Ordering::AcqRel) < generation
    }

    async fn ensure_verified<Prepare, Verify, VerifyFuture>(
        &self,
        prepare_runtime: Prepare,
        verify_endpoint: Verify,
    ) -> Result<()>
    where
        Prepare: Future<Output = Result<()>>,
        Verify: FnOnce() -> VerifyFuture,
        VerifyFuture: Future<Output = Result<()>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::time::{Duration, sleep};

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

    /// Connector stub for ProxyState tests — never actually dialed, since the
    /// generation tests drive the readiness state machine directly.
    struct StubConnector;

    impl super::super::GuestConnector for StubConnector {
        fn connect(
            &self,
        ) -> std::pin::Pin<
            Box<
                dyn Future<
                        Output = Result<
                            hyper_util::rt::TokioIo<arcbox_transport::vsock::VsockStream>,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            Box::pin(async { Err(DockerError::Server("stub connector".into())) })
        }
    }

    fn stub_proxy_state() -> ProxyState {
        ProxyState::new(Arc::new(StubConnector))
    }

    async fn mark_verified(state: &ProxyState) {
        state
            .endpoint_readiness
            .ensure_verified(async { Ok::<(), DockerError>(()) }, || async {
                Ok::<(), DockerError>(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn generation_change_resets_verified_state() {
        let proxy = stub_proxy_state();

        mark_verified(&proxy).await;
        assert_eq!(
            proxy.endpoint_readiness.state(),
            EndpointReadinessState::Verified
        );

        // Re-observing the same incarnation is a cache hit — no reset.
        assert!(!proxy.reset_if_restarted(0));
        assert_eq!(
            proxy.endpoint_readiness.state(),
            EndpointReadinessState::Verified
        );

        // A new incarnation (the VM restarted) drops the cached verification.
        assert!(proxy.reset_if_restarted(7));
        assert_eq!(
            proxy.endpoint_readiness.state(),
            EndpointReadinessState::Unverified
        );

        // Stable once recorded.
        assert!(!proxy.reset_if_restarted(7));
    }

    #[tokio::test]
    async fn generation_is_monotonic_under_stale_readers() {
        let proxy = stub_proxy_state();

        // A request that read generation 7 resets first.
        assert!(proxy.reset_if_restarted(7));

        // Re-verify, then a late request carrying a STALE generation (read
        // before the restart) lands. It must neither regress the counter nor
        // trigger a spurious reset.
        mark_verified(&proxy).await;
        assert!(!proxy.reset_if_restarted(3));
        assert_eq!(
            proxy.endpoint_readiness.state(),
            EndpointReadinessState::Verified
        );

        // And the next current-generation observation is still a no-op (7 was
        // not overwritten by 3).
        assert!(!proxy.reset_if_restarted(7));
        assert_eq!(
            proxy.endpoint_readiness.state(),
            EndpointReadinessState::Verified
        );
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
