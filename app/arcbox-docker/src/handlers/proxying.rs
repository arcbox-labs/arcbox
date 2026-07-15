//! Handler-level proxy dispatch helpers.

use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::proxy;
use crate::proxy::{ActivityClass, ActivityLease};
use axum::body::Body;
use axum::http::{Request, Uri};
use axum::response::Response;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// Ensures the system VM is up before any request reaches the connector, then
/// verifies guest dockerd with a real Docker `_ping`.
///
/// `activity` decides whether this request counts toward idle tracking;
/// passive observation streams verify the endpoint without touching the
/// idle clock (see [`ActivityClass`]).
pub async fn ensure_system_vm_ready(state: &AppState, activity: ActivityClass) -> Result<()> {
    let runtime = Arc::clone(&state.runtime);
    let generation = runtime.system_vm_restart_generation();
    state
        .proxy
        .ensure_endpoint_verified(generation, activity, async move {
            runtime
                .ensure_system_vm_ready()
                .await
                .map(|_| ())
                .map_err(|e| {
                    DockerError::Server(format!("failed to ensure system VM is ready: {e}"))
                })
        })
        .await
}

/// Forward a request to guest dockerd.
pub async fn proxy_to_system_vm(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    ensure_system_vm_ready(state, ActivityClass::Active).await?;
    proxy::invalidate_on_guest_error(
        state,
        proxy::proxy_to_guest_stream_pooled(state.proxy.client(), uri, req).await,
    )
    .map(|resp| hold_activity_for_response(state, ActivityClass::Active, resp))
}

/// Forward an upload request to guest dockerd.
pub async fn proxy_upload_to_system_vm(
    state: &AppState,
    uri: &Uri,
    req: Request<Body>,
) -> Result<Response> {
    ensure_system_vm_ready(state, ActivityClass::Active).await?;
    proxy::invalidate_on_guest_error(
        state,
        proxy::proxy_streaming_upload(state.proxy.connector(), uri, req).await,
    )
    .map(|resp| hold_activity_for_response(state, ActivityClass::Active, resp))
}

/// Ties an activity lease to the response body, so a streaming operation
/// (pull progress, build output) holds the VM out of idle until its last
/// byte. Plain bodies drop the lease when they finish; either way the idle
/// clock restarts at the operation's end. Passive observation streams pass
/// through untouched — watching the VM must not hold it out of idle (see
/// [`ActivityClass`]).
pub fn hold_activity_for_response(
    state: &AppState,
    activity: ActivityClass,
    resp: Response,
) -> Response {
    if activity == ActivityClass::PassiveObservation {
        return resp;
    }
    let Some(lease) = state.proxy.activity_lease() else {
        return resp;
    };
    resp.map(|body| {
        Body::new(LeasedBody {
            inner: body,
            _lease: lease,
        })
    })
}

/// A response body that carries an [`ActivityLease`] until it is fully
/// streamed (or dropped).
struct LeasedBody {
    inner: Body,
    _lease: ActivityLease,
}

impl http_body::Body for LeasedBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
