//! Trace ID middleware for Docker API requests.
//!
//! Generates a unique trace ID for each incoming request and attaches it to:
//! - Request extensions (for use by handlers)
//! - Response header `X-Trace-Id`
//! - tracing span (for structured logging)
//! - task-local storage (for automatic propagation to guest RPC calls)

use arcbox_core::trace::CURRENT_TRACE_ID;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// Header name for trace ID propagation.
pub const TRACE_ID_HEADER: &str = "X-Trace-Id";

/// Trace ID stored in request extensions.
#[derive(Debug, Clone)]
pub struct TraceId(pub String);

/// Axum middleware that generates a trace ID for each request.
///
/// If the incoming request already carries an `X-Trace-Id` header, it is
/// reused.  Otherwise a new UUID v4 is generated.  The ID is:
/// - inserted into request extensions as [`TraceId`]
/// - set on the response as the `X-Trace-Id` header
/// - recorded in the current tracing span
/// - stored in task-local for automatic propagation to guest RPC
pub async fn trace_id_middleware(mut request: Request, next: Next) -> Response {
    // Reuse caller-provided trace ID or generate a new one.
    let trace_id = request
        .headers()
        .get(TRACE_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Record in tracing for structured logs.
    tracing::Span::current().record("trace_id", &trace_id.as_str());
    tracing::debug!(trace_id = %trace_id, method = %request.method(), uri = %request.uri(), "request");

    // Store in request extensions so handlers can access it.
    request.extensions_mut().insert(TraceId(trace_id.clone()));

    // Run the handler inside a task-local scope so downstream code
    // (e.g. AgentClient::rpc_call) can read the trace ID automatically.
    let tid = trace_id.clone();
    let mut response = CURRENT_TRACE_ID.scope(tid, next.run(request)).await;

    // Attach to response header.
    if let Ok(value) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert(TRACE_ID_HEADER, value);
    }

    response
}
