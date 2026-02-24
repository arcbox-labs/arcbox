//! Task-local trace ID for cross-layer propagation.
//!
//! The Docker API middleware sets the trace ID via [`CURRENT_TRACE_ID`], and
//! downstream code (e.g. [`AgentClient`](crate::agent_client::AgentClient))
//! reads it automatically so every guest RPC call carries the originating
//! HTTP request's trace ID.

tokio::task_local! {
    /// Task-local trace ID.  Set by the HTTP middleware, read by RPC callers.
    pub static CURRENT_TRACE_ID: String;
}

/// Returns the current trace ID from task-local storage, or an empty string
/// if none is set (e.g. when called outside an HTTP request context).
pub fn current_trace_id() -> String {
    CURRENT_TRACE_ID
        .try_with(|id| id.clone())
        .unwrap_or_default()
}
