//! Server-Sent Events (SSE) helpers.

use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use std::convert::Infallible;
use tokio_stream::Stream;

/// Creates an SSE response with a default keep-alive interval.
pub fn sse_response(
    stream: impl Stream<Item = Result<Event, Infallible>> + Send + 'static,
) -> Response {
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}
