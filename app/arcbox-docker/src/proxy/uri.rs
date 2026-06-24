//! URI helpers for guest dockerd requests.

use axum::http::Uri;

/// Path and query forwarded to guest dockerd.
pub(super) struct GuestPath<'a>(&'a str);

impl<'a> From<&'a Uri> for GuestPath<'a> {
    fn from(uri: &'a Uri) -> Self {
        Self(
            uri.path_and_query()
                .map_or("/", hyper::http::uri::PathAndQuery::as_str),
        )
    }
}

impl AsRef<str> for GuestPath<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}
