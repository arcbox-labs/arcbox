//! HTTP header handling shared by proxy paths.

use axum::http::{HeaderMap, HeaderName, header};

/// Header forwarding mode for guest requests.
pub(super) enum ForwardedHeaderMode {
    /// Standard HTTP proxying.
    Normal,
    /// Upload proxying where ArcBox owns `Expect: 100-continue` handling.
    Upload,
}

/// Proxy-specific operations for HTTP request headers.
pub(super) trait HeaderMapProxyExt {
    /// Builds a forwarded header map suitable for proxying to guest dockerd.
    ///
    /// Strips hop-by-hop headers (per RFC 7230 §6.1), the `Host` header, the
    /// `Connection` header and any headers listed in `Connection`. Upload mode
    /// also strips `Expect` so ArcBox owns `100-continue` handling.
    fn forwarded_for_guest(&self, mode: ForwardedHeaderMode) -> HeaderMap;

    /// Returns whether these headers request an HTTP upgrade.
    fn wants_upgrade(&self) -> bool;
}

impl HeaderMapProxyExt for HeaderMap {
    fn forwarded_for_guest(&self, mode: ForwardedHeaderMode) -> HeaderMap {
        let strip_expect = matches!(mode, ForwardedHeaderMode::Upload);
        let connection_tokens = self
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|token| token.trim().parse::<HeaderName>().ok())
            .collect::<Vec<_>>();

        let mut forwarded = Self::new();
        for (name, value) in self {
            if name == header::HOST
                || name == header::CONNECTION
                || (strip_expect && name == header::EXPECT)
                || is_hop_by_hop_header(name)
                || connection_tokens.iter().any(|token| token == name)
            {
                continue;
            }
            forwarded.append(name.clone(), value.clone());
        }
        forwarded
    }

    fn wants_upgrade(&self) -> bool {
        self.get(header::UPGRADE).is_some()
            || self
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
    }
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
