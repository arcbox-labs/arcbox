//! Connecting to the daemon's control-plane socket.
//!
//! The daemon serves Connect, gRPC, and gRPC-Web from one endpoint
//! (CORE-53, CORE-68). The CLI speaks the Connect protocol over h2c on the
//! Unix socket — no TLS, no DNS, no port.
//!
//! Connections are **lazy**: the socket is dialled on the first call rather
//! than when the client is built. That keeps `abctl` subcommands that never
//! reach the daemon from paying for a connection, and it means a connection
//! failure surfaces at the call that needed it, with that call's context,
//! instead of at construction.

use std::path::Path;

use anyhow::{Context as _, Result};

use buffa::view::OwnedView;
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection, UnaryResponse};

/// Concurrent in-flight requests a single client transport will buffer.
///
/// The CLI issues a handful of calls per invocation, so this only has to be
/// large enough that a streaming call plus a few unary ones never queue
/// behind each other.
const TRANSPORT_BUFFER: usize = 32;

/// The authority the daemon is addressed by.
///
/// Unix sockets have no host, but HTTP/2 requires an `:authority`; the
/// daemon does not check it.
const AUTHORITY: &str = "http://localhost";

/// Opens a transport and config for the daemon at `socket`.
///
/// The pair is what every generated client constructor takes.
#[must_use]
pub fn daemon(socket: &Path) -> (SharedHttp2Connection, ClientConfig) {
    let authority = AUTHORITY.parse().expect("static authority parses");
    let transport = Http2Connection::lazy_unix(socket, authority).shared(TRANSPORT_BUFFER);
    let config = ClientConfig::new(AUTHORITY.parse().expect("static base URI parses"));
    (transport, config)
}

/// Reads a Connect response back as its prost twin.
///
/// The response arrives as a zero-copy view over the wire bytes; this
/// decodes those same bytes as the prost message the rest of the CLI
/// already formats and serializes. That is what keeps `--json` output
/// byte-identical across this migration.
pub trait UnaryExt {
    /// The prost message the response bytes decode as.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes do not decode as `P`, which would mean
    /// the two generated representations disagree — a build fault, not a
    /// user one.
    fn prost<P: prost::Message + Default>(self) -> Result<P>;
}

impl<V: buffa::view::MessageView<'static>> UnaryExt for UnaryResponse<OwnedView<V>> {
    fn prost<P: prost::Message + Default>(self) -> Result<P> {
        P::decode(self.into_view().bytes().clone()).with_context(|| {
            format!(
                "daemon response did not decode as {}",
                std::any::type_name::<P>()
            )
        })
    }
}
