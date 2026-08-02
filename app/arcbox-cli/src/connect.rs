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

use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};

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

/// The same, with a machine-routing header set on every call.
///
/// "Which local VM to target" is transport metadata a local client may set,
/// never part of the sandbox product contract (CORE-54). Setting it once on
/// the config beats attaching it per request — a call that forgot would
/// silently route to the default rather than fail.
#[must_use]
pub fn daemon_for_machine(socket: &Path, machine: &str) -> (SharedHttp2Connection, ClientConfig) {
    let (transport, config) = daemon(socket);
    (transport, config.with_default_header("x-machine", machine))
}
