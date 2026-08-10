//! The shared transport every handle clones.
//!
//! One lazy HTTP/2 connection to the daemon's Unix socket (dialled on
//! the first call, the `abctl` pattern), plus the client config the
//! generated Connect clients take.

use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};

use crate::connection::Connection;
use crate::error::Result;

/// Concurrent in-flight requests one transport will buffer. An SDK
/// consumer runs a few streams plus unary calls per sandbox; this only
/// has to keep them from queueing behind each other.
const TRANSPORT_BUFFER: usize = 64;

/// Unix sockets have no host, but HTTP/2 requires an `:authority`; the
/// daemon does not check it.
const AUTHORITY: &str = "http://localhost";

/// Shared transport + config; cheap to clone, one per entry point.
#[derive(Clone)]
pub struct ClientContext {
    pub transport: SharedHttp2Connection,
    pub config: ClientConfig,
}

impl ClientContext {
    pub fn new(connection: &Connection) -> Result<Self> {
        let socket = connection.resolve()?;
        let authority = AUTHORITY.parse().expect("static authority parses");
        let transport = Http2Connection::lazy_unix(&socket, authority).shared(TRANSPORT_BUFFER);
        let config = ClientConfig::new(AUTHORITY.parse().expect("static base URI parses"));
        Ok(Self { transport, config })
    }
}
