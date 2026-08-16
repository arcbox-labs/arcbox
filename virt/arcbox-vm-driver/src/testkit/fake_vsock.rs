//! The fake's vsock plumbing: guest-initiated connections queued per port,
//! and the echoing peer a `dial` gets.

use std::collections::{HashMap, VecDeque};
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::Notify;

use super::lock;
use crate::capability::VsockListener;
use crate::driver::{ExitStatus, IoMode, VmState, VsockConn};
use crate::error::{Error, Result};
use crate::spec::VmId;

/// Guest-initiated connections waiting for a host `accept`, per port.
///
/// Created when a VM is prepared, so a listener bound before the guest
/// starts and the VM booted afterwards share the same queues.
pub(super) struct Inbound {
    id: VmId,
    queues: Mutex<HashMap<u32, VecDeque<UnixStream>>>,
    /// Woken on every push and on close.
    wake: Notify,
    /// Set when the VM (or the prepared process) is gone; `accept` fails
    /// with it once the queues are drained.
    closed: Mutex<Option<ExitStatus>>,
}

impl Inbound {
    pub(super) fn new(id: VmId) -> Arc<Self> {
        Arc::new(Self {
            id,
            queues: Mutex::new(HashMap::new()),
            wake: Notify::new(),
            closed: Mutex::new(None),
        })
    }

    /// Queues a guest-side connection to host `port`.
    pub(super) fn push(&self, port: u32, stream: UnixStream) {
        lock(&self.queues)
            .entry(port)
            .or_default()
            .push_back(stream);
        self.wake.notify_waiters();
    }

    /// No more connections can arrive: the VM ended with `status`.
    pub(super) fn close(&self, status: ExitStatus) {
        lock(&self.closed).get_or_insert(status);
        self.wake.notify_waiters();
    }

    /// Ports with connections still queued.
    pub(super) fn pending_ports(&self) -> Vec<u32> {
        lock(&self.queues)
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(port, _)| *port)
            .collect()
    }
}

/// A bound fake listener: pops the port's queue, waits otherwise.
pub(super) struct FakeListener {
    pub(super) inbound: Arc<Inbound>,
    pub(super) port: u32,
}

#[async_trait]
impl VsockListener for FakeListener {
    async fn accept(&mut self) -> Result<VsockConn> {
        loop {
            // Register for the wake-up before checking, so a push between the
            // check and the await is not lost.
            let woken = self.inbound.wake.notified();
            let next = lock(&self.inbound.queues)
                .get_mut(&self.port)
                .and_then(VecDeque::pop_front);
            if let Some(stream) = next {
                return Ok(VsockConn {
                    fd: stream.into(),
                    mode: IoMode::Async,
                });
            }
            let closed = *lock(&self.inbound.closed);
            if let Some(status) = closed {
                return Err(Error::WrongState {
                    id: self.inbound.id.clone(),
                    state: VmState::Exited(status),
                    expected: "running or quiesced",
                });
            }
            woken.await;
        }
    }
}

/// One end of a socketpair whose other end echoes every byte back until
/// this end closes.
pub(super) fn echo_peer() -> std::io::Result<UnixStream> {
    let (host, guest) = UnixStream::pair()?;
    std::thread::Builder::new()
        .name("fake-vsock-echo".into())
        .spawn(move || echo(guest))?;
    Ok(host)
}

fn echo(mut stream: UnixStream) {
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
}
