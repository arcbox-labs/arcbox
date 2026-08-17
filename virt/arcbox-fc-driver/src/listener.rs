//! The port's [`VsockListener`] over [`UdsListener`]s: a guest dial-out
//! per `accept`, bound next to the vsock socket the VM has *now*, failing
//! once the VM is gone.
//!
//! Firecracker forwards a guest connect to host port `P` to `{uds}_P`
//! next to its vsock socket — the one it bound, which after a restore is
//! the path the checkpoint recorded, not the new runtime layout's. The
//! prepared VM, the handle, and every listener therefore share one
//! [`VsockEndpoint`]: `dial` reads it, `listen` binds next to it, and a
//! listener bound before a restore follows it to wherever the restored
//! guest dials out.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::Poll;

use arcbox_vm_driver::{Error, IoMode, Result, VmId, VmState, VsockConn, VsockListener};
use async_trait::async_trait;
use nix::unistd::{Gid, Uid, chown};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::error::FcError;
use crate::jail::Jail;
use crate::process::FcProcess;
use crate::render::VmLayout;
use crate::vsock::{UdsListener, listener_socket_path};

/// The vsock Unix socket a VM's guest dial-outs are forwarded next to, as
/// the host sees it.
///
/// Created at the layout's path when a VM is prepared and shared with the
/// handle booted on it; a restore [`relocate`](Self::relocate)s it to the
/// path the checkpoint recorded before the guest resumes, and listeners
/// bound earlier follow.
#[derive(Debug, Clone)]
pub struct VsockEndpoint(Arc<watch::Sender<PathBuf>>);

impl VsockEndpoint {
    /// An endpoint at `uds`.
    pub fn new(uds: PathBuf) -> Self {
        Self(Arc::new(watch::Sender::new(uds)))
    }

    /// Where the socket is now.
    pub fn path(&self) -> PathBuf {
        self.0.borrow().clone()
    }

    /// The socket moved: Firecracker bound it at `uds`.
    pub fn relocate(&self, uds: PathBuf) {
        self.0.send_if_modified(|current| {
            if *current == uds {
                return false;
            }
            *current = uds;
            true
        });
    }

    fn subscribe(&self) -> watch::Receiver<PathBuf> {
        self.0.subscribe()
    }
}

/// Bind the listener for host `port` next to the VM's vsock socket.
///
/// Under a jail the socket file is owned by the jailed uid/gid: Firecracker
/// `connect(2)`s to it as that user, which needs write permission on it.
pub fn bind(
    layout: &VmLayout,
    endpoint: &VsockEndpoint,
    process: &FcProcess,
    port: u32,
) -> Result<Box<dyn VsockListener>> {
    if let Some(status) = process.exit_status() {
        return Err(Error::WrongState {
            id: layout.id().clone(),
            state: VmState::Exited(status),
            expected: "a live vm",
        });
    }
    let mut uds = endpoint.subscribe();
    let first = bind_at(&uds.borrow_and_update(), port, layout.jail())?;
    Ok(Box::new(FcListener {
        id: layout.id().clone(),
        port,
        jail: layout.jail().cloned(),
        bound: vec![first],
        uds,
        follow: true,
        exit: process.subscribe(),
    }))
}

fn bind_at(uds: &Path, port: u32, jail: Option<&Jail>) -> Result<UdsListener> {
    let listener = UdsListener::bind(uds, port)?;
    if let Some(jail) = jail {
        chown(
            listener.path(),
            Some(Uid::from_raw(jail.uid)),
            Some(Gid::from_raw(jail.gid)),
        )
        .map_err(|source| FcError::Chown {
            path: listener.path().to_path_buf(),
            source,
        })?;
    }
    Ok(listener)
}

struct FcListener {
    id: VmId,
    port: u32,
    jail: Option<Jail>,
    /// One per place the VM's socket has been; the first is where it was
    /// when the listener was bound.
    bound: Vec<UdsListener>,
    uds: watch::Receiver<PathBuf>,
    /// The endpoint is still alive and may move.
    follow: bool,
    exit: watch::Receiver<Option<arcbox_vm_driver::ExitStatus>>,
}

impl FcListener {
    fn exited(&self, status: arcbox_vm_driver::ExitStatus) -> Error {
        Error::WrongState {
            id: self.id.clone(),
            state: VmState::Exited(status),
            expected: "running or quiesced",
        }
    }

    /// Bind next to the socket's current place, if not bound there yet.
    fn follow_endpoint(&mut self) -> Result<()> {
        let current = self.uds.borrow_and_update().clone();
        let target = listener_socket_path(&current, self.port);
        if !self.bound.iter().any(|l| l.path() == target) {
            self.bound
                .push(bind_at(&current, self.port, self.jail.as_ref())?);
        }
        Ok(())
    }
}

/// The next connection on any of `listeners`.
async fn accept_any(listeners: &[UdsListener]) -> Result<UnixStream> {
    std::future::poll_fn(|cx| {
        for listener in listeners {
            if let Poll::Ready(accepted) = listener.poll_accept(cx) {
                return Poll::Ready(accepted);
            }
        }
        Poll::Pending
    })
    .await
}

#[async_trait]
impl VsockListener for FcListener {
    async fn accept(&mut self) -> Result<VsockConn> {
        loop {
            let exited = *self.exit.borrow();
            if let Some(status) = exited {
                return Err(self.exited(status));
            }
            self.follow_endpoint()?;
            let Self {
                bound,
                uds,
                follow,
                exit,
                ..
            } = &mut *self;
            let stream = tokio::select! {
                accepted = accept_any(bound) => accepted?,
                _ = exit.changed() => {
                    let status = exit.borrow().unwrap_or(crate::process::UNKNOWN_EXIT);
                    return Err(self.exited(status));
                }
                moved = uds.changed(), if *follow => {
                    // Bound next to the new place on the next turn; a
                    // dropped endpoint moves no more.
                    *follow = moved.is_ok();
                    continue;
                }
            };
            return Ok(VsockConn {
                fd: stream.into_std()?.into(),
                mode: IoMode::Async,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::config::FcDriverConfig;
    use crate::process::testing::spawn;

    #[tokio::test]
    async fn a_listener_follows_the_endpoint_to_where_the_guest_dials_out() {
        let dir = tempfile::tempdir().unwrap();
        let id = VmId::new("box").unwrap();
        let config = FcDriverConfig::new("/opt/fc/firecracker");
        let layout = VmLayout::new(
            &id,
            &arcbox_vm_driver::IsolationSpec::None,
            &config,
            dir.path(),
        )
        .unwrap();
        let process = spawn("sleep", &["30"]);
        let endpoint = VsockEndpoint::new(layout.vsock_host_uds());
        let mut listener = bind(&layout, &endpoint, &process, 51).unwrap();
        assert!(dir.path().join("firecracker.vsock_51").exists());

        // A restore rebinds the vsock where the checkpoint recorded it: the
        // guest now dials out next to that path.
        let recorded = dir.path().join("source").join("firecracker.vsock");
        std::fs::create_dir_all(recorded.parent().unwrap()).unwrap();
        endpoint.relocate(recorded.clone());
        let dial = tokio::spawn(async move {
            let path = listener_socket_path(&recorded, 51);
            for _ in 0..100 {
                if let Ok(mut stream) = UnixStream::connect(&path).await {
                    stream.write_all(&[0]).await.unwrap();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            panic!("the relocated listener never came up at {}", path.display());
        });
        tokio::time::timeout(Duration::from_secs(10), listener.accept())
            .await
            .expect("accept before the deadline")
            .expect("accept the dial-out at the recorded path");
        dial.await.unwrap();

        // The original place stays bound too, and both go with the listener.
        assert!(dir.path().join("firecracker.vsock_51").exists());
        assert!(dir.path().join("source/firecracker.vsock_51").exists());
        drop(listener);
        assert!(!dir.path().join("firecracker.vsock_51").exists());
        assert!(!dir.path().join("source/firecracker.vsock_51").exists());
        process.kill().await.unwrap();
    }
}
