//! The port's [`VsockListener`] over a [`UdsListener`]: a guest dial-out
//! per `accept`, failing once the VM is gone.

use arcbox_vm_driver::{Error, IoMode, Result, VmId, VmState, VsockConn, VsockListener};
use async_trait::async_trait;
use nix::unistd::{Gid, Uid, chown};
use tokio::sync::watch;

use crate::error::FcError;
use crate::process::FcProcess;
use crate::render::VmLayout;
use crate::vsock::UdsListener;

/// Bind the listener for host `port` on the VM's vsock socket, owned by
/// the jailed uid/gid under a jail (Firecracker `connect(2)`s to it as
/// that user, which needs write permission on the socket file).
pub fn bind(layout: &VmLayout, process: &FcProcess, port: u32) -> Result<Box<dyn VsockListener>> {
    if let Some(status) = process.exit_status() {
        return Err(Error::WrongState {
            id: layout.id().clone(),
            state: VmState::Exited(status),
            expected: "a live vm",
        });
    }
    let inner = UdsListener::bind(&layout.vsock_host_uds(), port)?;
    if let Some(jail) = layout.jail() {
        chown(
            inner.path(),
            Some(Uid::from_raw(jail.uid)),
            Some(Gid::from_raw(jail.gid)),
        )
        .map_err(|source| FcError::Chown {
            path: inner.path().to_path_buf(),
            source,
        })?;
    }
    Ok(Box::new(FcListener {
        id: layout.id().clone(),
        inner,
        exit: process.subscribe(),
    }))
}

struct FcListener {
    id: VmId,
    inner: UdsListener,
    exit: watch::Receiver<Option<arcbox_vm_driver::ExitStatus>>,
}

#[async_trait]
impl VsockListener for FcListener {
    async fn accept(&mut self) -> Result<VsockConn> {
        let exited = *self.exit.borrow();
        if let Some(status) = exited {
            return Err(Error::WrongState {
                id: self.id.clone(),
                state: VmState::Exited(status),
                expected: "running or quiesced",
            });
        }
        let stream = tokio::select! {
            accepted = self.inner.accept() => accepted?,
            _ = self.exit.changed() => {
                let status = self.exit.borrow().unwrap_or(crate::process::UNKNOWN_EXIT);
                return Err(Error::WrongState {
                    id: self.id.clone(),
                    state: VmState::Exited(status),
                    expected: "running or quiesced",
                });
            }
        };
        Ok(VsockConn {
            fd: stream.into_std()?.into(),
            mode: IoMode::Async,
        })
    }
}
