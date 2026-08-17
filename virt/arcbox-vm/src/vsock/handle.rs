//! The guest agent's vsock, taken from the driver handle.

use std::sync::Arc;

use arcbox_vm_driver::{Error, VmHandle, Vsock, VsockConn};
use async_trait::async_trait;

/// The [`Vsock`] capability of a running VM, owned.
///
/// The port lends the capability out of the handle (`VmHandle::vsock`
/// borrows), while the manager's callers hold it across awaits and hand it
/// to detached tasks; this keeps the handle alive and dials through it.
pub struct HandleVsock(pub Arc<dyn VmHandle>);

#[async_trait]
impl Vsock for HandleVsock {
    async fn dial(&self, port: u32) -> arcbox_vm_driver::Result<VsockConn> {
        // Every sandbox spec asks for the device and the manager requires a
        // driver that has it, so a handle without one is a driver at odds
        // with what it claimed, not a state the guest can be in.
        let vsock = self.0.vsock().ok_or_else(|| {
            Error::InvalidSpec(format!(
                "vm {} has no vsock device to reach its agent through",
                self.0.id()
            ))
        })?;
        vsock.dial(port).await
    }
}
