//! How the runtime reaches the guest agent inside a Computer.
//!
//! Today there is one implementation, [`vm_proto`]: the `arcbox-vm-proto`
//! frame protocol over the driver port's vsock capability, which is what
//! every Firecracker sandbox speaks. It carries the exec channel (`run`,
//! `exec`, `sync_clock`, `reconfigure_network`, `wait_for_port`), the file
//! channel, and the readiness dial-out the boot gate waits on.

pub mod vm_proto;
