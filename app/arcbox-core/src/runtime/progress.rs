//! Startup milestones reported out of [`Runtime::init`](crate::Runtime::init).

/// A milestone [`Runtime::init`](crate::Runtime::init) passes while bringing
/// the System VM up.
///
/// `init` is a single call spanning the slowest stretch of daemon startup:
/// staging the guest runtime binaries, booting the VM, the agent handshake,
/// then probing the guest container runtime. A caller that wants to report
/// progress to its own clients needs the boundaries *inside* that call, and
/// cannot recover them from call order — doing so would bill the binary
/// download to VM boot and could not separate "the agent answered" from
/// "dockerd answered".
///
/// Reported on the calling task, in declaration order, and only while a
/// System VM is actually coming up: VM-host-only mode (`vm.autostart =
/// false`) starts no VM and reports nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitProgress {
    /// Guest binaries are staged and validated; the System VM is about to
    /// boot. Everything before this point is host-side preparation.
    SystemVmStarting,
    /// The System VM booted and its guest agent answered, so the VM accepts
    /// commands. Its container runtime may still be starting.
    SystemVmReady,
}
