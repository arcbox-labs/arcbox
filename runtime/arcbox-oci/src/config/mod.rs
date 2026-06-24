//! OCI runtime-spec configuration parsing.
//!
//! This module implements the OCI Runtime Specification config.json format.
//! Reference: <https://github.com/opencontainers/runtime-spec/blob/main/config.md>

mod linux;
mod mount;
mod process;
mod resources;
mod seccomp;
mod spec;

pub use linux::{Device, Linux, Namespace, NamespaceType};
pub use mount::{IdMapping, Mount, Root};
pub use process::{
    Capabilities, ConsoleSize, ExecCpuAffinity, IoPriority, Process, Rlimit, Scheduler, User,
};
pub use resources::{
    BlockIoResources, CpuResources, DeviceCgroup, HugepageLimit, MemoryResources, NetworkPriority,
    NetworkResources, PidsResources, RdmaResource, Resources, ThrottleDevice, WeightDevice,
};
pub use seccomp::{Seccomp, SyscallArg, SyscallRule, TimeOffset, TimeOffsets};
pub use spec::{OCI_VERSION, Spec};

#[cfg(test)]
mod tests;
