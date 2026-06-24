//! Seccomp and time offset configuration types.

use serde::{Deserialize, Serialize};

/// Seccomp configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Seccomp {
    /// Default action.
    pub default_action: String,
    /// Default errno return value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_errno_ret: Option<u32>,
    /// Architectures.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub architectures: Vec<String>,
    /// Flags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Listener path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_path: Option<String>,
    /// Listener metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listener_metadata: Option<String>,
    /// Syscall rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<SyscallRule>,
}

/// Seccomp syscall rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyscallRule {
    /// Syscall names.
    pub names: Vec<String>,
    /// Action to take.
    pub action: String,
    /// Errno return value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno_ret: Option<u32>,
    /// Arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<SyscallArg>,
}

/// Seccomp syscall argument filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyscallArg {
    /// Argument index.
    pub index: u32,
    /// Value to compare.
    pub value: u64,
    /// Secondary value (for masked equality).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_two: Option<u64>,
    /// Comparison operator.
    pub op: String,
}

/// Time offsets configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeOffsets {
    /// Monotonic clock offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monotonic: Option<TimeOffset>,
    /// Boottime clock offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boottime: Option<TimeOffset>,
}

/// Time offset value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeOffset {
    /// Seconds offset.
    pub secs: i64,
    /// Nanoseconds offset.
    pub nanosecs: u32,
}
