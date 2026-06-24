//! Process configuration types.

use serde::{Deserialize, Serialize};

/// Container process configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    /// Whether to allocate a terminal.
    #[serde(default)]
    pub terminal: bool,

    /// Console size (only used if terminal is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<ConsoleSize>,

    /// Current working directory (must be absolute path).
    /// REQUIRED field.
    pub cwd: String,

    /// Environment variables.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,

    /// Command arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Resource limits (rlimits).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<Rlimit>,

    /// `AppArmor` profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apparmor_profile: Option<String>,

    /// Linux capabilities.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,

    /// Prevent gaining new privileges.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_new_privileges: bool,

    /// OOM score adjustment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i32>,

    /// `SELinux` label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selinux_label: Option<String>,

    /// User specification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,

    /// I/O priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_priority: Option<IoPriority>,

    /// Scheduler settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<Scheduler>,

    /// CPU affinity for exec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_cpu_affinity: Option<ExecCpuAffinity>,
}

impl Default for Process {
    fn default() -> Self {
        Self {
            terminal: false,
            console_size: None,
            cwd: "/".to_string(),
            env: vec![
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                "TERM=xterm".to_string(),
            ],
            args: vec!["sh".to_string()],
            rlimits: vec![Rlimit {
                rlimit_type: "RLIMIT_NOFILE".to_string(),
                soft: 1024,
                hard: 1024,
            }],
            apparmor_profile: None,
            capabilities: Some(Capabilities::default()),
            no_new_privileges: false,
            oom_score_adj: None,
            selinux_label: None,
            user: Some(User::default()),
            io_priority: None,
            scheduler: None,
            exec_cpu_affinity: None,
        }
    }
}

/// Console size configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSize {
    /// Height in characters.
    pub height: u32,
    /// Width in characters.
    pub width: u32,
}

/// Resource limit (rlimit) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rlimit {
    /// Limit type (e.g., `RLIMIT_NOFILE`).
    #[serde(rename = "type")]
    pub rlimit_type: String,
    /// Soft limit.
    pub soft: u64,
    /// Hard limit.
    pub hard: u64,
}

/// Linux capabilities configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    /// Effective capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective: Vec<String>,
    /// Bounding capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounding: Vec<String>,
    /// Inheritable capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inheritable: Vec<String>,
    /// Permitted capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permitted: Vec<String>,
    /// Ambient capabilities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ambient: Vec<String>,
}

/// User identity configuration (POSIX).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// User ID.
    #[serde(default)]
    pub uid: u32,
    /// Group ID.
    #[serde(default)]
    pub gid: u32,
    /// File creation mask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub umask: Option<u32>,
    /// Additional group IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

/// I/O priority configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoPriority {
    /// I/O scheduling class.
    pub class: String,
    /// Priority within class.
    pub priority: i32,
}

/// Process scheduler configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scheduler {
    /// Scheduling policy.
    pub policy: String,
    /// Nice value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nice: Option<i32>,
    /// Priority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    /// Scheduler flags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// Runtime (for deadline scheduler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<u64>,
    /// Deadline (for deadline scheduler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deadline: Option<u64>,
    /// Period (for deadline scheduler).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period: Option<u64>,
}

/// CPU affinity for exec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecCpuAffinity {
    /// Initial CPU affinity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial: Option<String>,
    /// Final CPU affinity.
    #[serde(rename = "final", skip_serializing_if = "Option::is_none")]
    pub final_affinity: Option<String>,
}
