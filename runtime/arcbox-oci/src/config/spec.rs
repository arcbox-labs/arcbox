//! OCI runtime-spec configuration parsing.
//!
//! This module implements the OCI Runtime Specification config.json format.
//! Reference: <https://github.com/opencontainers/runtime-spec/blob/main/config.md>

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::{OciError, Result};
use crate::hooks::Hooks;

use super::{Linux, Mount, Process, Root};

/// OCI specification version supported by this implementation.
pub const OCI_VERSION: &str = "1.2.0";

/// OCI runtime configuration (config.json).
///
/// This is the main configuration structure that defines how a container
/// should be created and run according to the OCI runtime specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    /// OCI specification version (`SemVer` 2.0.0 format).
    /// REQUIRED field.
    pub oci_version: String,

    /// Container's root filesystem.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,

    /// Container process to run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,

    /// Container hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Container domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,

    /// Additional mounts beyond the root filesystem.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<Mount>,

    /// Lifecycle hooks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hooks: Option<Hooks>,

    /// Arbitrary metadata annotations.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,

    /// Linux-specific configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<Linux>,
}

impl Spec {
    /// Load OCI spec from a config.json file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;
        Self::from_json(&content)
    }

    /// Parse OCI spec from JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let spec: Self = serde_json::from_str(json)?;
        spec.validate()?;
        Ok(spec)
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize to JSON and write to file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Validate the specification.
    pub fn validate(&self) -> Result<()> {
        // Validate OCI version format (must be valid SemVer).
        if self.oci_version.is_empty() {
            return Err(OciError::MissingField("ociVersion"));
        }

        // Validate version is parseable as semver.
        if self.oci_version.split('.').count() < 2 {
            return Err(OciError::InvalidVersion(self.oci_version.clone()));
        }

        // Validate root if present.
        if let Some(ref root) = self.root {
            if root.path.is_empty() {
                return Err(OciError::InvalidConfig(
                    "root.path cannot be empty".to_string(),
                ));
            }
        }

        // Validate process if present.
        if let Some(ref process) = self.process {
            if process.cwd.is_empty() {
                return Err(OciError::MissingField("process.cwd"));
            }
            if !process.cwd.starts_with('/') {
                return Err(OciError::InvalidConfig(
                    "process.cwd must be an absolute path".to_string(),
                ));
            }
        }

        // Validate mounts.
        for (i, mount) in self.mounts.iter().enumerate() {
            if mount.destination.is_empty() {
                return Err(OciError::InvalidConfig(format!(
                    "mounts[{i}].destination cannot be empty"
                )));
            }
            if !mount.destination.starts_with('/') {
                return Err(OciError::InvalidConfig(format!(
                    "mounts[{i}].destination must be an absolute path"
                )));
            }
        }

        Ok(())
    }

    /// Create a default spec for Linux containers.
    #[must_use]
    pub fn default_linux() -> Self {
        Self {
            oci_version: OCI_VERSION.to_string(),
            root: Some(Root {
                path: "rootfs".to_string(),
                readonly: false,
            }),
            process: Some(Process::default()),
            hostname: None,
            domainname: None,
            mounts: Self::default_mounts(),
            hooks: None,
            annotations: HashMap::new(),
            linux: Some(Linux::default()),
        }
    }

    /// Returns the default mounts for a Linux container.
    fn default_mounts() -> Vec<Mount> {
        vec![
            Mount {
                destination: "/proc".to_string(),
                source: Some("proc".to_string()),
                mount_type: Some("proc".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/dev".to_string(),
                source: Some("tmpfs".to_string()),
                mount_type: Some("tmpfs".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "strictatime".to_string(),
                    "mode=755".to_string(),
                    "size=65536k".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/dev/pts".to_string(),
                source: Some("devpts".to_string()),
                mount_type: Some("devpts".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "newinstance".to_string(),
                    "ptmxmode=0666".to_string(),
                    "mode=0620".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/dev/shm".to_string(),
                source: Some("shm".to_string()),
                mount_type: Some("tmpfs".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "mode=1777".to_string(),
                    "size=65536k".to_string(),
                ]),
                ..Default::default()
            },
            Mount {
                destination: "/sys".to_string(),
                source: Some("sysfs".to_string()),
                mount_type: Some("sysfs".to_string()),
                options: Some(vec![
                    "nosuid".to_string(),
                    "noexec".to_string(),
                    "nodev".to_string(),
                    "ro".to_string(),
                ]),
                ..Default::default()
            },
        ]
    }
}
