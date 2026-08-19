use std::path::{Path, PathBuf};

use arcbox_vm_driver::{CgroupSpec, IsolationSpec};
use serde::{Deserialize, Serialize};

use crate::error::VmmError;

/// The per-VM isolation half of `[firecracker.jailer]`.
///
/// Who the VMM runs as, where its chroot lives, which namespaces and
/// cgroup it enters — everything [`IsolationSpec`] carries. The jailer
/// binary and the rlimits it applies are node-wide and belong to whoever
/// builds the adapter that spawns it; they stay in the same TOML table,
/// read by that composer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JailerConfig {
    /// UID the Firecracker process runs as inside the jail.
    pub uid: u32,
    /// GID the Firecracker process runs as inside the jail.
    pub gid: u32,
    /// Base chroot directory (default: `/srv/jailer`).
    pub chroot_base_dir: Option<String>,
    /// Network namespace path (e.g., `/var/run/netns/myns`).
    pub netns: Option<String>,
    /// Create a new PID namespace.
    #[serde(default)]
    pub new_pid_ns: bool,
    /// cgroup version (`"1"` or `"2"`).
    pub cgroup_version: Option<String>,
    /// Parent cgroup path.
    pub parent_cgroup: Option<String>,
}

impl JailerConfig {
    /// The jailer's default chroot base, used when the config names none.
    pub const DEFAULT_CHROOT_BASE: &'static str = "/srv/jailer";

    /// The chroot base the jailer actually uses: the configured directory,
    /// or the jailer's own default.
    pub fn chroot_base(&self) -> &Path {
        Path::new(
            self.chroot_base_dir
                .as_deref()
                .unwrap_or(Self::DEFAULT_CHROOT_BASE),
        )
    }
}

impl TryFrom<&JailerConfig> for IsolationSpec {
    type Error = VmmError;

    /// Who the VMM runs as, where its chroot lives, which namespaces and
    /// cgroup it enters.
    ///
    /// A `parent_cgroup` without a `cgroup_version` keeps the jailer's own
    /// default, version 1, made explicit here because the spec's
    /// [`CgroupSpec`] always names a version.
    fn try_from(jc: &JailerConfig) -> Result<Self, VmmError> {
        let cgroup = match (jc.cgroup_version.as_deref(), jc.parent_cgroup.as_deref()) {
            (None, None) => None,
            (version, parent) => Some(CgroupSpec {
                version: match version {
                    None => 1,
                    Some("1") => 1,
                    Some("2") => 2,
                    Some(other) => {
                        return Err(VmmError::Config(format!(
                            "jailer cgroup_version must be \"1\" or \"2\", got {other:?}"
                        )));
                    }
                },
                parent: parent.map(str::to_owned),
            }),
        };
        Ok(Self::Jailer {
            uid: jc.uid,
            gid: jc.gid,
            chroot_base: jc.chroot_base().to_path_buf(),
            netns: jc.netns.as_deref().map(PathBuf::from),
            new_pid_ns: jc.new_pid_ns,
            cgroup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jailer() -> JailerConfig {
        JailerConfig {
            uid: 1000,
            gid: 1000,
            chroot_base_dir: None,
            netns: None,
            new_pid_ns: false,
            cgroup_version: None,
            parent_cgroup: None,
        }
    }

    #[test]
    fn isolation_defaults_the_chroot_base_and_carries_no_cgroup_when_unset() {
        let spec = IsolationSpec::try_from(&jailer()).unwrap();
        assert_eq!(
            spec,
            IsolationSpec::Jailer {
                uid: 1000,
                gid: 1000,
                chroot_base: PathBuf::from("/srv/jailer"),
                netns: None,
                new_pid_ns: false,
                cgroup: None,
            }
        );
    }

    #[test]
    fn isolation_maps_the_cgroup_fields_and_the_jailer_default_version() {
        let mut jc = jailer();
        jc.chroot_base_dir = Some("/jail".into());
        jc.netns = Some("/var/run/netns/x".into());
        jc.new_pid_ns = true;
        jc.cgroup_version = Some("2".into());
        jc.parent_cgroup = Some("arcbox".into());
        let IsolationSpec::Jailer {
            chroot_base,
            netns,
            new_pid_ns,
            cgroup,
            ..
        } = IsolationSpec::try_from(&jc).unwrap()
        else {
            panic!("jailer config converts to jailer isolation");
        };
        assert_eq!(chroot_base, PathBuf::from("/jail"));
        assert_eq!(netns, Some(PathBuf::from("/var/run/netns/x")));
        assert!(new_pid_ns);
        assert_eq!(
            cgroup,
            Some(CgroupSpec {
                version: 2,
                parent: Some("arcbox".into())
            })
        );

        // A parent alone rides on the jailer's default cgroup version.
        jc.cgroup_version = None;
        let IsolationSpec::Jailer { cgroup, .. } = IsolationSpec::try_from(&jc).unwrap() else {
            unreachable!()
        };
        assert_eq!(cgroup.map(|c| c.version), Some(1));

        jc.cgroup_version = Some("v2".into());
        assert!(matches!(
            IsolationSpec::try_from(&jc),
            Err(VmmError::Config(_))
        ));
    }
}
