//! Finding a Firecracker that outlived the process which booted it.
//!
//! The recorded pid may have been recycled since the record was written —
//! by another Firecracker, on a busy node — so it is held to the same
//! identity test as any other candidate: a Firecracker (`/proc/<pid>/comm`)
//! whose command line names the VM (`--id`) or its API socket
//! (`--api-sock`), or whose root is the VM's jail. Those are the three
//! signatures the sandbox manager's restart sweep keys on, and the recorded
//! pid only saves the `/proc` scan that looks for the same thing.
//!
//! All three read `/proc`, so nothing is adopted off Linux: an unverified
//! pid is a VM this driver would later signal, and Firecracker needs KVM
//! anyway.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{IsolationSpec, VmRecord};

use crate::config::FcDriverConfig;

/// A live Firecracker matching a record, with what a handle needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The process.
    pub pid: u32,
    /// The API socket as the host connects to it.
    pub api_socket: PathBuf,
    /// The confinement the process runs under, as far as `/proc` tells:
    /// jailed (uid, gid and chroot base read back; namespaces and cgroup
    /// unknown) or not.
    pub isolation: IsolationSpec,
}

/// The Firecracker `record` names, if one is still running.
pub fn find(config: &FcDriverConfig, record: &VmRecord) -> Option<Found> {
    let recorded_socket = record.process.as_ref().and_then(|p| p.api_socket.clone());
    let identity = Identity::of(config, record, recorded_socket.as_deref());
    let pid = record
        .process
        .as_ref()
        .map(|p| p.pid)
        .filter(|pid| identity.matches(*pid))
        .or_else(|| identity.scan_proc())?;
    let jail_root = jail_root_of(pid);
    let api_socket = recorded_socket
        .or_else(|| cmdline_api_socket(pid, jail_root.as_deref()))
        .unwrap_or_else(|| default_api_socket(jail_root.as_deref(), &record.runtime_dir));
    let isolation = match jail_root {
        Some(root) => {
            let (uid, gid) = process_ids(pid).unwrap_or((0, 0));
            // {chroot_base}/{exec}/{id}/root → chroot_base.
            let chroot_base = root.ancestors().nth(3).map_or_else(
                || PathBuf::from(crate::jail::DEFAULT_CHROOT_BASE),
                Path::to_path_buf,
            );
            IsolationSpec::Jailer {
                uid,
                gid,
                chroot_base,
                netns: None,
                new_pid_ns: false,
                cgroup: None,
            }
        }
        None => IsolationSpec::None,
    };
    Some(Found {
        pid,
        api_socket,
        isolation,
    })
}

/// True when `pid` is alive and (on Linux) named like a Firecracker binary.
fn process_is_firecracker(pid: u32) -> bool {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "Firecracker pid fits platform pid_t"
    )]
    if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_err() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            Ok(comm) => comm.trim_end().starts_with("firecracker"),
            Err(_) => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        true
    }
}

/// The chroot a jailed Firecracker runs in, read from `/proc/<pid>/root`;
/// `None` for an unjailed process (root is `/`) or off Linux.
fn jail_root_of(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/root"))
            .ok()
            .filter(|root| root != Path::new("/"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Where a VMM that named no socket must be listening: the jailer's fixed
/// in-jail location when the process is chrooted, else where a direct spawn
/// for this record would have put it.
///
/// The jailer execs Firecracker without `--api-sock`, so a jailed VMM binds
/// its own default (`/run/firecracker.socket`) and says so nowhere a reader
/// of `/proc` can see it. Its host path is the jail's — the same path
/// [`VmLayout::api_socket`](crate::render::VmLayout::api_socket) hands the
/// spawn, through the same [`jail::api_socket_path`]. Falling through to the
/// direct-mode path instead dials a socket nobody bound, and an adopt that
/// cannot reach the API settles for a process it can only kill.
fn default_api_socket(jail_root: Option<&Path>, runtime_dir: &Path) -> PathBuf {
    match jail_root {
        Some(root) => crate::jail::api_socket_path(root),
        None => runtime_dir.join("firecracker.sock"),
    }
}

/// The `--api-sock` argument of `pid`, made absolute against its jail root
/// when it is chroot-relative.
fn cmdline_api_socket(pid: u32, jail_root: Option<&Path>) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let socket = cmdline_arg(&bytes, b"--api-sock")?;
        let socket = PathBuf::from(String::from_utf8_lossy(socket).into_owned());
        Some(match jail_root {
            Some(root) => root.join(socket.strip_prefix("/").unwrap_or(&socket)),
            None => socket,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, jail_root);
        None
    }
}

/// The real uid and gid of `pid`, from `/proc/<pid>/status`.
fn process_ids(pid: u32) -> Option<(u32, u32)> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse::<u32>().ok())
        };
        Some((field("Uid:")?, field("Gid:")?))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// What makes a running process *this* VM: the id on its command line, the
/// API socket it was given, or the jail it is chrooted into.
struct Identity<'a> {
    id: &'a str,
    /// The direct-mode API socket: the recorded one, else where a direct
    /// spawn for this record would have put it.
    socket: PathBuf,
    /// `{firecracker binary name}/{id}/root`, the tail of the VM's jail.
    jail_tail: Option<PathBuf>,
}

impl<'a> Identity<'a> {
    fn of(config: &FcDriverConfig, record: &'a VmRecord, socket: Option<&Path>) -> Self {
        Self {
            id: record.id.as_str(),
            socket: socket.map_or_else(
                || record.runtime_dir.join("firecracker.sock"),
                Path::to_path_buf,
            ),
            jail_tail: config
                .firecracker_binary
                .file_name()
                .map(|exec| Path::new(exec).join(record.id.as_str()).join("root")),
        }
    }

    /// True when `pid` is a live Firecracker that this record names.
    fn matches(&self, pid: u32) -> bool {
        process_is_firecracker(pid) && self.identifies(Path::new("/proc").join(pid.to_string()))
    }

    /// True when the `/proc` entry's command line or root names this VM.
    #[cfg(target_os = "linux")]
    fn identifies(&self, proc_dir: PathBuf) -> bool {
        let by_cmdline = std::fs::read(proc_dir.join("cmdline"))
            .ok()
            .is_some_and(|bytes| cmdline_matches(&bytes, self.id, &self.socket));
        let by_jail = self.jail_tail.as_ref().is_some_and(|tail| {
            std::fs::read_link(proc_dir.join("root"))
                .ok()
                .is_some_and(|root| root.ends_with(tail))
        });
        by_cmdline || by_jail
    }

    /// Identity is a `/proc` question; off Linux there is nothing to ask.
    #[cfg(not(target_os = "linux"))]
    fn identifies(&self, _proc_dir: PathBuf) -> bool {
        let _ = (self.id, &self.socket, &self.jail_tail);
        false
    }

    /// Scan `/proc` for the VM: `--id {id}`, `--api-sock {socket}`, or a
    /// root ending in `{exec}/{id}/root`.
    #[cfg(target_os = "linux")]
    fn scan_proc(&self) -> Option<u32> {
        let entries = std::fs::read_dir("/proc").ok()?;
        entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
                process_is_firecracker(pid).then_some((pid, entry.path()))
            })
            .find(|(_, proc_dir)| self.identifies(proc_dir.clone()))
            .map(|(pid, _)| pid)
    }

    #[cfg(not(target_os = "linux"))]
    fn scan_proc(&self) -> Option<u32> {
        None
    }
}

/// The value following `flag` in a NUL-separated command line.
#[cfg(any(target_os = "linux", test))]
fn cmdline_arg<'a>(bytes: &'a [u8], flag: &[u8]) -> Option<&'a [u8]> {
    let args: Vec<_> = bytes
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1])
}

/// True when the command line names VM `id` or its direct-mode socket.
#[cfg(any(target_os = "linux", test))]
fn cmdline_matches(bytes: &[u8], id: &str, socket: &Path) -> bool {
    cmdline_arg(bytes, b"--id") == Some(id.as_bytes())
        || cmdline_arg(bytes, b"--api-sock") == Some(socket.as_os_str().as_encoded_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dead_pid_is_not_firecracker() {
        // PID 0 targets "the calling process group" for kill(2); use an
        // implausibly high PID instead.
        assert!(!process_is_firecracker(
            u32::try_from(i32::MAX - 1).unwrap()
        ));
    }

    #[test]
    fn firecracker_command_line_matches_only_the_owned_id_or_socket() {
        let socket = Path::new("/var/lib/arcbox/sandbox/sandboxes/box/firecracker.sock");
        assert!(cmdline_matches(
            b"firecracker\0--api-sock\0/var/lib/arcbox/sandbox/sandboxes/box/firecracker.sock\0",
            "box",
            socket
        ));
        assert!(cmdline_matches(b"firecracker\0--id\0box\0", "box", socket));
        assert!(!cmdline_matches(
            b"firecracker\0--id\0other\0",
            "box",
            socket
        ));
        assert_eq!(
            cmdline_arg(
                b"firecracker\0--api-sock\0/run/firecracker.socket\0--id\0box\0",
                b"--api-sock"
            ),
            Some(&b"/run/firecracker.socket"[..])
        );
        assert_eq!(cmdline_arg(b"firecracker\0--id\0", b"--id"), None);
    }

    /// A jailed VMM names its socket nowhere — not in the record the sweep
    /// rebuilds from its journal, not on its command line — so the fallback
    /// is the only thing that finds it, and it has to land where the spawn
    /// put it.
    #[test]
    fn a_jailed_vmm_falls_back_to_the_socket_in_its_jail() {
        let config = FcDriverConfig::new("/opt/fc/firecracker");
        let id = arcbox_vm_driver::VmId::new("box").unwrap();
        let runtime_dir = Path::new("/var/tmp/sandboxes/box");
        let isolation = IsolationSpec::Jailer {
            uid: 0,
            gid: 0,
            chroot_base: "/srv/jailer".into(),
            netns: None,
            new_pid_ns: false,
            cgroup: None,
        };
        let layout = crate::render::VmLayout::new(&id, &isolation, &config, runtime_dir).unwrap();
        let jail_root = layout.jail().unwrap().root.clone();

        assert_eq!(
            default_api_socket(Some(&jail_root), runtime_dir),
            layout.api_socket(),
            "adoption must derive the socket the spawn bound"
        );
        assert_eq!(
            default_api_socket(None, runtime_dir),
            runtime_dir.join("firecracker.sock"),
            "an unjailed vmm still answers in its runtime dir"
        );
    }

    #[test]
    fn a_recorded_pid_that_is_not_this_vm_is_not_adopted() {
        // The test binary itself: alive, and nothing about it names the VM.
        let record = VmRecord {
            id: arcbox_vm_driver::VmId::new("recycled").unwrap(),
            driver: crate::NAME.to_owned(),
            runtime_dir: "/nonexistent/arcbox-fc-driver".into(),
            process: Some(arcbox_vm_driver::ProcessRecord {
                pid: std::process::id(),
                api_socket: None,
            }),
        };
        assert!(find(&FcDriverConfig::new("/opt/fc/firecracker"), &record).is_none());
    }

    #[test]
    fn a_record_whose_pid_is_gone_and_names_no_socket_is_not_found() {
        let record = VmRecord {
            id: arcbox_vm_driver::VmId::new("never-booted").unwrap(),
            driver: crate::NAME.to_owned(),
            runtime_dir: "/nonexistent/arcbox-fc-driver".into(),
            process: Some(arcbox_vm_driver::ProcessRecord {
                pid: u32::try_from(i32::MAX - 1).unwrap(),
                api_socket: None,
            }),
        };
        assert!(find(&FcDriverConfig::new("/opt/fc/firecracker"), &record).is_none());
    }
}
