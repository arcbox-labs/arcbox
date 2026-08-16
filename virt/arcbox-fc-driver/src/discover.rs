//! Finding a Firecracker that outlived the process which booted it.
//!
//! The recorded pid may have been recycled since the record was written, so
//! it counts only while its command name still looks like Firecracker
//! (`/proc/<pid>/comm` on Linux; elsewhere the check degrades to "process
//! exists"). On Linux, `/proc` is also scanned for a Firecracker whose
//! command line names the VM (`--id`) or its API socket (`--api-sock`), or
//! whose root is the VM's jail — the same three signatures the sandbox
//! manager's restart sweep keys on.

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
    let pid = record
        .process
        .as_ref()
        .map(|p| p.pid)
        .filter(|pid| process_is_firecracker(*pid))
        .or_else(|| scan_proc(config, record, recorded_socket.as_deref()))?;
    let jail_root = jail_root_of(pid);
    let api_socket = recorded_socket
        .or_else(|| cmdline_api_socket(pid, jail_root.as_deref()))
        .unwrap_or_else(|| record.runtime_dir.join("firecracker.sock"));
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

/// Scan `/proc` for a Firecracker that names the VM: `--id {id}`,
/// `--api-sock {socket}`, or a root ending in `{exec}/{id}/root`.
#[cfg(target_os = "linux")]
fn scan_proc(config: &FcDriverConfig, record: &VmRecord, socket: Option<&Path>) -> Option<u32> {
    let direct_socket = socket.map_or_else(
        || record.runtime_dir.join("firecracker.sock"),
        Path::to_path_buf,
    );
    let jail_tail = config
        .firecracker_binary
        .file_name()
        .map(|exec| Path::new(exec).join(record.id.as_str()).join("root"));
    let entries = std::fs::read_dir("/proc").ok()?;
    entries
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let pid = entry.file_name().to_str()?.parse::<u32>().ok()?;
            process_is_firecracker(pid).then_some((pid, entry.path()))
        })
        .find(|(_, proc_dir)| {
            let direct_match = std::fs::read(proc_dir.join("cmdline"))
                .ok()
                .is_some_and(|bytes| cmdline_matches(&bytes, record.id.as_str(), &direct_socket));
            let jail_match = jail_tail.as_ref().is_some_and(|tail| {
                std::fs::read_link(proc_dir.join("root"))
                    .ok()
                    .is_some_and(|root| root.ends_with(tail))
            });
            direct_match || jail_match
        })
        .map(|(pid, _)| pid)
}

#[cfg(not(target_os = "linux"))]
fn scan_proc(_config: &FcDriverConfig, _record: &VmRecord, _socket: Option<&Path>) -> Option<u32> {
    None
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
