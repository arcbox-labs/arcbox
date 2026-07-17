//! Guest-side NFSv4 export of the dockerd data mount.
//!
//! Configures the in-kernel Linux nfsd to export `/var/lib/docker` read-only
//! over NFSv4, reachable from the macOS host through a single vsock relay (see
//! `run_nfs_relay`). The host mounts it at `~/ArcBox`.
//!
//! NFSv4 (not v3) is deliberate. NFSv4 serves everything on the well-known
//! port 2049 and does not register with the portmapper, so the guest needs no
//! `rpcbind` — which it does not ship and which the in-kernel NFSv3 server
//! fatally requires. It also removes the MOUNT protocol, so a single relay
//! suffices. NFSv4's grace period is ended immediately after nfsd starts
//! (there is a single read-only client with no lock state to reclaim), so
//! file opens are never deferred; the `nfsdcld`/`rpc_pipefs` client-tracking
//! machinery that stalled the earlier attempt is not used.
//!
//! `rpc.mountd` still runs locally: the kernel calls it to authorize export
//! access even under NFSv4, but the client never contacts it.
//!
//! All writable state lives on the guest's tmpfs layers (`/run`, `/var`,
//! `/etc`) that sit over the read-only EROFS root, so no rootfs asset carries
//! an export mountpoint.

/// Guest-local TCP port for the kernel nfsd (NFS protocol).
pub const NFSD_PORT: u16 = 2049;
/// Guest-local TCP port the mount daemon (`rpc.mountd`) is pinned to. The
/// kernel calls mountd for NFSv4 export-access upcalls; no client connects.
pub const MOUNTD_PORT: u16 = 20048;

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use arcbox_constants::paths::DOCKER_DATA_MOUNT_POINT;
    use nix::mount::{MsFlags, mount};

    use super::{MOUNTD_PORT, NFSD_PORT};

    const EXPORT_DOCKER: &str = "/run/arcbox/nfs-export/docker";
    const NFSD_MOUNTPOINT: &str = "/proc/fs/nfsd";
    const NFS_STATE_DIR: &str = "/var/lib/nfs";
    const EXPORTS_PATH: &str = "/etc/exports";
    const NETCONFIG_PATH: &str = "/etc/netconfig";
    const NFSD_THREADS: &str = "4";

    /// Minimal libtirpc netconfig. The guest rootfs ships none, and without it
    /// `rpc.mountd` logs "No V2 or V3 listeners created" and serves nothing;
    /// the TCP entry is the one the host client uses.
    const NETCONFIG_CONTENTS: &str = "\
udp        tpi_clts      v     inet     udp     -       -
tcp        tpi_cots_ord  v     inet     tcp     -       -
udp6       tpi_clts      v     inet6    udp     -       -
tcp6       tpi_cots_ord  v     inet6    tcp     -       -
local      tpi_cots_ord  -     loopback  -       -       -
";

    /// Immutable guest-side NFS export configuration.
    ///
    /// nfsd keeps its well-known 2049 port (never overridden), so only the
    /// pinned mountd port needs to be carried here.
    pub struct ExportConfig<'a> {
        pub export_docker: &'a str,
        pub exports_path: &'a str,
        pub mountd_port: u16,
        pub threads: &'a str,
    }

    impl Default for ExportConfig<'_> {
        fn default() -> Self {
            Self {
                export_docker: EXPORT_DOCKER,
                exports_path: EXPORTS_PATH,
                mountd_port: MOUNTD_PORT,
                threads: NFSD_THREADS,
            }
        }
    }

    /// Brings up the read-only NFSv4 export of the docker data mount.
    ///
    /// Idempotent: every step checks for an existing mount/process first, so
    /// re-running after a partial setup converges rather than erroring.
    pub fn ensure_docker_export() -> Result<Vec<String>, String> {
        let cfg = ExportConfig::default();
        let mut notes = Vec::new();

        // Writable dirs on the tmpfs layers over the read-only EROFS root.
        fs::create_dir_all(cfg.export_docker)
            .map_err(|e| format!("mkdir {} failed({e})", cfg.export_docker))?;
        fs::create_dir_all(NFS_STATE_DIR)
            .map_err(|e| format!("mkdir {NFS_STATE_DIR} failed({e})"))?;

        ensure_nfsd_mount()?;

        if !is_mounted(cfg.export_docker) {
            tracing::info!(
                source = DOCKER_DATA_MOUNT_POINT,
                target = cfg.export_docker,
                "nfs export: binding docker data mount read-only"
            );
            bind_readonly(DOCKER_DATA_MOUNT_POINT, cfg.export_docker)?;
            notes.push(format!(
                "bound {DOCKER_DATA_MOUNT_POINT} -> {} (ro)",
                cfg.export_docker
            ));
        }

        write_exports(&cfg).map_err(|e| format!("write {} failed({e})", cfg.exports_path))?;
        refresh_exports()?;
        notes.push("refreshed exportfs".to_string());

        ensure_netconfig()?;

        if !mountd_running() && !tcp_port_ready(cfg.mountd_port) {
            spawn_mountd(&cfg)?;
            notes.push(format!("spawned rpc.mountd on port {}", cfg.mountd_port));
        }

        ensure_nfsd_threads(&cfg)?;
        notes.push(format!("ensured nfsd threads={}", cfg.threads));

        tracing::info!(
            export_ready = export_ready(),
            mountd_ready = mountd_ready(),
            nfsd_ready = nfsd_ready(),
            "nfs export: ensure complete"
        );

        Ok(notes)
    }

    /// True once the docker bind mount and the export table are in place.
    fn export_ready() -> bool {
        is_mounted(EXPORT_DOCKER) && Path::new(EXPORTS_PATH).exists()
    }

    /// True once `rpc.mountd` is serving the MOUNT protocol on its pinned port.
    fn mountd_ready() -> bool {
        mountd_running() && tcp_port_ready(MOUNTD_PORT)
    }

    /// True once kernel nfsd has live threads and is accepting NFS on 2049.
    fn nfsd_ready() -> bool {
        nfsd_thread_count().is_some_and(|count| count > 0) && tcp_port_ready(NFSD_PORT)
    }

    fn ensure_nfsd_mount() -> Result<(), String> {
        if is_mounted(NFSD_MOUNTPOINT) {
            return Ok(());
        }

        fs::create_dir_all(NFSD_MOUNTPOINT)
            .map_err(|e| format!("mkdir {NFSD_MOUNTPOINT} failed({e})"))?;
        mount(
            Some("nfsd"),
            NFSD_MOUNTPOINT,
            Some("nfsd"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|e| format!("mount -t nfsd {NFSD_MOUNTPOINT} failed({e})"))?;
        tracing::info!(
            target = NFSD_MOUNTPOINT,
            "nfs export: mounted nfsd pseudo-fs"
        );
        Ok(())
    }

    /// Bind-mounts `source` at `target`, then remounts the bind read-only.
    ///
    /// A read-only remount is a separate `mount(2)` call — the `MS_RDONLY` on
    /// the initial `MS_BIND` is ignored by the kernel.
    fn bind_readonly(source: &str, target: &str) -> Result<(), String> {
        mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind mount {source} -> {target} failed({e})"))?;

        mount(
            None::<&str>,
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| format!("remount readonly {target} failed({e})"))
    }

    fn write_exports(cfg: &ExportConfig<'_>) -> io::Result<()> {
        fs::write(cfg.exports_path, render_exports(cfg))
    }

    fn refresh_exports() -> Result<(), String> {
        run_checked("/sbin/exportfs", &["-ra"])
    }

    /// Writes a minimal libtirpc netconfig if the rootfs ships none, so
    /// `rpc.mountd` can create its RPC listeners. `/etc` is a writable tmpfs.
    fn ensure_netconfig() -> Result<(), String> {
        if Path::new(NETCONFIG_PATH).exists() {
            return Ok(());
        }
        fs::write(NETCONFIG_PATH, NETCONFIG_CONTENTS)
            .map_err(|e| format!("write {NETCONFIG_PATH} failed({e})"))
    }

    /// Spawns `rpc.mountd` in the foreground, pinned to its port. Under NFSv4
    /// no client contacts it, but the kernel still calls it to authorize
    /// export access. Registration with a portmapper is not needed (and there
    /// is no `rpcbind`); the listener is created directly.
    ///
    /// A watcher thread reaps the child and logs its exit: a dead mountd
    /// leaves every kernel export upcall unanswered, which wedges the host's
    /// `mount_nfs` in uninterruptible sleep with zero diagnostics. Reaping
    /// also keeps the zombie from satisfying the [`mountd_running`] respawn
    /// guard forever.
    fn spawn_mountd(cfg: &ExportConfig<'_>) -> Result<(), String> {
        let port = cfg.mountd_port.to_string();
        let mut child = Command::new("/sbin/rpc.mountd")
            .args(["-F", "-p", &port])
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(daemon_log_file("rpc.mountd"))
            .stderr(daemon_log_file("rpc.mountd"))
            .spawn()
            .map_err(|e| format!("failed to spawn rpc.mountd: {e}"))?;
        tracing::info!(
            pid = child.id(),
            port = cfg.mountd_port,
            "nfs export: rpc.mountd spawned"
        );
        std::thread::spawn(move || match child.wait() {
            Ok(status) => tracing::warn!(%status, "nfs export: rpc.mountd exited"),
            // On the legacy PID-1 path the supervisor's global waitpid(-1)
            // reaper can win the race; its own log line carries the status.
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                tracing::debug!("nfs export: rpc.mountd reaped by the global reaper");
            }
            Err(e) => tracing::warn!(error = %e, "nfs export: rpc.mountd wait failed"),
        });
        // Let the listener bind before returning so a repeat setup pass sees
        // the port taken and does not spawn a second, conflicting mountd.
        for _ in 0..20 {
            if tcp_port_ready(cfg.mountd_port) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }

    /// Brings up kernel nfsd by writing `/proc/fs/nfsd` directly.
    ///
    /// NFSv4 only: it serves on the well-known port 2049 and does not register
    /// with a portmapper, so it starts cleanly without an `rpcbind` (which the
    /// guest rootfs does not ship, and which the NFSv3 server path fatally
    /// requires). NFSv3/v2 are disabled. Writing a positive thread count makes
    /// the kernel open the 2049 listener.
    fn ensure_nfsd_threads(cfg: &ExportConfig<'_>) -> Result<(), String> {
        write_proc("/proc/fs/nfsd/versions", "+4 -3")?;
        set_grace_fallback();
        write_proc("/proc/fs/nfsd/threads", cfg.threads)?;
        end_grace_early();
        Ok(())
    }

    /// Best-effort: cap the grace period at the kernel minimum (10s) before
    /// threads start. Only a fallback — [`end_grace_early`] normally ends the
    /// grace period outright the moment nfsd is up. The lease time is left at
    /// the kernel default (90s) so the host client renews it rarely instead of
    /// every few seconds.
    fn set_grace_fallback() {
        if let Err(e) = fs::write("/proc/fs/nfsd/nfsv4gracetime", "10") {
            tracing::debug!(error = %e, "nfs export: could not cap v4 grace (non-fatal)");
        }
    }

    /// Best-effort: end the NFSv4 grace period immediately. During grace the
    /// server defers new OPENs to let prior clients reclaim state, but this
    /// export has a single read-only client with nothing to reclaim. Requires
    /// running nfsd threads (the kernel returns EBUSY otherwise); repeat
    /// writes are no-ops once grace has ended.
    fn end_grace_early() {
        if let Err(e) = fs::write("/proc/fs/nfsd/v4_end_grace", "Y") {
            tracing::debug!(error = %e, "nfs export: could not end v4 grace early (non-fatal)");
        }
    }

    fn write_proc(path: &str, value: &str) -> Result<(), String> {
        fs::write(path, format!("{value}\n")).map_err(|e| format!("write {path} failed({e})"))
    }

    fn run_checked(program: &str, args: &[&str]) -> Result<(), String> {
        let output = Command::new(program)
            .args(args)
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output()
            .map_err(|e| format!("failed to execute {program}: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{program} {} exited with {} stderr='{}' stdout='{}'",
                args.join(" "),
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim(),
                String::from_utf8_lossy(&output.stdout).trim()
            ))
        }
    }

    fn mountd_running() -> bool {
        process_named("rpc.mountd")
    }

    /// True when a live (non-zombie) process with this comm exists. Zombies
    /// keep their comm until reaped, and a zombie mountd must not satisfy the
    /// respawn guard — that is exactly the state that wedges the host mount.
    fn process_named(name: &str) -> bool {
        let Ok(entries) = fs::read_dir("/proc") else {
            return false;
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_str() else {
                continue;
            };
            if !pid.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
                continue;
            };
            if comm.trim() != name {
                continue;
            }
            let is_zombie = fs::read_to_string(entry.path().join("stat"))
                .ok()
                .and_then(|stat| {
                    // State is the first field after the parenthesized comm.
                    let after = stat.rsplit_once(')')?.1.trim_start();
                    after.chars().next()
                })
                .is_some_and(|state| state == 'Z');
            if !is_zombie {
                return true;
            }
        }

        false
    }

    fn nfsd_thread_count() -> Option<u32> {
        fs::read_to_string("/proc/fs/nfsd/threads")
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    fn tcp_port_ready(port: u16) -> bool {
        std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
    }

    fn is_mounted(path: &str) -> bool {
        mounted_fstype(path).is_some()
    }

    fn mounted_fstype(path: &str) -> Option<String> {
        fs::read_to_string("/proc/mounts").ok().and_then(|content| {
            content.lines().find_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                match (parts.get(1), parts.get(2)) {
                    (Some(&mountpoint), Some(&fstype)) if mountpoint == path => {
                        Some(fstype.to_string())
                    }
                    _ => None,
                }
            })
        })
    }

    /// Renders the single `/etc/exports` entry.
    ///
    /// - `127.0.0.1/32`: only the guest-local vsock relay ever connects.
    /// - `ro`: read-only export.
    /// - `insecure`: the relay's source port is unprivileged (>1024).
    /// - `all_squash,anonuid=0,anongid=0`: nfsd reads as root, so every layer
    ///   and volume is served regardless of on-disk ownership.
    /// - `fsid=0`: a fixed id keeps file handles stable across daemon restarts.
    fn render_exports(cfg: &ExportConfig<'_>) -> String {
        format!(
            "{} 127.0.0.1/32(ro,fsid=0,no_subtree_check,insecure,all_squash,anonuid=0,anongid=0)\n",
            cfg.export_docker
        )
    }

    fn daemon_log_file(name: &str) -> Stdio {
        let log_dir = format!("/arcbox/{}", arcbox_constants::paths::guest::LOG);
        let arcbox_path = format!("{log_dir}/{name}.log");
        let tmp_log_path = format!("/tmp/{name}.log");

        let log_path = if Path::new("/arcbox").exists() {
            let _ = fs::create_dir_all(&log_dir);
            &arcbox_path
        } else {
            &tmp_log_path
        };

        match fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            Ok(file) => file.into(),
            Err(_) => match fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp_log_path)
            {
                Ok(file) => file.into(),
                Err(_) => Stdio::null(),
            },
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{ExportConfig, render_exports};

        #[test]
        fn render_exports_is_readonly_and_localhost_only() {
            let rendered = render_exports(&ExportConfig::default());
            assert!(rendered.starts_with("/run/arcbox/nfs-export/docker 127.0.0.1/32("));
            assert!(rendered.contains("ro,"));
            assert!(rendered.contains("fsid=0"));
            assert!(rendered.contains("insecure"));
            assert!(rendered.contains("all_squash"));
            // Read-only export must never advertise write access.
            assert!(!rendered.contains("(rw"));
            assert!(!rendered.contains(",rw"));
        }

        #[test]
        fn default_export_targets_the_docker_bind() {
            let cfg = ExportConfig::default();
            assert_eq!(cfg.export_docker, "/run/arcbox/nfs-export/docker");
            assert_eq!(cfg.mountd_port, 20048);
        }
    }
}

#[cfg(target_os = "linux")]
pub use platform::ensure_docker_export;

/// Bidirectional vsock→TCP relay for one NFS service.
///
/// Accepts vsock connections on `vsock_port` and relays each to
/// `127.0.0.1:tcp_target_port` (the guest-local nfsd or rpc.mountd). This lets
/// the host daemon reach the guest NFS services over vsock, independent of any
/// guest NIC. NFSv3 needs two of these — one for nfsd, one for rpc.mountd.
#[cfg(target_os = "linux")]
pub async fn run_nfs_relay(
    cancel: tokio_util::sync::CancellationToken,
    vsock_port: u32,
    tcp_target_port: u16,
) {
    use tokio::io::copy_bidirectional;
    use tokio::net::TcpStream;
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

    let addr = VsockAddr::new(VMADDR_CID_ANY, vsock_port);
    let mut listener = match VsockListener::bind(addr) {
        Ok(l) => {
            tracing::info!(vsock_port, tcp_target_port, "NFS vsock relay listening");
            l
        }
        Err(e) => {
            tracing::error!(vsock_port, error = %e, "failed to bind NFS vsock relay");
            return;
        }
    };

    loop {
        let stream = tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::info!(vsock_port, "NFS vsock relay shutting down");
                return;
            }
            result = listener.accept() => match result {
                Ok((stream, _)) => stream,
                Err(e) => {
                    tracing::warn!(vsock_port, error = %e, "NFS vsock relay accept failed");
                    continue;
                }
            }
        };

        tokio::spawn(async move {
            match TcpStream::connect(("127.0.0.1", tcp_target_port)).await {
                Ok(mut tcp) => {
                    let mut vsock = stream;
                    if let Err(e) = copy_bidirectional(&mut vsock, &mut tcp).await {
                        tracing::debug!(tcp_target_port, error = %e, "NFS relay copy error");
                    }
                }
                Err(e) => {
                    tracing::warn!(tcp_target_port, error = %e, "NFS relay: connect to local service failed");
                }
            }
        });
    }
}
