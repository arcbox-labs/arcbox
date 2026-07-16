//! Host-side NFSv4 mount of the guest docker data export at `~/ArcBox`.
//!
//! The guest agent exports `/var/lib/docker` read-only over NFSv4, which serves
//! everything on the single well-known port 2049 (no MOUNT protocol). This
//! module runs one localhost TCP proxy and bridges it to the guest over vsock:
//!
//! ```text
//! mount_nfs -o vers=4,port=<nfsd> 127.0.0.1:/ ~/ArcBox
//!   └─ 127.0.0.1:<nfsd> → vsock NFS_NFSD_RELAY_PORT → guest 127.0.0.1:2049
//! ```
//!
//! Readiness needs no separate probe: the reconcile simply retries `mount_nfs`
//! until the guest server answers, so the mount is its own liveness check and
//! the path works identically on the HV and VZ backends.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Result, bail};
use arcbox_constants::ports::NFS_NFSD_RELAY_PORT;
use arcbox_core::{DEFAULT_MACHINE_NAME, Runtime};
use arcbox_transport::vsock::{VsockShutdown, VsockStream};
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::context::DaemonContext;

const MOUNT_TIMEOUT: Duration = Duration::from_secs(30);
const MOUNT_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// Path this daemon successfully mounted, set once by the reconcile task.
/// [`cleanup`] only unmounts what this process created — a daemon that never
/// completed its mount must not unmount whatever else sits at `~/ArcBox`.
static MOUNTED_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Spawns the background task that mounts the guest export at `~/ArcBox`.
pub fn spawn(ctx: &DaemonContext, runtime: &Arc<Runtime>) {
    if !ctx.mount_nfs {
        return;
    }

    let runtime = Arc::clone(runtime);
    let shutdown = ctx.shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = reconcile(runtime, shutdown).await {
            warn!(error = %e, "failed to establish host NFS mount at ~/ArcBox");
        }
    });
}

/// Unmounts `~/ArcBox` on shutdown, but only the mount this daemon created.
pub fn cleanup(ctx: &DaemonContext) {
    if !ctx.mount_nfs {
        return;
    }

    // Never mounted (startup raced shutdown, or the mount failed): whatever
    // sits at the path is not ours to touch.
    let Some(mount_path) = MOUNTED_PATH.get() else {
        return;
    };

    // Re-check the shape in case the user replaced the mount since.
    match current_mount_info(mount_path) {
        Some(info) if is_arcbox_nfs_mount(&info) => match unmount(mount_path) {
            Ok(()) => info!(path = %mount_path.display(), "unmounted ~/ArcBox host NFS mount"),
            Err(e) => warn!(path = %mount_path.display(), error = %e, "failed to unmount ~/ArcBox"),
        },
        _ => {}
    }
}

async fn reconcile(runtime: Arc<Runtime>, shutdown: CancellationToken) -> Result<()> {
    let Some(mount_path) = resolve_mount_path() else {
        bail!("could not determine home directory for ~/ArcBox mount");
    };

    // One localhost TCP proxy to the guest nfsd, bridged over vsock.
    let nfsd_port = spawn_proxy(&runtime, &shutdown, NFS_NFSD_RELAY_PORT).await?;

    reconcile_existing_mount(&mount_path)?;
    std::fs::create_dir_all(&mount_path)?;

    mount_with_retry(&mount_path, nfsd_port, &shutdown).await
}

/// Binds a localhost TCP proxy that relays each connection to `vsock_port` on
/// the guest, and returns the local port it is listening on.
async fn spawn_proxy(
    runtime: &Arc<Runtime>,
    shutdown: &CancellationToken,
    vsock_port: u32,
) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    debug!(local_port, vsock_port, "NFS proxy listening");

    let runtime = Arc::clone(runtime);
    let shutdown = shutdown.clone();
    tokio::spawn(run_proxy(listener, runtime, shutdown, vsock_port));
    Ok(local_port)
}

async fn run_proxy(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
    vsock_port: u32,
) {
    loop {
        let stream = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            result = listener.accept() => match result {
                Ok((stream, _)) => stream,
                Err(e) => {
                    warn!(vsock_port, error = %e, "NFS proxy accept failed");
                    continue;
                }
            }
        };

        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(e) = relay_connection(stream, runtime, vsock_port).await {
                debug!(vsock_port, error = %e, "NFS proxy relay failed");
            }
        });
    }
}

async fn relay_connection(
    mut tcp: tokio::net::TcpStream,
    runtime: Arc<Runtime>,
    vsock_port: u32,
) -> Result<()> {
    // connect_vsock_port is a blocking hypervisor call on both backends.
    let fd = tokio::task::spawn_blocking(move || {
        runtime.connect_vsock_port(DEFAULT_MACHINE_NAME, vsock_port)
    })
    .await??;

    // SAFETY: `fd` is a valid, newly-opened vsock fd handed over by the
    // hypervisor layer; ownership transfers to the OwnedFd here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut vsock = VsockStream::from_fd_with_shutdown(owned, VsockShutdown::CloseOnDropOnly)?;

    copy_bidirectional(&mut tcp, &mut vsock).await?;
    Ok(())
}

/// Retries `mount_nfs` until it succeeds, the deadline passes, or shutdown.
///
/// The guest export comes up shortly after dockerd; while it is not yet
/// answering, `mount_nfs` fails fast (the guest relay resets the connection),
/// so retrying is the readiness signal.
async fn mount_with_retry(
    mount_path: &Path,
    nfsd_port: u16,
    shutdown: &CancellationToken,
) -> Result<()> {
    let source = mount_source();
    let opts = render_mount_opts(nfsd_port);
    let deadline = tokio::time::Instant::now() + MOUNT_TIMEOUT;

    loop {
        if shutdown.is_cancelled() {
            bail!("daemon shutdown before ~/ArcBox mount completed");
        }

        match run_mount(&opts, &source, mount_path).await {
            Ok(()) => {
                let _ = MOUNTED_PATH.set(mount_path.to_path_buf());
                info!(
                    path = %mount_path.display(),
                    nfsd_port,
                    "mounted guest docker data at ~/ArcBox (NFSv4, read-only)"
                );
                return Ok(());
            }
            Err(e) if tokio::time::Instant::now() >= deadline => {
                bail!("mount_nfs did not succeed within {MOUNT_TIMEOUT:?}: {e}");
            }
            Err(e) => debug!(error = %e, "mount_nfs attempt failed, retrying"),
        }

        tokio::time::sleep(MOUNT_RETRY_INTERVAL).await;
    }
}

async fn run_mount(opts: &str, source: &str, mount_path: &Path) -> Result<(), String> {
    let opts = opts.to_string();
    let source = source.to_string();
    let mount_path = mount_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let output = Command::new("/sbin/mount_nfs")
            .arg("-o")
            .arg(&opts)
            .arg(&source)
            .arg(&mount_path)
            .output()
            .map_err(|e| format!("failed to execute mount_nfs: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "mount_nfs exited with {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    })
    .await
    .map_err(|e| format!("mount_nfs task panicked: {e}"))?
}

/// The `host:/path` source string for `mount_nfs`. The export carries
/// `fsid=0`, so it is the NFSv4 pseudo-root at `/`.
fn mount_source() -> String {
    "127.0.0.1:/".to_string()
}

/// Read-only NFSv4 mount options with the nfsd port pinned.
///
/// - `deadtimeout=60`: a vanished VM makes the mount fail I/O after 60s instead
///   of hanging Finder forever (macOS rejects `soft` with `vers=4`).
/// - `rdirplus`: fetch attributes with directory entries — fewer round trips.
/// - `actimeo=10`: modest attribute cache for a browse mount.
fn render_mount_opts(nfsd_port: u16) -> String {
    format!("ro,vers=4,rdirplus,actimeo=10,deadtimeout=60,port={nfsd_port}")
}

/// Host mount point: `$ARCBOX_HOST_MOUNT_DIR` when set (so a test daemon stays
/// off the shared `~/ArcBox`), otherwise `~/ArcBox`.
fn resolve_mount_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("ARCBOX_HOST_MOUNT_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::home_dir().map(|home| resolve_mount_path_from_home(&home))
}

fn resolve_mount_path_from_home(home: &Path) -> PathBuf {
    home.join("ArcBox")
}

/// Removes a stale ArcBox NFS mount, or errors if the path is otherwise taken.
///
/// Only a mount matching our exact shape (`nfs` from `127.0.0.1:/`) is
/// replaced — that is a leftover from a previous daemon whose local proxy is
/// gone, so it is dead weight. Anything else at the path, including a foreign
/// NFS mount, is someone else's and makes the reconcile bail.
fn reconcile_existing_mount(mount_path: &Path) -> Result<()> {
    match current_mount_info(mount_path) {
        Some(info) if is_arcbox_nfs_mount(&info) => {
            info!(path = %mount_path.display(), "replacing stale ~/ArcBox NFS mount");
            unmount(mount_path)
        }
        Some(info) => bail!(
            "~/ArcBox path {} already occupied by {} ({})",
            mount_path.display(),
            info.source,
            info.fstype
        ),
        None => Ok(()),
    }
}

/// True when the mount at the path has exactly the shape this daemon creates:
/// NFS from the v4 pseudo-root of the localhost proxy.
fn is_arcbox_nfs_mount(info: &MountInfo) -> bool {
    info.fstype == "nfs" && info.source == mount_source()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfo {
    source: String,
    fstype: String,
}

fn current_mount_info(path: &Path) -> Option<MountInfo> {
    let output = Command::new("/sbin/mount").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let target = path.to_string_lossy();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| match parse_mount_line(line) {
            Some((mountpoint, info)) if mountpoint == target => Some(info),
            _ => None,
        })
}

/// Parses one `/sbin/mount` line: `SOURCE on MOUNTPOINT (fstype, opts…)`.
fn parse_mount_line(line: &str) -> Option<(&str, MountInfo)> {
    let (source, rest) = line.split_once(" on ")?;
    let (mountpoint, suffix) = rest.split_once(" (")?;
    let fstype = suffix
        .split([',', ')'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();

    Some((
        mountpoint,
        MountInfo {
            source: source.to_string(),
            fstype,
        },
    ))
}

fn unmount(path: &Path) -> Result<()> {
    let status = Command::new("/sbin/umount").arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        bail!("umount exited with {}", status.code().unwrap_or(-1))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MountInfo, is_arcbox_nfs_mount, mount_source, parse_mount_line, render_mount_opts,
        resolve_mount_path_from_home,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn only_our_exact_mount_shape_is_reclaimed() {
        let ours = MountInfo {
            source: "127.0.0.1:/".to_string(),
            fstype: "nfs".to_string(),
        };
        assert!(is_arcbox_nfs_mount(&ours));

        // A user's own NFS mount at ~/ArcBox must never be unmounted.
        let foreign_nfs = MountInfo {
            source: "fileserver:/export/home".to_string(),
            fstype: "nfs".to_string(),
        };
        assert!(!is_arcbox_nfs_mount(&foreign_nfs));

        let smb = MountInfo {
            source: "//user@server/share".to_string(),
            fstype: "smbfs".to_string(),
        };
        assert!(!is_arcbox_nfs_mount(&smb));
    }

    #[test]
    fn mount_path_is_arcbox_under_home() {
        assert_eq!(
            resolve_mount_path_from_home(Path::new("/Users/tester")),
            PathBuf::from("/Users/tester/ArcBox")
        );
    }

    #[test]
    fn mount_opts_are_readonly_v4_with_nfsd_port_pinned() {
        let opts = render_mount_opts(51000);
        assert!(opts.contains("vers=4"));
        assert!(opts.contains("ro,"));
        assert!(opts.contains("port=51000"));
        // Must never request write access to a read-only export.
        assert!(!opts.contains("rw"));
    }

    #[test]
    fn mount_source_is_the_v4_pseudo_root() {
        assert_eq!(mount_source(), "127.0.0.1:/");
    }

    #[test]
    fn parse_mount_line_extracts_source_and_fstype() {
        let line =
            "127.0.0.1:/run/arcbox/nfs-export/docker on /Users/t/ArcBox (nfs, nodev, read-only)";
        let (mountpoint, info) = parse_mount_line(line).expect("line should parse");
        assert_eq!(mountpoint, "/Users/t/ArcBox");
        assert_eq!(
            info,
            MountInfo {
                source: "127.0.0.1:/run/arcbox/nfs-export/docker".to_string(),
                fstype: "nfs".to_string(),
            }
        );
    }
}
