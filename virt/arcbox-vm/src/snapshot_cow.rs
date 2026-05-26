//! Block-level copy-on-write for sandbox rootfs via dm-snapshot.
//!
//! Instead of copying the full rootfs ext4 image for every sandbox,
//! `CowManager` creates a dm-snapshot backed by a sparse COW file.
//! The template image is shared read-only across all sandboxes that
//! use the same rootfs; only written blocks consume disk space.
//!
//! Requires `CONFIG_DM_SNAPSHOT=y` in the guest kernel and the `dmsetup`
//! binary at one of [`DMSETUP_CANDIDATES`].  `PATH` is not searched — the
//! guest does not have a meaningful one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};

use crate::error::{Result, VmmError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Busybox binary (used for `losetup` and `blockdev` applets).
const BUSYBOX: &str = "/bin/busybox";

/// Candidate paths for the `dmsetup` binary.  The first existing entry
/// wins.  `/sbin/dmsetup` covers stock Debian/Alpine; `/usr/sbin/dmsetup`
/// covers usrmerged distros; `/arcbox/bin/dmsetup` is the guest's bundled
/// copy.
const DMSETUP_CANDIDATES: &[&str] = &["/arcbox/bin/dmsetup", "/usr/sbin/dmsetup", "/sbin/dmsetup"];

/// dm-snapshot chunk size in 512-byte sectors (4096 bytes = 8 sectors).
const SNAPSHOT_CHUNK_SECTORS: u64 = 8;

/// Device-mapper name prefix for sandbox snapshots.
const DM_NAME_PREFIX: &str = "arcbox-snap-";

/// Maximum length of a device-mapper name (DM_NAME_LEN - 1, from linux/dm-ioctl.h).
const DM_NAME_MAX_LEN: usize = 127;

/// Validate that `sandbox_id` can be used as the suffix of a dm-name.
///
/// Device-mapper allows `[A-Za-z0-9_+.-]` (see kernel `validate_name`).
/// Sandboxes are most commonly UUIDs, which already pass; this rejects
/// caller-supplied IDs containing whitespace, `/`, `:`, etc., before
/// `dmsetup create` errors out with a confusing message.
fn validate_dm_name_suffix(sandbox_id: &str) -> Result<()> {
    if sandbox_id.is_empty() {
        return Err(VmmError::DeviceMapper("empty sandbox id".into()));
    }
    if DM_NAME_PREFIX.len() + sandbox_id.len() > DM_NAME_MAX_LEN {
        return Err(VmmError::DeviceMapper(format!(
            "sandbox id too long for dm-name (max {} chars after prefix)",
            DM_NAME_MAX_LEN - DM_NAME_PREFIX.len()
        )));
    }
    if let Some(bad) = sandbox_id
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '.' | '-')))
    {
        return Err(VmmError::DeviceMapper(format!(
            "sandbox id contains character {bad:?} not allowed in dm-name"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Tracks a read-only loop device for a template rootfs image.
struct TemplateEntry {
    /// Loop device path, e.g. `/dev/loop0`.
    loop_device: String,
    /// Template size in 512-byte sectors.
    sectors: u64,
    /// Number of active sandboxes using this template.
    refcount: usize,
}

/// Per-sandbox CoW state.  Stored in `SandboxInstance` for cleanup.
///
/// Intentionally `!Clone`: every handle owns a refcount on its template,
/// and a stray clone would double-decrement on teardown.
#[derive(Debug)]
pub struct CowHandle {
    /// dm device name, e.g. `arcbox-snap-<sandbox_id>`.
    pub dm_name: String,
    /// Absolute device path, e.g. `/dev/mapper/arcbox-snap-<sandbox_id>`.
    pub dm_device: String,
    /// Loop device backing the sparse COW file.
    pub cow_loop: String,
    /// Path to the sparse COW file on disk.
    pub cow_file: PathBuf,
    /// Original template rootfs path (used to release the template refcount).
    pub template_path: PathBuf,
}

/// Manages template loop devices and per-sandbox dm-snapshot lifecycle.
pub struct CowManager {
    templates: Mutex<HashMap<PathBuf, TemplateEntry>>,
    /// Serializes `losetup -f` + `losetup DEV FILE` to prevent TOCTOU races
    /// where concurrent callers get the same free loop device.
    losetup_lock: AsyncMutex<()>,
    cow_dir: PathBuf,
    dmsetup_bin: Option<String>,
}

// ---------------------------------------------------------------------------
// CowManager
// ---------------------------------------------------------------------------

impl CowManager {
    /// Create a new manager.  `data_dir` is the Firecracker data directory
    /// (e.g. `/var/lib/firecracker-vmm`); COW files are stored under
    /// `{data_dir}/cow/`.
    pub fn new(data_dir: &str) -> std::io::Result<Self> {
        let cow_dir = PathBuf::from(data_dir).join("cow");
        std::fs::create_dir_all(&cow_dir)?;

        let dmsetup_bin = DMSETUP_CANDIDATES
            .iter()
            .find(|p| Path::new(p).exists())
            .map(|s| (*s).to_string());

        if dmsetup_bin.is_none() {
            warn!("dmsetup not found; dm-snapshot CoW will be unavailable");
        }

        let mgr = Self {
            templates: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir,
            dmsetup_bin,
        };

        // Clean up orphaned dm devices and COW files from a previous crash.
        mgr.cleanup_stale_sync();

        Ok(mgr)
    }

    /// Create a dm-snapshot for `sandbox_id` using `rootfs_path` as template.
    ///
    /// Returns a [`CowHandle`] whose `dm_device` field can be passed to
    /// Firecracker as the rootfs block device.
    pub async fn setup(&self, sandbox_id: &str, rootfs_path: &str) -> Result<CowHandle> {
        validate_dm_name_suffix(sandbox_id)?;

        let dmsetup = self
            .dmsetup_bin
            .as_deref()
            .ok_or_else(|| VmmError::DeviceMapper("dmsetup binary not found".into()))?;

        let template = PathBuf::from(rootfs_path);

        // --- 1. Acquire template loop device (shared, refcounted) -----------
        //
        // Fast path: cache hit under the sync mutex, no I/O needed.
        // Slow path: hold the async losetup_lock across attach+insert so a
        // concurrent first-time setup of the same template cannot race ahead,
        // attach a second loop device, and leak the loser's entry on insert.
        let (template_loop, sectors) = 'acquire: {
            // Fast path under the sync mutex.
            if let Some(cached) = {
                let mut templates = self.templates.lock().unwrap();
                templates.get_mut(&template).map(|entry| {
                    entry.refcount += 1;
                    debug!(
                        template = %rootfs_path,
                        loop_dev = %entry.loop_device,
                        refcount = entry.refcount,
                        "reusing template loop device"
                    );
                    (entry.loop_device.clone(), entry.sectors)
                })
            } {
                break 'acquire cached;
            }

            // Slow path: serialize attach+insert across all concurrent
            // first-time callers for this template.
            let _losetup_guard = self.losetup_lock.lock().await;

            // Re-check the cache: another caller may have populated it while
            // we were waiting for the lock.
            if let Some(cached) = {
                let mut templates = self.templates.lock().unwrap();
                templates.get_mut(&template).map(|entry| {
                    entry.refcount += 1;
                    debug!(
                        template = %rootfs_path,
                        loop_dev = %entry.loop_device,
                        refcount = entry.refcount,
                        "reusing template loop device (after lock)"
                    );
                    (entry.loop_device.clone(), entry.sectors)
                })
            } {
                break 'acquire cached;
            }

            // Genuinely first to attach — do the work and publish the entry
            // before releasing the lock.
            let loop_dev = losetup_attach(BUSYBOX, Path::new(rootfs_path), true).await?;
            let sectors = blockdev_getsz(BUSYBOX, &loop_dev).await.inspect_err(|_| {
                let ld = loop_dev.clone();
                tokio::spawn(async move {
                    let _ = losetup_detach(BUSYBOX, &ld).await;
                });
            })?;
            debug!(
                template = %rootfs_path,
                loop_dev = %loop_dev,
                sectors,
                "attached new template loop device"
            );
            {
                let mut templates = self.templates.lock().unwrap();
                templates.insert(
                    template.clone(),
                    TemplateEntry {
                        loop_device: loop_dev.clone(),
                        sectors,
                        refcount: 1,
                    },
                );
            }
            (loop_dev, sectors)
        };

        // --- 2. Create sparse COW file (O(1), no actual I/O) ---------------
        let cow_file = self.cow_dir.join(format!("arcbox-cow-{sandbox_id}.img"));
        let cow_size = sectors * 512;
        if let Err(e) = create_sparse_file(&cow_file, cow_size).await {
            self.release_template(&template);
            return Err(e);
        }

        // --- 3. Attach COW file as a loop device ----------------------------
        let cow_loop_result = {
            let losetup_guard = self.losetup_lock.lock().await;
            let result = losetup_attach(BUSYBOX, &cow_file, false).await;
            drop(losetup_guard);
            result
        };
        let cow_loop = match cow_loop_result {
            Ok(dev) => dev,
            Err(e) => {
                let _ = std::fs::remove_file(&cow_file);
                self.release_template(&template);
                return Err(e);
            }
        };

        // --- 4. Create dm-snapshot device -----------------------------------
        let dm_name = format!("{DM_NAME_PREFIX}{sandbox_id}");
        let table =
            format!("0 {sectors} snapshot {template_loop} {cow_loop} P {SNAPSHOT_CHUNK_SECTORS}");

        if let Err(e) = dmsetup_create(dmsetup, &dm_name, &table).await {
            let _ = losetup_detach(BUSYBOX, &cow_loop).await;
            let _ = std::fs::remove_file(&cow_file);
            self.release_template(&template);
            return Err(e);
        }

        let dm_device = format!("/dev/mapper/{dm_name}");
        info!(
            sandbox_id,
            dm_device = %dm_device,
            cow_file = %cow_file.display(),
            "dm-snapshot created"
        );

        Ok(CowHandle {
            dm_name,
            dm_device,
            cow_loop,
            cow_file,
            template_path: template,
        })
    }

    /// Tear down a dm-snapshot.  Best-effort: each step logs errors but
    /// continues to the next so resources are not leaked.  The return type
    /// is intentionally `()` — callers cannot do anything more useful than
    /// log on individual step failures, which this function already does.
    pub async fn teardown(&self, handle: &CowHandle) {
        let dmsetup = self.dmsetup_bin.as_deref().unwrap_or("dmsetup");

        // 1. Remove dm device.
        let dm_removed = dmsetup_remove(dmsetup, &handle.dm_name).await.is_ok();
        if !dm_removed {
            warn!(dm = %handle.dm_name, "failed to remove dm device");
        }

        // 2. Detach COW loop device.
        let loop_detached = losetup_detach(BUSYBOX, &handle.cow_loop).await.is_ok();
        if !loop_detached {
            warn!(loop_dev = %handle.cow_loop, "failed to detach cow loop");
        }

        // 3. Delete COW sparse file only after both dm and loop are released.
        //    Unlinking while still referenced would delay space reclamation
        //    until the last kernel reference drops.
        if dm_removed && loop_detached {
            if let Err(e) = std::fs::remove_file(&handle.cow_file) {
                warn!(file = %handle.cow_file.display(), error = %e, "failed to remove cow file");
            }
        } else {
            warn!(
                file = %handle.cow_file.display(),
                "skipping cow file removal — backing resources not fully released"
            );
        }

        // 4. Release template refcount.
        self.release_template(&handle.template_path);

        info!(sandbox = %handle.dm_name, "dm-snapshot teardown complete");
    }

    /// Remove orphaned dm-snapshot devices and COW files left over from a
    /// previous crash.  Called once at startup before a tokio runtime is
    /// guaranteed to exist, so this is intentionally synchronous.
    fn cleanup_stale_sync(&self) {
        let dmsetup = match self.dmsetup_bin.as_deref() {
            Some(bin) => bin,
            None => return,
        };

        // Remove stale dm devices.
        if let Ok(output) = Command::new(dmsetup)
            .args(["ls", "--target", "snapshot"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(name) = line.split_whitespace().next()
                    && name.starts_with(DM_NAME_PREFIX)
                {
                    debug!(dm = %name, "removing stale dm-snapshot");
                    let _ = Command::new(dmsetup).args(["remove", name]).output();
                }
            }
        }

        // Remove stale COW files and detach associated loop devices.
        let entries = match std::fs::read_dir(&self.cow_dir) {
            Ok(e) => e,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("arcbox-cow-"))
            {
                if let Ok(output) = Command::new(BUSYBOX)
                    .args(["losetup", "-j", path.to_str().unwrap_or("")])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if let Some(dev) = line.split(':').next() {
                            let _ = Command::new(BUSYBOX)
                                .args(["losetup", "-d", dev.trim()])
                                .output();
                        }
                    }
                }
                debug!(file = %path.display(), "removing stale cow file");
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Decrement the refcount for a template; detach its loop device when
    /// the count reaches zero.
    fn release_template(&self, template_path: &Path) {
        let mut templates = self.templates.lock().unwrap();
        let should_detach = if let Some(entry) = templates.get_mut(template_path) {
            entry.refcount = entry.refcount.saturating_sub(1);
            if entry.refcount == 0 {
                Some(entry.loop_device.clone())
            } else {
                None
            }
        } else {
            None
        };

        if let Some(loop_dev) = should_detach {
            templates.remove(template_path);
            // Fire-and-forget detach (we are under a sync Mutex, cannot await).
            tokio::spawn(async move {
                if let Err(e) = losetup_detach(BUSYBOX, &loop_dev).await {
                    warn!(loop_dev = %loop_dev, error = %e, "failed to detach template loop");
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/// Run a synchronous [`Command`] on a blocking thread.
///
/// `tokio::process::Command` conflicts with the PID-1 SIGCHLD reaper
/// (`spawn_reaper`), causing `ECHILD` errors.  Using `std::process::Command`
/// inside `spawn_blocking` avoids this because `waitpid` is called
/// synchronously before the signal can be stolen.
async fn run_cmd(mut cmd: Command) -> Result<std::process::Output> {
    tokio::task::spawn_blocking(move || cmd.output())
        .await
        .map_err(|e| VmmError::DeviceMapper(format!("spawn_blocking join: {e}")))?
        .map_err(|e| VmmError::DeviceMapper(format!("command spawn: {e}")))
}

/// Attach a file as a loop device.  Returns the device path (e.g. `/dev/loop0`).
///
/// Uses busybox-compatible two-step approach: `busybox losetup -f` to find a
/// free device, then `busybox losetup [-r] DEV FILE` to attach.
async fn losetup_attach(bin: &str, path: &Path, read_only: bool) -> Result<String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| VmmError::DeviceMapper("non-UTF-8 path".into()))?;

    // Step 1: find a free loop device.
    let mut find_cmd = Command::new(bin);
    find_cmd.args(["losetup", "-f"]);
    let output = run_cmd(find_cmd).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!("losetup -f: {stderr}")));
    }
    let dev = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if dev.is_empty() {
        return Err(VmmError::DeviceMapper(
            "losetup -f returned empty device".into(),
        ));
    }

    // Step 2: attach the file to that device.
    let mut attach_cmd = Command::new(bin);
    if read_only {
        attach_cmd.args(["losetup", "-r", &dev, path_str]);
    } else {
        attach_cmd.args(["losetup", &dev, path_str]);
    }
    let output = run_cmd(attach_cmd).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "losetup {dev} {}: {stderr}",
            path.display()
        )));
    }

    Ok(dev)
}

/// Detach a loop device.
async fn losetup_detach(bin: &str, dev: &str) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(["losetup", "-d", dev]);

    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "losetup -d {dev}: {stderr}"
        )));
    }
    Ok(())
}

/// Get the size of a block device in 512-byte sectors.
async fn blockdev_getsz(bin: &str, dev: &str) -> Result<u64> {
    let mut cmd = Command::new(bin);
    cmd.args(["blockdev", "--getsz", dev]);

    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "blockdev --getsz {dev}: {stderr}"
        )));
    }

    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u64>()
        .map_err(|e| VmmError::DeviceMapper(format!("blockdev parse: {e}")))
}

/// Create a dm-snapshot device via `dmsetup create`.
async fn dmsetup_create(bin: &str, name: &str, table: &str) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(["create", name, "--table", table]);

    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "dmsetup create {name}: {stderr}"
        )));
    }
    Ok(())
}

/// Remove a dm device via `dmsetup remove`.
async fn dmsetup_remove(bin: &str, name: &str) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(["remove", name]);

    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "dmsetup remove {name}: {stderr}"
        )));
    }
    Ok(())
}

/// Create a sparse file of the given size in bytes.
async fn create_sparse_file(path: &Path, size: u64) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::create(&path)
            .map_err(|e| VmmError::DeviceMapper(format!("create cow file: {e}")))?;
        file.set_len(size)
            .map_err(|e| VmmError::DeviceMapper(format!("truncate cow file: {e}")))?;
        Ok(())
    })
    .await
    .map_err(|e| VmmError::DeviceMapper(format!("spawn_blocking join: {e}")))?
}

/// Get the `(major, minor)` device numbers for a block device.
///
/// Uses `busybox stat -c '%t %T'` which prints major and minor in hex.
pub async fn device_major_minor(path: &str) -> Result<(u32, u32)> {
    let mut cmd = Command::new(BUSYBOX);
    cmd.args(["stat", "-c", "%t %T", path]);
    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!("stat {path}: {stderr}")));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.split_whitespace().collect();
    if parts.len() != 2 {
        return Err(VmmError::DeviceMapper(format!(
            "unexpected stat output for {path}: {stdout}"
        )));
    }
    let major = u32::from_str_radix(parts[0], 16)
        .map_err(|e| VmmError::DeviceMapper(format!("parse major: {e}")))?;
    let minor = u32::from_str_radix(parts[1], 16)
        .map_err(|e| VmmError::DeviceMapper(format!("parse minor: {e}")))?;
    Ok((major, minor))
}

/// Create a block device node at `node_path` pointing to `(major, minor)`.
pub async fn mknod_blkdev(node_path: &Path, major: u32, minor: u32) -> Result<()> {
    let path_str = node_path
        .to_str()
        .ok_or_else(|| VmmError::DeviceMapper("non-UTF-8 node path".into()))?;
    let mut cmd = Command::new(BUSYBOX);
    cmd.args([
        "mknod",
        path_str,
        "b",
        &major.to_string(),
        &minor.to_string(),
    ]);
    let output = run_cmd(cmd).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "mknod {path_str}: {stderr}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dm_name_format() {
        let name = format!("{DM_NAME_PREFIX}test-sandbox-123");
        assert_eq!(name, "arcbox-snap-test-sandbox-123");
    }

    #[test]
    fn validate_dm_name_suffix_accepts_uuid_and_basic_ids() {
        validate_dm_name_suffix("550e8400-e29b-41d4-a716-446655440000").unwrap();
        validate_dm_name_suffix("sandbox_1").unwrap();
        validate_dm_name_suffix("a.b+c-d").unwrap();
    }

    #[test]
    fn validate_dm_name_suffix_rejects_invalid_chars() {
        assert!(validate_dm_name_suffix("").is_err());
        assert!(validate_dm_name_suffix("has space").is_err());
        assert!(validate_dm_name_suffix("with/slash").is_err());
        assert!(validate_dm_name_suffix("with:colon").is_err());
        assert!(validate_dm_name_suffix(&"x".repeat(DM_NAME_MAX_LEN)).is_err());
    }

    #[test]
    fn test_cow_file_path() {
        let cow_dir = PathBuf::from("/var/lib/firecracker-vmm/cow");
        let path = cow_dir.join(format!("arcbox-cow-{}.img", "sandbox-1"));
        assert_eq!(
            path,
            PathBuf::from("/var/lib/firecracker-vmm/cow/arcbox-cow-sandbox-1.img")
        );
    }

    #[test]
    fn test_snapshot_table_format() {
        let sectors = 2097152_u64; // 1 GiB
        let table =
            format!("0 {sectors} snapshot /dev/loop0 /dev/loop1 P {SNAPSHOT_CHUNK_SECTORS}");
        assert_eq!(table, "0 2097152 snapshot /dev/loop0 /dev/loop1 P 8");
    }

    #[tokio::test]
    async fn test_release_template_refcount() {
        let mgr = CowManager {
            templates: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir: PathBuf::from("/tmp"),
            dmsetup_bin: None,
        };

        let path = PathBuf::from("/tmp/template.ext4");
        {
            let mut t = mgr.templates.lock().unwrap();
            t.insert(
                path.clone(),
                TemplateEntry {
                    loop_device: "/dev/loop99".into(),
                    sectors: 1024,
                    refcount: 2,
                },
            );
        }

        // First release: refcount 2 → 1, entry stays.
        mgr.release_template(&path);
        {
            let t = mgr.templates.lock().unwrap();
            assert_eq!(t.get(&path).unwrap().refcount, 1);
        }

        // Second release: refcount 1 → 0, entry removed.
        // (losetup_detach is spawned but won't run in sync test — that's fine,
        // we just verify the map entry is removed.)
        mgr.release_template(&path);
        {
            let t = mgr.templates.lock().unwrap();
            assert!(!t.contains_key(&path));
        }
    }
}
