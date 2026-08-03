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
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

/// Subdirectory of `cow_dir` holding template-loop marker files for
/// crash recovery.  Each file is named after the loop's basename (e.g.
/// `loop0`) and contains the absolute path of the backing template; on
/// startup we use these to identify *our* attached read-only loops
/// rather than every read-only loop on the system.
const TEMPLATE_LOOP_DIR: &str = ".template-loops";
const TEMPLATE_PENDING_PREFIX: &str = "pending-";
const TEMPLATE_MARKER_TEMP_PREFIX: &str = ".tmp-";

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

#[derive(Clone, Default)]
struct SetupOrphan {
    pending_template_marker: Option<PathBuf>,
    template_loop: Option<(String, PathBuf)>,
    template_path: Option<PathBuf>,
    dm_name: Option<String>,
    cow_loop: Option<String>,
    cow_file: Option<PathBuf>,
}

impl SetupOrphan {
    fn is_empty(&self) -> bool {
        self.pending_template_marker.is_none()
            && self.template_loop.is_none()
            && self.template_path.is_none()
            && self.dm_name.is_none()
            && self.cow_loop.is_none()
            && self.cow_file.is_none()
    }
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
    setup_orphans: Mutex<HashMap<String, SetupOrphan>>,
    /// Serializes the cache-miss attach+insert window so two concurrent
    /// first-time setups for the same template converge on a single
    /// `TemplateEntry` instead of each attaching its own loop device and
    /// leaking the loser.  (TOCTOU on `losetup -f` itself is handled by
    /// the kernel via `losetup --show`.)
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
    pub fn new(data_dir: &str) -> Result<Self> {
        let data_dir = PathBuf::from(data_dir);
        let cow_dir = data_dir.join("cow");
        let marker_dir = cow_dir.join(TEMPLATE_LOOP_DIR);
        std::fs::create_dir_all(&marker_dir)?;
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&cow_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&marker_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::File::open(&marker_dir)?.sync_all()?;
        std::fs::File::open(&cow_dir)?.sync_all()?;
        std::fs::File::open(&data_dir)?.sync_all()?;

        let dmsetup_bin = DMSETUP_CANDIDATES
            .iter()
            .find(|p| Path::new(p).exists())
            .map(|s| (*s).to_string());

        if dmsetup_bin.is_none() {
            warn!("dmsetup not found; dm-snapshot CoW will be unavailable");
        }

        Ok(Self {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir,
            dmsetup_bin,
        })
    }

    /// Create a dm-snapshot for `sandbox_id` using `rootfs_path` as template.
    ///
    /// Returns a [`CowHandle`] whose `dm_device` field can be passed to
    /// Firecracker as the rootfs block device.
    pub async fn setup(&self, sandbox_id: &str, rootfs_path: &str) -> Result<CowHandle> {
        validate_dm_name_suffix(sandbox_id)?;
        if self.setup_orphans.lock().unwrap().contains_key(sandbox_id) {
            return Err(VmmError::Unavailable(format!(
                "sandbox {sandbox_id} still owns resources from an incomplete CoW setup"
            )));
        }

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
                let entry = templates.get_mut(&template);
                if entry.as_ref().is_some_and(|entry| entry.refcount == 0) {
                    return Err(VmmError::Unavailable(format!(
                        "template {} still owns resources from an incomplete CoW setup",
                        template.display()
                    )));
                }
                entry.map(|entry| {
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
                let entry = templates.get_mut(&template);
                if entry.as_ref().is_some_and(|entry| entry.refcount == 0) {
                    return Err(VmmError::Unavailable(format!(
                        "template {} still owns resources from an incomplete CoW setup",
                        template.display()
                    )));
                }
                entry.map(|entry| {
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
            let pending = self.write_template_pending(sandbox_id, &template)?;
            let loop_dev = match losetup_attach(BUSYBOX, Path::new(rootfs_path), true).await {
                Ok(loop_dev) => loop_dev,
                Err(error) => {
                    return Err(self
                        .abort_template_acquisition(sandbox_id, &pending, None, &template, error)
                        .await);
                }
            };
            // Persist ownership before publishing the loop. If the marker
            // cannot be made durable, detach immediately rather than creating
            // a resource that restart reconciliation cannot identify.
            if let Err(error) = self.write_template_marker(&loop_dev, &template) {
                return Err(self
                    .abort_template_acquisition(
                        sandbox_id,
                        &pending,
                        Some(&loop_dev),
                        &template,
                        error,
                    )
                    .await);
            }
            let sectors = match blockdev_getsz(BUSYBOX, &loop_dev).await {
                Ok(sectors) => sectors,
                Err(error) => {
                    return Err(self
                        .abort_template_acquisition(
                            sandbox_id,
                            &pending,
                            Some(&loop_dev),
                            &template,
                            error,
                        )
                        .await);
                }
            };
            if let Err(error) = clear_owner_marker(&pending) {
                return Err(self
                    .abort_template_acquisition(
                        sandbox_id,
                        &pending,
                        Some(&loop_dev),
                        &template,
                        error,
                    )
                    .await);
            }
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
        if let Err((e, owns_file)) = create_sparse_file(&cow_file, cow_size).await {
            return Err(self
                .rollback_setup(
                    sandbox_id,
                    &template,
                    None,
                    None,
                    owns_file.then_some(cow_file.as_path()),
                    e,
                )
                .await);
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
                return Err(self
                    .rollback_setup(sandbox_id, &template, None, None, Some(&cow_file), e)
                    .await);
            }
        };

        // --- 4. Create dm-snapshot device -----------------------------------
        let dm_name = format!("{DM_NAME_PREFIX}{sandbox_id}");
        let table =
            format!("0 {sectors} snapshot {template_loop} {cow_loop} P {SNAPSHOT_CHUNK_SECTORS}");

        if let Err(e) = dmsetup_create(dmsetup, &dm_name, &table).await {
            return Err(self
                .rollback_setup(
                    sandbox_id,
                    &template,
                    Some(&dm_name),
                    Some(&cow_loop),
                    Some(&cow_file),
                    e,
                )
                .await);
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

    /// Tear down a dm-snapshot, logging any incomplete cleanup.
    pub async fn teardown(&self, handle: &CowHandle) {
        if let Err(error) = self.teardown_checked(handle).await {
            warn!(dm = %handle.dm_name, error = %error, "dm-snapshot teardown incomplete");
        }
    }

    /// Tear down a dm-snapshot and report whether every owned resource was
    /// released. Crash reconciliation and durable Remove use this result to
    /// avoid declaring cleanup complete when a retry is still required.
    pub async fn teardown_checked(&self, handle: &CowHandle) -> Result<()> {
        let dmsetup = self
            .dmsetup_bin
            .as_deref()
            .ok_or_else(|| VmmError::DeviceMapper("dmsetup binary not found".into()))?;
        let mut failures = Vec::new();

        // 1. Remove dm device.
        let dm_removed = if !Path::new(&handle.dm_device).exists() {
            true
        } else {
            match dmsetup_remove(dmsetup, &handle.dm_name).await {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("remove {}: {error}", handle.dm_name));
                    false
                }
            }
        };

        // 2. Detach COW loop device.
        let loop_detached = if loop_backs_path(&handle.cow_loop, &handle.cow_file)? {
            match losetup_detach(BUSYBOX, &handle.cow_loop).await {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("detach {}: {error}", handle.cow_loop));
                    false
                }
            }
        } else {
            match loop_devices_for_backing_sync(&handle.cow_file) {
                Ok(devices) if devices.is_empty() => true,
                Ok(devices) => {
                    failures.push(format!(
                        "{} is still attached through {} after {} changed ownership",
                        handle.cow_file.display(),
                        devices.join(", "),
                        handle.cow_loop
                    ));
                    false
                }
                Err(error) => {
                    failures.push(format!(
                        "verify loop ownership for {}: {error}",
                        handle.cow_file.display()
                    ));
                    false
                }
            }
        };

        // 3. Delete COW sparse file only after both dm and loop are released.
        //    Unlinking while still referenced would delay space reclamation
        //    until the last kernel reference drops.
        if dm_removed && loop_detached {
            if let Err(error) = remove_file_durable(&handle.cow_file) {
                failures.push(format!("remove {}: {error}", handle.cow_file.display()));
            }
        }

        if failures.is_empty() {
            // Release the shared template exactly once, after every per-sandbox
            // resource is gone. A failed teardown keeps the handle for retry.
            self.release_template_ref(&handle.template_path, true)
                .await?;
            info!(sandbox = %handle.dm_name, "dm-snapshot teardown complete");
            Ok(())
        } else {
            Err(VmmError::DeviceMapper(failures.join("; ")))
        }
    }

    /// Remove orphaned dm-snapshot devices, COW files, and template loop
    /// devices left over from a previous crash. Called after orphaned
    /// Firecracker processes are dead; it is synchronous because every
    /// command is short and startup is already gated on reconciliation.
    pub(crate) fn reconcile_stale(&self) -> Result<()> {
        let dmsetup = self.dmsetup_bin.as_deref();

        // 1. Remove stale dm devices first — they pin the loop devices
        //    underneath, so the loop detach below would fail otherwise.
        if let Some(dmsetup) = dmsetup {
            let output =
                run_sync_checked(Command::new(dmsetup).args(["ls", "--target", "snapshot"]))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if let Some(name) = line.split_whitespace().next()
                    && name.starts_with(DM_NAME_PREFIX)
                {
                    debug!(dm = %name, "removing stale dm-snapshot");
                    run_sync_checked(Command::new(dmsetup).args(["remove", name]))?;
                }
            }
        }

        // 2. Detach loops backing stale COW files, then unlink the files.
        for entry in std::fs::read_dir(&self.cow_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("arcbox-cow-"))
            {
                for loop_device in loop_devices_for_backing_sync(&path)? {
                    run_sync_checked(Command::new(BUSYBOX).args(["losetup", "-d", &loop_device]))?;
                }
                debug!(file = %path.display(), "removing stale cow file");
                remove_file_durable(&path)?;
            }
        }

        // 3. Detach orphaned template loop devices.
        //
        // Template attaches are tracked only in the in-memory `templates`
        // HashMap, which is empty at startup — without this pass, every
        // crash+restart cycle would permanently leak one read-only loop
        // device per unique rootfs template, eventually exhausting the
        // 256-entry loop namespace.
        //
        // We use marker files written at attach time (under
        // `{cow_dir}/.template-loops/`) rather than a system-wide "any
        // RO loop" scan, so we never touch loops attached by other
        // services in the guest (containerd snapshotter, squashfs mounts).
        self.cleanup_stale_template_markers()?;
        Ok(())
    }

    /// Marker path for the template loop `loop_dev` (e.g.
    /// `{cow_dir}/.template-loops/loop0`).  Returns `None` for a
    /// malformed device path.
    fn template_marker_path(&self, loop_dev: &str) -> Option<PathBuf> {
        let basename = Path::new(loop_dev).file_name()?;
        Some(self.cow_dir.join(TEMPLATE_LOOP_DIR).join(basename))
    }

    fn write_template_marker(&self, loop_dev: &str, template_path: &Path) -> Result<()> {
        let Some(marker) = self.template_marker_path(loop_dev) else {
            return Err(VmmError::DeviceMapper(format!(
                "unparseable template loop device: {loop_dev}"
            )));
        };
        write_owner_marker(&marker, template_path)?;
        Ok(())
    }

    fn write_template_pending(&self, sandbox_id: &str, template_path: &Path) -> Result<PathBuf> {
        let marker = self
            .cow_dir
            .join(TEMPLATE_LOOP_DIR)
            .join(format!("{TEMPLATE_PENDING_PREFIX}{sandbox_id}"));
        write_owner_marker(&marker, template_path)?;
        Ok(marker)
    }

    async fn abort_template_acquisition(
        &self,
        sandbox_id: &str,
        pending: &Path,
        loop_device: Option<&str>,
        template_path: &Path,
        error: VmmError,
    ) -> VmmError {
        let mut failures = Vec::new();
        let detached = match loop_device {
            Some(loop_device) => match self.detach_template_loop(loop_device).await {
                Ok(()) => true,
                Err(cleanup) => {
                    failures.push(cleanup.to_string());
                    false
                }
            },
            None => true,
        };
        if detached && let Err(cleanup) = clear_owner_marker(pending) {
            failures.push(cleanup.to_string());
        }
        if !failures.is_empty() {
            self.setup_orphans.lock().unwrap().insert(
                sandbox_id.to_owned(),
                SetupOrphan {
                    pending_template_marker: Some(pending.to_path_buf()),
                    template_loop: loop_device
                        .map(|loop_device| (loop_device.to_owned(), template_path.to_path_buf())),
                    ..Default::default()
                },
            );
        }
        incomplete_cleanup(error, failures)
    }

    fn cleanup_stale_template_markers(&self) -> Result<()> {
        let dir = self.cow_dir.join(TEMPLATE_LOOP_DIR);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            let marker_path = entry.path();
            let Some(loop_basename) = marker_path.file_name().and_then(|n| n.to_str()) else {
                return Err(VmmError::DeviceMapper(format!(
                    "invalid template marker path: {}",
                    marker_path.display()
                )));
            };
            if loop_basename.starts_with(TEMPLATE_MARKER_TEMP_PREFIX) {
                clear_owner_marker(&marker_path)?;
                continue;
            }
            let expected_backing = std::fs::read_to_string(&marker_path)?.trim().to_string();
            if expected_backing.is_empty() {
                return Err(VmmError::DeviceMapper(format!(
                    "empty template marker: {}",
                    marker_path.display()
                )));
            }
            if loop_basename.starts_with(TEMPLATE_PENDING_PREFIX) {
                for loop_device in loop_devices_for_backing_sync(Path::new(&expected_backing))? {
                    run_sync_checked(Command::new(BUSYBOX).args(["losetup", "-d", &loop_device]))?;
                }
                clear_owner_marker(&marker_path)?;
                continue;
            }

            let dev = format!("/dev/{loop_basename}");
            // Verify the loop is still attached AND still backs the
            // expected template, so we never detach a /dev/loopN that
            // was reused by another process after our crash.
            let actual_backing = loop_backing_path(loop_basename)?;

            if !expected_backing.is_empty()
                && actual_backing.as_deref() == Some(expected_backing.as_str())
            {
                debug!(dev = %dev, "detaching stale template loop");
                run_sync_checked(Command::new(BUSYBOX).args(["losetup", "-d", &dev]))?;
            } else {
                debug!(
                    dev = %dev,
                    expected = %expected_backing,
                    actual = ?actual_backing,
                    "skipping stale template loop: backing mismatch"
                );
            }

            clear_owner_marker(&marker_path)?;
        }
        std::fs::File::open(&dir)?.sync_all()?;
        Ok(())
    }

    async fn rollback_setup(
        &self,
        sandbox_id: &str,
        template_path: &Path,
        dm_name: Option<&str>,
        cow_loop: Option<&str>,
        cow_file: Option<&Path>,
        error: VmmError,
    ) -> VmmError {
        let mut failures = Vec::new();
        let mut orphan = SetupOrphan::default();
        let dm_removed = match dm_name {
            Some(dm_name) if Path::new(&format!("/dev/mapper/{dm_name}")).exists() => {
                let cleanup = match self.dmsetup_bin.as_deref() {
                    Some(dmsetup) => dmsetup_remove(dmsetup, dm_name).await,
                    None => Err(VmmError::DeviceMapper("dmsetup binary not found".into())),
                };
                match cleanup {
                    Ok(()) => true,
                    Err(cleanup) => {
                        failures.push(cleanup.to_string());
                        orphan.dm_name = Some(dm_name.to_owned());
                        false
                    }
                }
            }
            _ => true,
        };
        let cow_detached = match (dm_removed, cow_loop) {
            (false, Some(loop_device)) => {
                orphan.cow_loop = Some(loop_device.to_owned());
                false
            }
            (true, Some(loop_device)) => match losetup_detach(BUSYBOX, loop_device).await {
                Ok(()) => true,
                Err(cleanup) => {
                    failures.push(cleanup.to_string());
                    orphan.cow_loop = Some(loop_device.to_owned());
                    false
                }
            },
            (_, None) => true,
        };
        if let Some(cow_file) = cow_file {
            if cow_detached {
                if let Err(cleanup) = remove_file_durable(cow_file) {
                    failures.push(format!("remove {}: {cleanup}", cow_file.display()));
                    orphan.cow_file = Some(cow_file.to_path_buf());
                }
            } else if !cow_detached {
                orphan.cow_file = Some(cow_file.to_path_buf());
            }
        }
        if let Err(cleanup) = self.release_template_ref(template_path, false).await {
            failures.push(cleanup.to_string());
            orphan.template_path = Some(template_path.to_path_buf());
        }
        if !orphan.is_empty() {
            self.setup_orphans
                .lock()
                .unwrap()
                .insert(sandbox_id.to_owned(), orphan);
        }
        incomplete_cleanup(error, failures)
    }

    pub(crate) async fn cleanup_setup_orphan(&self, sandbox_id: &str) -> Result<()> {
        let Some(orphan) = self.setup_orphans.lock().unwrap().get(sandbox_id).cloned() else {
            return Ok(());
        };

        if let Some(dm_name) = &orphan.dm_name
            && Path::new(&format!("/dev/mapper/{dm_name}")).exists()
        {
            let dmsetup = self
                .dmsetup_bin
                .as_deref()
                .ok_or_else(|| VmmError::DeviceMapper("dmsetup binary not found".into()))?;
            dmsetup_remove(dmsetup, dm_name).await?;
        }
        if let (Some(cow_loop), Some(cow_file)) = (&orphan.cow_loop, &orphan.cow_file)
            && loop_backs_path(cow_loop, cow_file)?
        {
            losetup_detach(BUSYBOX, cow_loop).await?;
        }
        if let Some(cow_file) = &orphan.cow_file {
            remove_file_durable(cow_file)?;
        }
        if let Some(template_path) = &orphan.template_path {
            self.release_template_ref(template_path, false).await?;
        }
        if let Some((template_loop, template_path)) = &orphan.template_loop
            && loop_backs_path(template_loop, template_path)?
        {
            self.detach_template_loop(template_loop).await?;
        }
        if let Some(pending) = &orphan.pending_template_marker {
            clear_owner_marker(pending)?;
        }
        self.setup_orphans.lock().unwrap().remove(sandbox_id);
        Ok(())
    }

    /// Decrement the refcount for a template; detach its loop device when
    /// the count reaches zero.
    ///
    /// `restore_ref_on_failure` is true only for an already-delivered
    /// `CowHandle`. Setup rollback has no owner to restore, so a failed detach
    /// stays cached with refcount zero for a future setup or restart sweep.
    async fn release_template_ref(
        &self,
        template_path: &Path,
        restore_ref_on_failure: bool,
    ) -> Result<()> {
        let _losetup_guard = self.losetup_lock.lock().await;
        let Some(entry) = ({
            let mut templates = self.templates.lock().unwrap();
            let Some(entry) = templates.get_mut(template_path) else {
                return Ok(());
            };
            if entry.refcount > 1 {
                entry.refcount -= 1;
                return Ok(());
            }
            templates.remove(template_path)
        }) else {
            return Ok(());
        };

        if let Err(error) = self.detach_template_loop(&entry.loop_device).await {
            let mut entry = entry;
            entry.refcount = usize::from(restore_ref_on_failure);
            self.templates
                .lock()
                .unwrap()
                .insert(template_path.to_path_buf(), entry);
            return Err(error);
        }
        Ok(())
    }

    async fn detach_template_loop(&self, loop_device: &str) -> Result<()> {
        losetup_detach(BUSYBOX, loop_device).await?;
        if let Some(marker) = self.template_marker_path(loop_device)
            && let Err(error) = clear_owner_marker(&marker)
        {
            warn!(
                marker = %marker.display(),
                error = %error,
                "detached template loop but failed to remove recovery marker"
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

fn write_owner_marker(marker: &Path, backing: &Path) -> Result<()> {
    let parent = marker
        .parent()
        .ok_or_else(|| VmmError::DeviceMapper("resource marker has no parent".into()))?;
    let name = marker
        .file_name()
        .ok_or_else(|| VmmError::DeviceMapper("resource marker has no file name".into()))?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(
        "{TEMPLATE_MARKER_TEMP_PREFIX}{}",
        name.to_string_lossy()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(backing.to_string_lossy().as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&temporary, marker)?;
    std::fs::File::open(parent)?.sync_all()?;
    if let Some(grandparent) = parent.parent() {
        std::fs::File::open(grandparent)?.sync_all()?;
    }
    Ok(())
}

fn clear_owner_marker(marker: &Path) -> Result<()> {
    match std::fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = marker
        .parent()
        .ok_or_else(|| VmmError::DeviceMapper("resource marker has no parent".into()))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn remove_file_durable(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .ok_or_else(|| VmmError::DeviceMapper("owned file has no parent".into()))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn loop_backs_path(loop_device: &str, backing: &Path) -> Result<bool> {
    let Some(loop_name) = Path::new(loop_device)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return Ok(false);
    };
    Ok(loop_backing_path(loop_name)?.is_some_and(|actual| actual == backing.to_string_lossy()))
}

fn loop_devices_for_backing_sync(backing: &Path) -> Result<Vec<String>> {
    let expected = backing.to_string_lossy();
    let mut devices = Vec::new();
    for entry in std::fs::read_dir("/sys/block")? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(index) = name.strip_prefix("loop") else {
            continue;
        };
        if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        if loop_backing_path(&name)?.as_deref() == Some(expected.as_ref()) {
            devices.push(format!("/dev/{name}"));
        }
    }
    devices.sort();
    Ok(devices)
}

fn loop_backing_path(loop_name: &str) -> Result<Option<String>> {
    match std::fs::read_to_string(format!("/sys/block/{loop_name}/loop/backing_file")) {
        Ok(path) => Ok(Some(path.trim().to_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn incomplete_cleanup(error: VmmError, failures: impl IntoIterator<Item = String>) -> VmmError {
    let failures: Vec<_> = failures.into_iter().collect();
    if failures.is_empty() {
        error
    } else {
        VmmError::Unavailable(format!(
            "{error}; resource rollback is incomplete: {}",
            failures.join("; ")
        ))
    }
}

fn run_sync_checked(command: &mut Command) -> Result<std::process::Output> {
    let output = command
        .output()
        .map_err(|error| VmmError::DeviceMapper(format!("command spawn: {error}")))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(VmmError::DeviceMapper(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}

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
/// Uses the atomic `losetup -f --show` form so the kernel allocates and
/// attaches in a single `LOOP_CTL_GET_FREE`+`LOOP_SET_FD` call, avoiding
/// the TOCTOU window of separate `-f` then `attach` invocations against
/// other processes that might claim the same slot.  Supported by busybox
/// >= 1.21 and util-linux >= 2.20.
async fn losetup_attach(bin: &str, path: &Path, read_only: bool) -> Result<String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| VmmError::DeviceMapper("non-UTF-8 path".into()))?;

    let mut cmd = Command::new(bin);
    if read_only {
        cmd.args(["losetup", "-r", "-f", "--show", path_str]);
    } else {
        cmd.args(["losetup", "-f", "--show", path_str]);
    }
    let output = run_cmd(cmd).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VmmError::DeviceMapper(format!(
            "losetup attach {}: {stderr}",
            path.display()
        )));
    }
    let dev = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if dev.is_empty() {
        return Err(VmmError::DeviceMapper(
            "losetup --show returned empty device path".into(),
        ));
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
async fn create_sparse_file(path: &Path, size: u64) -> std::result::Result<(), (VmmError, bool)> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::result::Result<(), (VmmError, bool)> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                (
                    VmmError::DeviceMapper(format!("create cow file: {e}")),
                    false,
                )
            })?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                (
                    VmmError::DeviceMapper(format!("secure cow file: {e}")),
                    true,
                )
            })?;
        file.set_len(size).map_err(|e| {
            (
                VmmError::DeviceMapper(format!("truncate cow file: {e}")),
                true,
            )
        })?;
        file.sync_all()
            .map_err(|e| (VmmError::DeviceMapper(format!("sync cow file: {e}")), true))?;
        let parent = path.parent().ok_or_else(|| {
            (
                VmmError::DeviceMapper("cow file has no parent".into()),
                true,
            )
        })?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| {
                (
                    VmmError::DeviceMapper(format!("sync cow directory: {e}")),
                    true,
                )
            })?;
        Ok(())
    })
    .await
    .map_err(|e| {
        (
            VmmError::DeviceMapper(format!("spawn_blocking join: {e}")),
            false,
        )
    })?
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

    #[test]
    fn template_marker_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = CowManager {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir: tmp.path().to_path_buf(),
            dmsetup_bin: None,
        };

        let template = PathBuf::from("/var/lib/arcbox/rootfs.ext4");
        mgr.write_template_marker("/dev/loop7", &template).unwrap();
        let marker = mgr.template_marker_path("/dev/loop7").unwrap();
        assert_eq!(marker.file_name().unwrap(), "loop7");
        assert!(marker.exists());
        let content = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(content, template.to_string_lossy());

        let pending = mgr.write_template_pending("box", &template).unwrap();
        assert!(pending.exists());
        clear_owner_marker(&pending).unwrap();
        assert!(!pending.exists());
    }

    #[test]
    fn stale_marker_temp_is_discarded() {
        let tmp = tempfile::tempdir().unwrap();
        let marker_dir = tmp.path().join(TEMPLATE_LOOP_DIR);
        std::fs::create_dir_all(&marker_dir).unwrap();
        let temporary = marker_dir.join(format!("{TEMPLATE_MARKER_TEMP_PREFIX}loop7"));
        std::fs::write(&temporary, b"/partial").unwrap();
        let mgr = CowManager {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir: tmp.path().to_path_buf(),
            dmsetup_bin: None,
        };

        mgr.cleanup_stale_template_markers().unwrap();

        assert!(!temporary.exists());
    }

    #[tokio::test]
    async fn sparse_cow_creation_never_overwrites_an_owned_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cow.img");
        create_sparse_file(&path, 4096).await.unwrap();

        let (_, owns_file) = create_sparse_file(&path, 8192).await.unwrap_err();
        assert!(!owns_file);
        assert_eq!(std::fs::metadata(path).unwrap().len(), 4096);
    }

    #[tokio::test]
    async fn rollback_never_removes_an_unowned_cow_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cow_file = tmp.path().join("existing.img");
        std::fs::write(&cow_file, b"owned by another setup").unwrap();
        let mgr = CowManager {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir: tmp.path().to_path_buf(),
            dmsetup_bin: None,
        };

        let _ = mgr
            .rollback_setup(
                "box",
                Path::new("/template"),
                None,
                None,
                None,
                VmmError::DeviceMapper("create failed".into()),
            )
            .await;

        assert_eq!(std::fs::read(&cow_file).unwrap(), b"owned by another setup");
    }

    #[tokio::test]
    async fn zero_ref_template_is_not_reused() {
        let tmp = tempfile::tempdir().unwrap();
        let template = PathBuf::from("/template");
        let mgr = CowManager {
            templates: Mutex::new(HashMap::from([(
                template.clone(),
                TemplateEntry {
                    loop_device: "/dev/loop7".into(),
                    sectors: 1024,
                    refcount: 0,
                },
            )])),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir: tmp.path().to_path_buf(),
            dmsetup_bin: Some("/not-used".into()),
        };

        assert!(matches!(
            mgr.setup("box", template.to_str().unwrap()).await,
            Err(VmmError::Unavailable(_))
        ));
        assert_eq!(
            mgr.templates
                .lock()
                .unwrap()
                .get(&template)
                .unwrap()
                .refcount,
            0
        );
    }

    #[tokio::test]
    async fn test_release_template_refcount() {
        let mgr = CowManager {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
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
        mgr.release_template_ref(&path, true).await.unwrap();
        {
            let t = mgr.templates.lock().unwrap();
            assert_eq!(t.get(&path).unwrap().refcount, 1);
        }
    }
}
