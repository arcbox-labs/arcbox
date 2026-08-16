use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use tracing::{debug, warn};

use super::{
    CowManager, DM_NAME_PREFIX, TEMPLATE_LOOP_DIR, TEMPLATE_MARKER_TEMP_PREFIX,
    TEMPLATE_PENDING_PREFIX, dmsetup_remove,
};
use crate::error::{Result, SnapshotError};

#[derive(Clone, Default)]
pub(super) struct SetupOrphan {
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

impl CowManager {
    /// Remove orphaned dm-snapshot devices, COW files, and template loop
    /// devices left over from a previous crash. Called after orphaned
    /// Firecracker processes are dead; it is synchronous because every
    /// command is short and startup is already gated on reconciliation.
    ///
    /// `keep_cow_ids` names sandboxes whose COW file is *retained state*,
    /// not an orphan: a paused sandbox keeps its (detached) overlay on disk
    /// so Resume can re-assemble the dm-snapshot with every written block
    /// intact (CORE-21). Deleting those files here would silently destroy a
    /// paused sandbox's disk across an agent restart.
    pub fn reconcile_stale(&self, keep_cow_ids: &std::collections::HashSet<String>) -> Result<()> {
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
        //    Overlays retained by a paused sandbox are skipped wholesale.
        for entry in std::fs::read_dir(&self.cow_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(rest) = name.strip_prefix("arcbox-cow-") {
                let id = rest.strip_suffix(".img").unwrap_or(rest);
                if keep_cow_ids.contains(id) {
                    debug!(file = %path.display(), "keeping paused sandbox cow file");
                    continue;
                }
                for loop_device in loop_devices_for_backing_sync(&path)? {
                    self.tools.detach_loop(&loop_device)?;
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
    pub(super) fn template_marker_path(&self, loop_dev: &str) -> Option<PathBuf> {
        let basename = Path::new(loop_dev).file_name()?;
        Some(self.cow_dir.join(TEMPLATE_LOOP_DIR).join(basename))
    }

    pub(super) fn write_template_marker(&self, loop_dev: &str, template_path: &Path) -> Result<()> {
        let Some(marker) = self.template_marker_path(loop_dev) else {
            return Err(SnapshotError::DeviceMapper(format!(
                "unparseable template loop device: {loop_dev}"
            )));
        };
        write_owner_marker(&marker, template_path)?;
        Ok(())
    }

    pub(super) fn write_template_pending(
        &self,
        sandbox_id: &str,
        template_path: &Path,
    ) -> Result<PathBuf> {
        let marker = self
            .cow_dir
            .join(TEMPLATE_LOOP_DIR)
            .join(format!("{TEMPLATE_PENDING_PREFIX}{sandbox_id}"));
        write_owner_marker(&marker, template_path)?;
        Ok(marker)
    }

    pub(super) async fn abort_template_acquisition(
        &self,
        sandbox_id: &str,
        pending: &Path,
        loop_device: Option<&str>,
        template_path: &Path,
        error: SnapshotError,
    ) -> SnapshotError {
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

    pub(super) fn cleanup_stale_template_markers(&self) -> Result<()> {
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
                return Err(SnapshotError::DeviceMapper(format!(
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
                return Err(SnapshotError::DeviceMapper(format!(
                    "empty template marker: {}",
                    marker_path.display()
                )));
            }
            if loop_basename.starts_with(TEMPLATE_PENDING_PREFIX) {
                for loop_device in loop_devices_for_backing_sync(Path::new(&expected_backing))? {
                    self.tools.detach_loop(&loop_device)?;
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
                self.tools.detach_loop(&dev)?;
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

    pub(super) async fn rollback_setup(
        &self,
        sandbox_id: &str,
        template_path: &Path,
        dm_name: Option<&str>,
        cow_loop: Option<&str>,
        cow_file: Option<&Path>,
        error: SnapshotError,
    ) -> SnapshotError {
        let mut failures = Vec::new();
        let mut orphan = SetupOrphan::default();
        let dm_removed = match dm_name {
            Some(dm_name) if Path::new(&format!("/dev/mapper/{dm_name}")).exists() => {
                let cleanup = match self.dmsetup_bin.as_deref() {
                    Some(dmsetup) => dmsetup_remove(dmsetup, dm_name).await,
                    None => Err(SnapshotError::DeviceMapper(
                        "dmsetup binary not found".into(),
                    )),
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
            (true, Some(loop_device)) => match self.detach_loop(loop_device).await {
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

    pub async fn cleanup_setup_orphan(&self, sandbox_id: &str) -> Result<()> {
        let Some(orphan) = self.setup_orphans.lock().unwrap().get(sandbox_id).cloned() else {
            return Ok(());
        };

        if let Some(dm_name) = &orphan.dm_name
            && Path::new(&format!("/dev/mapper/{dm_name}")).exists()
        {
            let dmsetup = self
                .dmsetup_bin
                .as_deref()
                .ok_or_else(|| SnapshotError::DeviceMapper("dmsetup binary not found".into()))?;
            dmsetup_remove(dmsetup, dm_name).await?;
        }
        if let (Some(cow_loop), Some(cow_file)) = (&orphan.cow_loop, &orphan.cow_file)
            && loop_backs_path(cow_loop, cow_file)?
        {
            self.detach_loop(cow_loop).await?;
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
    pub(super) async fn release_template_ref(
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
        self.detach_loop(loop_device).await?;
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

fn write_owner_marker(marker: &Path, backing: &Path) -> Result<()> {
    let parent = marker
        .parent()
        .ok_or_else(|| SnapshotError::DeviceMapper("resource marker has no parent".into()))?;
    let name = marker
        .file_name()
        .ok_or_else(|| SnapshotError::DeviceMapper("resource marker has no file name".into()))?;
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

pub(super) fn clear_owner_marker(marker: &Path) -> Result<()> {
    match std::fs::remove_file(marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = marker
        .parent()
        .ok_or_else(|| SnapshotError::DeviceMapper("resource marker has no parent".into()))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn remove_file_durable(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let parent = path
        .parent()
        .ok_or_else(|| SnapshotError::DeviceMapper("owned file has no parent".into()))?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn loop_backs_path(loop_device: &str, backing: &Path) -> Result<bool> {
    let Some(loop_name) = Path::new(loop_device)
        .file_name()
        .and_then(|name| name.to_str())
    else {
        return Ok(false);
    };
    Ok(loop_backing_path(loop_name)?.is_some_and(|actual| actual == backing.to_string_lossy()))
}

pub(super) fn loop_devices_for_backing_sync(backing: &Path) -> Result<Vec<String>> {
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

fn incomplete_cleanup(
    error: SnapshotError,
    failures: impl IntoIterator<Item = String>,
) -> SnapshotError {
    let failures: Vec<_> = failures.into_iter().collect();
    if failures.is_empty() {
        error
    } else {
        SnapshotError::Unavailable(format!(
            "{error}; resource rollback is incomplete: {}",
            failures.join("; ")
        ))
    }
}

fn run_sync_checked(command: &mut Command) -> Result<std::process::Output> {
    let output = command
        .output()
        .map_err(|error| SnapshotError::DeviceMapper(format!("command spawn: {error}")))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(SnapshotError::DeviceMapper(
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ))
    }
}
