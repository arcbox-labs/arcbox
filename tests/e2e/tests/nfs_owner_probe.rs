//! ABX-427 ownership display — NOT part of the suite. Run manually:
//!   cargo test -p arcbox-e2e --test nfs_owner_probe -- --ignored --nocapture
//!
//! The guest's uids mean nothing on the host, so `~/ArcBox` used to list as
//! `root` and bare numbers. The mount now carries `noowners`
//! (`MNT_IGNORE_OWNERSHIP`), under which every object reports uid 99 and the
//! VFS renders that as the current user.
//!
//! Asserting "uid 99" would test the constant, not the behaviour, so the
//! comparison is against a file this process created in the same run: the
//! export must report the same owner as something we own. That is exactly the
//! property a user checks in Finder, and it holds whoever runs the test.
//!
//! Access was never the problem — the export is `all_squash,anonuid=0`, so the
//! server evaluates ACCESS as root and root-0600 files already read fine
//! (probed 2026-07-16). This probe therefore also reads a file through the
//! mount, to catch a regression where the display fix broke reads.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

use arcbox_e2e::boot_assets::{
    read_file_with_retry, resolve_boot_version, stage_dev_boot_assets, wait_for_nfs_mount,
};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use arcbox_e2e::repo_root;

const READY_TIMEOUT: Duration = Duration::from_secs(180);

#[test]
#[ignore = "ABX-427 ownership probe: boots a VM"]
fn nfs_owner_probe() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();

    let root = repo_root();
    let version = resolve_boot_version(&root)?;

    let temp = tempfile::Builder::new()
        .prefix("arcbox-nfs-owner-")
        .tempdir()?;
    let test_dir = temp.path().to_owned();

    let result = run_probe(&root, &test_dir, &version);
    if result.is_err() {
        let kept = temp.keep();
        eprintln!("preserving test directory path={}", kept.display());
    }
    result
}

fn run_probe(root: &Path, test_dir: &Path, version: &str) -> Result<()> {
    stage_dev_boot_assets(root, test_dir, version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: test_dir.to_owned(),
        args: vec!["--guest-docker-vsock-port".into(), "2375".into()],
        env: vec![("ARCBOX_BOOT_ASSET_VERSION".into(), version.to_owned())],
    })?;
    daemon.wait_ready_blocking(READY_TIMEOUT)?;

    let mount_dir = test_dir.join("ArcBox");
    wait_for_nfs_mount(&mount_dir)?;

    // The reference: a directory this process created, on local disk.
    let expected_uid = fs::metadata(test_dir)
        .context("stat of the test dir")?
        .uid();
    println!("browsing user uid={expected_uid}");

    let mut checked = Vec::new();
    let mut wrong = Vec::new();

    let mut record = |label: String, path: &Path| -> Result<()> {
        let meta = fs::symlink_metadata(path).with_context(|| format!("stat of {label}"))?;
        let (uid, gid) = (meta.uid(), meta.gid());
        println!("{label}: uid={uid} gid={gid}");
        if uid == expected_uid {
            checked.push(label);
        } else {
            wrong.push(format!("{label} reports uid {uid}"));
        }
        Ok(())
    };

    record("mount root".to_string(), &mount_dir)?;

    // Guest-owned entries: dockerd writes these as root, which is precisely
    // what used to surface. Cover a few rather than trusting one.
    let entries: Vec<_> = fs::read_dir(&mount_dir)
        .with_context(|| format!("reading {}", mount_dir.display()))?
        .filter_map(Result::ok)
        .take(5)
        .collect();
    if entries.is_empty() {
        bail!("export listed no entries; the probe has nothing to check");
    }
    for entry in &entries {
        record(
            format!("entry {}", entry.file_name().to_string_lossy()),
            &entry.path(),
        )?;
    }

    if !wrong.is_empty() {
        bail!(
            "~/ArcBox still reports guest ownership ({}); expected uid {expected_uid} everywhere",
            wrong.join("; ")
        );
    }
    println!(
        "OK: all {} checked paths report the browsing user (uid {expected_uid})",
        checked.len()
    );

    // The display fix must not have cost us read access. This is the only
    // check here that reads *content* — the loop above exercises getattr and
    // readdir only — so it must never degrade into a skip: the daemon is
    // ready and the export is populated, so a file that will not read is a
    // failure, not an absence. The retry covers the `actimeo=10` attribute
    // cache a freshly mounted export sits behind.
    read_through_check(&mount_dir)?;

    daemon.shutdown()?;
    Ok(())
}

/// Reads a real guest file through the mount, preferring dockerd's `engine-id`
/// and otherwise scanning the export root for the first regular file.
///
/// The scan is this function's own `read_dir`, not the uid loop's sample: that
/// one is an arbitrary five entries, and dockerd's data root is nearly all
/// directories at the top level, so a sample can legitimately contain no
/// regular file at all. Absence of a candidate and failure to read one are
/// reported as the different things they are.
fn read_through_check(mount_dir: &Path) -> Result<()> {
    const READ_RETRY: Duration = Duration::from_secs(20);

    // `symlink_metadata`, so a symlink is not mistaken for its target.
    let is_regular_file = |path: &Path| fs::symlink_metadata(path).is_ok_and(|meta| meta.is_file());

    let engine_id = mount_dir.join("engine-id");
    let candidates = std::iter::once(engine_id)
        .filter(|path| is_regular_file(path))
        .chain(
            fs::read_dir(mount_dir)
                .with_context(|| format!("scanning {} for a file", mount_dir.display()))?
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| is_regular_file(path)),
        );

    let mut attempts = Vec::new();
    for path in candidates {
        match read_file_with_retry(&path, READ_RETRY) {
            Ok(content) if !content.trim().is_empty() => {
                println!("OK: {} still readable through the mount", path.display());
                return Ok(());
            }
            Ok(_) => attempts.push(format!("{} read empty", path.display())),
            Err(e) => attempts.push(format!("{} failed: {e:#}", path.display())),
        }
    }

    if attempts.is_empty() {
        bail!(
            "the export root {} holds no regular file, so the read-through check had no candidate",
            mount_dir.display()
        );
    }
    bail!(
        "no file could be read through the mount: {}",
        attempts.join("; ")
    )
}
