use std::{fs, path::Path};

use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};
use tar::Builder;
use xtask_kit::{fs as xtask_fs, hash::sha256_file};

use crate::PackageTarballArgs;

pub fn run(args: PackageTarballArgs) -> Result<()> {
    xtask_fs::create_dir_all(&args.output_dir)?;

    let staging_name = format!("arcbox-darwin-arm64-{}", args.version);
    let staging = args.output_dir.join(&staging_name);
    xtask_fs::remove_path(&staging)?;

    super::stage_executable(
        args.host_artifacts.join("target/release/abctl"),
        staging.join("abctl"),
    )?;
    super::stage_executable(
        args.host_artifacts.join("target/release/arcbox-daemon"),
        staging.join("arcbox-daemon"),
    )?;
    super::stage_executable(
        args.host_artifacts.join("target/release/arcbox-helper"),
        staging.join("arcbox-helper"),
    )?;
    super::stage_executable(
        args.agent_artifacts.join("arcbox-agent"),
        staging.join("arcbox-agent"),
    )?;
    super::stage_executable(
        args.agent_artifacts.join("vm-agent"),
        staging.join("vm-agent"),
    )?;
    xtask_fs::copy_file(
        args.host_artifacts.join("bundle/arcbox.entitlements"),
        staging.join("bundle/arcbox.entitlements"),
    )?;
    xtask_fs::copy_file(
        args.host_artifacts
            .join("bundle/com.arcboxlabs.desktop.helper.plist"),
        staging.join("bundle/com.arcboxlabs.desktop.helper.plist"),
    )?;

    let tarball_name = format!("{staging_name}.tar.gz");
    let tarball = args.output_dir.join(&tarball_name);
    let archive =
        fs::File::create(&tarball).with_context(|| format!("creating {}", tarball.display()))?;
    let encoder = GzEncoder::new(archive, Compression::default());
    let mut builder = Builder::new(encoder);
    builder
        .append_dir_all(&staging_name, &staging)
        .with_context(|| format!("archiving {}", staging.display()))?;
    builder.into_inner()?.finish()?;

    let digest = sha256_file(&tarball)?;
    let checksum = args.output_dir.join(format!("{tarball_name}.sha256"));
    xtask_fs::write_string(&checksum, format!("{digest}  {tarball_name}\n"))?;

    println!("=== Tarball contents ===");
    print_tree(&staging, &staging_name)?;
    println!("{}", tarball.display());
    println!("{}", checksum.display());

    Ok(())
}

fn print_tree(dir: &Path, prefix: &str) -> Result<()> {
    println!("{prefix}/");
    let mut entries = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            print_tree(&path, &format!("{prefix}/{name}"))?;
        } else {
            println!("{prefix}/{name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use flate2::read::GzDecoder;
    use tar::Archive;

    use super::*;

    fn write_mode_644(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, bytes).expect("write file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).expect("chmod 644");
    }

    /// CI artifact downloads deliver every file as `0644`; the tarball must
    /// still ship binaries executable (regression: v0.4.x tarballs shipped
    /// `rw-r--r--` binaries) while bundle files stay non-executable.
    #[test]
    fn packaged_binaries_are_executable_and_bundle_files_are_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = dir.path().join("host");
        let agent = dir.path().join("agent");
        for bin in ["abctl", "arcbox-daemon", "arcbox-helper"] {
            write_mode_644(&host.join("target/release").join(bin), b"bin");
        }
        write_mode_644(&host.join("bundle/arcbox.entitlements"), b"plist");
        write_mode_644(
            &host.join("bundle/com.arcboxlabs.desktop.helper.plist"),
            b"plist",
        );
        write_mode_644(&agent.join("arcbox-agent"), b"bin");
        write_mode_644(&agent.join("vm-agent"), b"bin");

        let output_dir = dir.path().join("out");
        run(PackageTarballArgs {
            version: "v0.0.1".to_owned(),
            host_artifacts: host,
            agent_artifacts: agent,
            output_dir: output_dir.clone(),
        })
        .expect("packaging succeeds");

        let tarball = output_dir.join("arcbox-darwin-arm64-v0.0.1.tar.gz");
        let archive = fs::File::open(&tarball).expect("tarball exists");
        let mut entries = Archive::new(GzDecoder::new(archive));
        for entry in entries.entries().expect("read entries") {
            let entry = entry.expect("entry readable");
            if entry.header().entry_type().is_dir() {
                continue;
            }
            let path = PathBuf::from(&*entry.path().expect("entry path"));
            let mode = entry.header().mode().expect("mode set") & 0o777;
            let in_bundle = path.parent().is_some_and(|p| p.ends_with("bundle"));
            let expected = if in_bundle { 0o644 } else { 0o755 };
            assert_eq!(mode, expected, "unexpected mode for {}", path.display());
        }
    }
}
