use std::{fs, path::Path};

use anyhow::{Context, Result};
use flate2::{Compression, write::GzEncoder};
use tar::Builder;
use xtask_kit::{fs::copy_file, github_actions, hash::sha256_file};

use crate::PackageTarballArgs;

pub fn run(args: PackageTarballArgs) -> Result<()> {
    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating {}", args.output_dir.display()))?;

    let staging_name = format!("arcbox-darwin-arm64-{}", args.version);
    let staging = args.output_dir.join(&staging_name);
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .with_context(|| format!("removing old staging dir {}", staging.display()))?;
    }

    copy_file(
        args.host_artifacts.join("target/release/abctl"),
        staging.join("abctl"),
    )?;
    copy_file(
        args.host_artifacts.join("target/release/arcbox-daemon"),
        staging.join("arcbox-daemon"),
    )?;
    copy_file(
        args.host_artifacts.join("target/release/arcbox-helper"),
        staging.join("arcbox-helper"),
    )?;
    copy_file(
        args.agent_artifacts.join("arcbox-agent"),
        staging.join("arcbox-agent"),
    )?;
    copy_file(
        args.host_artifacts.join("bundle/arcbox.entitlements"),
        staging.join("bundle/arcbox.entitlements"),
    )?;
    copy_file(
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
    fs::write(&checksum, format!("{digest}  {tarball_name}\n"))
        .with_context(|| format!("writing {}", checksum.display()))?;

    println!("=== Tarball contents ===");
    print_tree(&staging, &staging_name)?;
    println!("{}", tarball.display());
    println!("{}", checksum.display());

    if let Some(github_output) = args.github_output {
        github_actions::append_output(&github_output, "tarball", &tarball_name)?;
    }

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
