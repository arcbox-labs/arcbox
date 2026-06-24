use std::{fs, path::PathBuf};

use anyhow::{Context, Result, bail};
use toml_edit::DocumentMut;

use crate::{BootAssetSource, DevArgs, DevCommand, support::fs::copy_file, support::repo_root};

pub fn run(args: DevArgs) -> Result<()> {
    match args.command {
        DevCommand::BootAssets(args) => prepare_boot_assets(args),
    }
}

pub fn prepare_boot_assets(args: crate::BootAssetsArgs) -> Result<()> {
    let root = repo_root();
    let version = match args.version {
        Some(version) => version,
        None => boot_version(&root.join("assets.lock"))?,
    };
    let source = args.source.unwrap_or(BootAssetSource::Release);
    let dev_boot_dir = root.join("boot-assets/dev");

    if dev_assets_match(&dev_boot_dir, &version)? {
        println!("[INFO] Development boot assets already exist");
        print_info(&dev_boot_dir, &version, source);
        return Ok(());
    }

    println!("[INFO] Setting up development boot assets...");
    match source {
        BootAssetSource::Release => {
            let user_boot_dir = args
                .data_dir
                .unwrap_or_else(default_data_dir)
                .join("boot")
                .join(&version);
            copy_boot_assets(&user_boot_dir, &dev_boot_dir).with_context(|| {
                format!(
                    "copying boot assets from user cache {}; run `abctl boot prefetch --force` first if missing",
                    user_boot_dir.display()
                )
            })?;
        }
        BootAssetSource::KernelOutput => {
            let kernel_dir = args
                .kernel_dir
                .unwrap_or_else(|| root.join("../arcbox-kernel"));
            let output_dir = kernel_dir.join("output");
            copy_kernel_output(&output_dir, &dev_boot_dir)?;
        }
    }

    println!("[INFO] Development boot assets ready");
    print_info(&dev_boot_dir, &version, source);
    Ok(())
}

fn boot_version(lockfile: &std::path::Path) -> Result<String> {
    let text = fs::read_to_string(lockfile)
        .with_context(|| format!("reading asset lockfile {}", lockfile.display()))?;
    let doc = text
        .parse::<DocumentMut>()
        .with_context(|| format!("parsing {}", lockfile.display()))?;
    doc["boot"]["version"]
        .as_str()
        .map(str::to_owned)
        .context("assets.lock is missing [boot].version")
}

fn default_data_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        dirs::home_dir()
            .expect("home directory is required for default macOS data dir")
            .join("Library/Application Support/arcbox")
    } else {
        dirs::data_dir()
            .expect("data directory is required for default Linux data dir")
            .join("arcbox")
    }
}

fn dev_assets_match(dev_boot_dir: &std::path::Path, version: &str) -> Result<bool> {
    let manifest = dev_boot_dir.join("manifest.json");
    if !dev_boot_dir.join("kernel").is_file()
        || !dev_boot_dir.join("rootfs.erofs").is_file()
        || !manifest.is_file()
    {
        return Ok(false);
    }

    let json: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest).with_context(|| format!("reading {}", manifest.display()))?,
    )
    .with_context(|| format!("parsing {}", manifest.display()))?;
    Ok(json
        .get("asset_version")
        .and_then(serde_json::Value::as_str)
        == Some(version))
}

fn copy_boot_assets(source: &std::path::Path, dev_boot_dir: &std::path::Path) -> Result<()> {
    if !source.is_dir() {
        bail!("boot asset source does not exist: {}", source.display());
    }
    copy_file(&source.join("kernel"), &dev_boot_dir.join("kernel"))?;
    copy_file(
        &source.join("rootfs.erofs"),
        &dev_boot_dir.join("rootfs.erofs"),
    )?;
    copy_file(
        &source.join("manifest.json"),
        &dev_boot_dir.join("manifest.json"),
    )?;
    Ok(())
}

fn copy_kernel_output(output_dir: &std::path::Path, dev_boot_dir: &std::path::Path) -> Result<()> {
    copy_file(
        &output_dir.join("kernel-arm64"),
        &dev_boot_dir.join("kernel"),
    )?;
    copy_file(
        &output_dir.join("rootfs.erofs"),
        &dev_boot_dir.join("rootfs.erofs"),
    )?;
    copy_file(
        &output_dir.join("manifest.json"),
        &dev_boot_dir.join("manifest.json"),
    )?;
    Ok(())
}

fn print_info(dev_boot_dir: &std::path::Path, version: &str, source: BootAssetSource) {
    println!();
    println!("Development Boot Assets");
    println!("=======================");
    println!("Location: {}", dev_boot_dir.display());
    println!("Version:  {version}");
    println!("Source:   {}", source.as_str());
    println!();
    for name in ["kernel", "rootfs.erofs", "manifest.json"] {
        let path = dev_boot_dir.join(name);
        if let Ok(metadata) = fs::metadata(&path) {
            println!("{name}: {} bytes", metadata.len());
        } else {
            println!("{name}: missing");
        }
    }
    println!();
}

impl BootAssetSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::KernelOutput => "kernel-output",
        }
    }
}
