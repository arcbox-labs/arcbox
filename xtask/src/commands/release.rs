pub mod check_tool_updates;
pub mod package_tarball;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use xtask_kit::fs as xtask_fs;

use crate::{ReleaseArgs, ReleaseCommand};

/// Copy a binary into the staging tree and mark it `0o755`. CI artifact
/// round-trips strip permissions (upload/download-artifact v4 delivers every
/// file as `0644`), and the tar builder records on-disk modes — without the
/// explicit chmod the shipped binaries would not be executable after
/// extraction.
fn stage_executable(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let to = to.as_ref();
    xtask_fs::copy_file(from, to)?;
    fs::set_permissions(to, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("marking {} executable", to.display()))
}

pub fn run(args: ReleaseArgs) -> Result<()> {
    match args.command {
        ReleaseCommand::CheckToolUpdates(args) => check_tool_updates::run(args),
        ReleaseCommand::PackageTarball(args) => package_tarball::run(args),
    }
}
