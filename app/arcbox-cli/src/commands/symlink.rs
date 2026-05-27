//! App-bundle path detection for the bundled xbin directory.
//!
//! The privileged `/usr/local/bin/*` symlinks are managed by `arcbox-helper`
//! (`server::mutations::cli`); the user-space `~/.arcbox/bin/*` symlinks are
//! managed by `setup::link_docker_tools_to_user_bin`. This module exists only
//! to share the xbin-detection helper between those code paths.

use std::path::PathBuf;

/// Detects the `xbin/` directory inside the current app bundle.
///
/// When `abctl` runs from `Contents/MacOS/bin/abctl`, xbin is at
/// `Contents/MacOS/xbin/`. Returns `None` outside an app bundle.
pub fn detect_bundle_xbin() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let xbin = exe.parent()?.parent()?.join("xbin");
    xbin.is_dir().then_some(xbin)
}
