//! macOS guest support: base images, copy-on-write clones, and the macOS machine
//! lifecycle. Apple Silicon only.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use crate::error::{CoreError, Result};

#[cfg(feature = "macos-ipsw-install")]
mod download;
mod image;
#[cfg(feature = "macos-ipsw-install")]
mod install;
mod lease;
mod machine;
mod pull;
mod remote;
mod vm;

pub use image::{MacImage, MacImageManager, MacImageMeta, MacInstanceDisks};
#[cfg(feature = "macos-ipsw-install")]
pub use install::{PullPhase, PullSource};
pub use machine::{MacMachineConfig, MacMachineInfo, MacMachineManager};
pub use pull::{PullStage, RemoteSource, ResolvedImage};
pub use remote::{ImageReference, RemoteLocation};
pub use vm::MacVm;

/// Validates that `name` is a single, safe path component.
///
/// Image and machine names are used verbatim as a directory under a managed
/// root (`macos/images/<name>`, `macos/machines/<name>`). A name must therefore
/// be exactly one normal path component: this rejects empty names, embedded NUL,
/// absolute paths, path separators, and `.`/`..`, so a caller- or manifest-
/// supplied name can never escape its root.
pub(super) fn validate_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(only)), None)
            if only == OsStr::new(name) && !name.contains('\0') =>
        {
            Ok(())
        }
        _ => Err(CoreError::macos(format!("invalid name '{name}'"))),
    }
}

/// Removes a staging directory on drop unless disarmed.
///
/// Both the image pull and machine create flows assemble their artifacts in a
/// staging directory and rename it into place only when complete. This guard is
/// what makes those flows safe against early return and cancellation: if it is
/// dropped before `disarm` (an error, or the future being dropped at an await
/// point), the partial directory is removed rather than leaked.
pub(super) struct StagingGuard {
    path: Option<PathBuf>,
}

impl StagingGuard {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Keeps the directory (it has been renamed into its final location).
    pub(super) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod name_tests {
    use super::validate_name;

    #[test]
    fn accepts_plain_and_dotted_components() {
        for ok in [
            "tahoe-base",
            "tahoe-base@2026.07.02",
            ".pull-x",
            ".create-ci-1",
        ] {
            assert!(validate_name(ok).is_ok(), "should accept {ok:?}");
        }
    }

    #[test]
    fn rejects_traversal_and_separators() {
        for bad in ["", ".", "..", "a/b", "/abs", "a/../b", "a\0b", "sub/dir"] {
            assert!(validate_name(bad).is_err(), "should reject {bad:?}");
        }
    }
}
