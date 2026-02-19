//! Test fixtures for E2E tests.
//!
//! Provides common test data and setup utilities.

use std::path::{Path, PathBuf};

/// Test fixtures.
pub struct TestFixtures {
    /// Project root directory.
    project_root: PathBuf,
}

impl TestFixtures {
    /// Creates a new fixtures instance.
    pub fn new() -> Self {
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

        Self { project_root }
    }

    /// Returns the project root path.
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }

    /// Returns path to the test resources directory.
    pub fn resources_dir(&self) -> PathBuf {
        self.project_root.join("tests/resources")
    }

    /// Returns path to the kernel image.
    pub fn kernel_path(&self) -> PathBuf {
        self.resources_dir().join("Image-arm64")
    }

    /// Returns path to the initramfs.
    pub fn initramfs_path(&self) -> PathBuf {
        self.resources_dir().join("initramfs-arcbox")
    }

    /// Returns path to the arcbox binary (debug).
    pub fn arcbox_binary(&self) -> PathBuf {
        self.project_root.join("target/debug/arcbox")
    }

    /// Returns path to the arcbox binary (release).
    pub fn arcbox_binary_release(&self) -> PathBuf {
        self.project_root.join("target/release/arcbox")
    }

    /// Checks if all required test resources are available.
    pub fn check_resources(&self) -> ResourceCheck {
        ResourceCheck {
            kernel_exists: self.kernel_path().exists(),
            initramfs_exists: self.initramfs_path().exists(),
            binary_exists: self.arcbox_binary().exists(),
            binary_release_exists: self.arcbox_binary_release().exists(),
        }
    }
}

impl Default for TestFixtures {
    fn default() -> Self {
        Self::new()
    }
}

/// Resource check result.
#[derive(Debug, Clone)]
pub struct ResourceCheck {
    /// Kernel image exists.
    pub kernel_exists: bool,
    /// Initramfs exists.
    pub initramfs_exists: bool,
    /// Debug binary exists.
    pub binary_exists: bool,
    /// Release binary exists.
    pub binary_release_exists: bool,
}

impl ResourceCheck {
    /// Returns true if all required resources are available.
    pub fn all_ready(&self) -> bool {
        self.kernel_exists && self.initramfs_exists && self.binary_exists
    }

    /// Returns a list of missing resources.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.kernel_exists {
            missing.push("kernel (run tests/resources/download-kernel.sh)");
        }
        if !self.initramfs_exists {
            missing.push("initramfs (run tests/resources/build-initramfs.sh)");
        }
        if !self.binary_exists {
            missing.push("arcbox binary (run cargo build)");
        }
        missing
    }
}

/// Common test images.
pub mod images {
    /// Alpine Linux (minimal).
    pub const ALPINE: &str = "quay.io/libpod/alpine:latest";
    /// Alternate Alpine reference for tag-specific test paths.
    pub const ALPINE_3_19: &str = "quay.io/libpod/alpine:latest";
    /// BusyBox (ultra minimal).
    pub const BUSYBOX: &str = "quay.io/prometheus/busybox:latest";
    /// Debian slim.
    pub const DEBIAN_SLIM: &str = "debian:bookworm-slim";
}

/// Common test commands.
pub mod commands {
    /// Simple echo command.
    pub const ECHO_HELLO: &[&str] = &["echo", "hello"];
    /// Exit with code 0.
    pub const EXIT_SUCCESS: &[&str] = &["sh", "-c", "exit 0"];
    /// Exit with code 1.
    pub const EXIT_FAILURE: &[&str] = &["sh", "-c", "exit 1"];
    /// Sleep for 1 second.
    pub const SLEEP_1: &[&str] = &["sleep", "1"];
    /// Sleep for 10 seconds.
    pub const SLEEP_10: &[&str] = &["sleep", "10"];
    /// Print environment.
    pub const PRINT_ENV: &[&str] = &["env"];
    /// Print working directory.
    pub const PRINT_PWD: &[&str] = &["pwd"];
    /// List root directory.
    pub const LIST_ROOT: &[&str] = &["ls", "-la", "/"];
    /// Check if /proc is mounted.
    pub const CHECK_PROC: &[&str] = &["cat", "/proc/version"];
}
