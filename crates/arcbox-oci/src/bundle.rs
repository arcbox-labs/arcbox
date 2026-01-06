//! OCI bundle handling.
//!
//! An OCI bundle is a directory containing everything needed to run a container:
//! - `config.json`: The OCI runtime specification
//! - `rootfs/`: The root filesystem (optional if config.json specifies an external root)
//!
//! Reference: <https://github.com/opencontainers/runtime-spec/blob/main/bundle.md>

use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use crate::config::Spec;
use crate::error::{OciError, Result};

/// OCI bundle directory name constants.
pub mod paths {
    /// Standard config file name.
    pub const CONFIG_FILE: &str = "config.json";
    /// Default rootfs directory name.
    pub const ROOTFS_DIR: &str = "rootfs";
}

/// OCI bundle representation.
///
/// A bundle encapsulates an OCI runtime configuration and its associated
/// root filesystem.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Absolute path to the bundle directory.
    path: PathBuf,
    /// Parsed OCI specification.
    spec: Spec,
}

impl Bundle {
    /// Load an OCI bundle from a directory.
    ///
    /// This reads and validates the config.json file and checks that the
    /// bundle structure is valid.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();

        // Ensure bundle directory exists.
        if !path.exists() {
            return Err(OciError::BundleNotFound(path.to_path_buf()));
        }

        if !path.is_dir() {
            return Err(OciError::InvalidBundle(format!(
                "not a directory: {}",
                path.display()
            )));
        }

        // Convert to absolute path.
        let path = path
            .canonicalize()
            .map_err(|e| OciError::InvalidBundle(format!("failed to resolve path: {e}")))?;

        // Load config.json.
        let config_path = path.join(paths::CONFIG_FILE);
        if !config_path.exists() {
            return Err(OciError::ConfigNotFound(path));
        }

        let spec = Spec::load(&config_path)?;
        debug!("Loaded OCI spec from {}", config_path.display());

        let bundle = Self { path, spec };
        bundle.validate()?;

        Ok(bundle)
    }

    /// Create a new bundle from an existing spec.
    ///
    /// This creates the bundle directory structure and writes the config.json.
    pub fn create<P: AsRef<Path>>(path: P, spec: Spec) -> Result<Self> {
        let path = path.as_ref();

        // Create bundle directory.
        std::fs::create_dir_all(path)?;

        // Convert to absolute path.
        let path = path
            .canonicalize()
            .map_err(|e| OciError::InvalidBundle(format!("failed to resolve path: {e}")))?;

        // Write config.json.
        let config_path = path.join(paths::CONFIG_FILE);
        spec.save(&config_path)?;
        debug!("Wrote OCI spec to {}", config_path.display());

        // Create default rootfs directory if root path is relative.
        if let Some(ref root) = spec.root {
            let rootfs_path = path.join(&root.path);
            if !rootfs_path.exists() {
                std::fs::create_dir_all(&rootfs_path)?;
                debug!("Created rootfs at {}", rootfs_path.display());
            }
        }

        Ok(Self { path, spec })
    }

    /// Create a bundle with default Linux configuration.
    pub fn create_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::create(path, Spec::default_linux())
    }

    /// Get the bundle directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the OCI specification.
    #[must_use]
    pub const fn spec(&self) -> &Spec {
        &self.spec
    }

    /// Get mutable reference to the OCI specification.
    pub const fn spec_mut(&mut self) -> &mut Spec {
        &mut self.spec
    }

    /// Get the config.json path.
    #[must_use]
    pub fn config_path(&self) -> PathBuf {
        self.path.join(paths::CONFIG_FILE)
    }

    /// Get the root filesystem path.
    ///
    /// Returns the resolved absolute path to the rootfs.
    #[must_use]
    pub fn rootfs_path(&self) -> PathBuf {
        self.spec.root.as_ref().map_or_else(
            || self.path.join(paths::ROOTFS_DIR),
            |root| {
                let root_path = PathBuf::from(&root.path);
                if root_path.is_absolute() {
                    root_path
                } else {
                    self.path.join(&root.path)
                }
            },
        )
    }

    /// Check if the rootfs exists.
    #[must_use]
    pub fn rootfs_exists(&self) -> bool {
        self.rootfs_path().exists()
    }

    /// Check if the rootfs is configured as read-only.
    #[must_use]
    pub fn rootfs_readonly(&self) -> bool {
        self.spec.root.as_ref().is_some_and(|r| r.readonly)
    }

    /// Validate the bundle structure.
    pub fn validate(&self) -> Result<()> {
        // Validate the spec.
        self.spec.validate()?;

        // Check rootfs exists (warn if not, error if we need it).
        let rootfs = self.rootfs_path();
        if !rootfs.exists() {
            // Rootfs might be mounted later or provided externally.
            warn!("Rootfs does not exist: {}", rootfs.display());
        }

        // Validate hooks if present.
        if let Some(ref hooks) = self.spec.hooks {
            hooks.validate()?;
        }

        Ok(())
    }

    /// Save any modifications to the spec back to config.json.
    pub fn save(&self) -> Result<()> {
        self.spec.save(self.config_path())
    }

    /// Update the spec and save.
    pub fn update_spec(&mut self, spec: Spec) -> Result<()> {
        spec.validate()?;
        self.spec = spec;
        self.save()
    }
}

/// Bundle builder for creating new bundles.
#[derive(Debug)]
pub struct BundleBuilder {
    spec: Spec,
}

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleBuilder {
    /// Create a new bundle builder with default Linux spec.
    #[must_use]
    pub fn new() -> Self {
        Self {
            spec: Spec::default_linux(),
        }
    }

    /// Create a new bundle builder with a custom spec.
    #[must_use]
    pub const fn with_spec(spec: Spec) -> Self {
        Self { spec }
    }

    /// Set the hostname.
    #[must_use]
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.spec.hostname = Some(hostname.into());
        self
    }

    /// Set the process arguments.
    #[must_use]
    pub fn args(mut self, args: Vec<String>) -> Self {
        if let Some(ref mut process) = self.spec.process {
            process.args = args;
        }
        self
    }

    /// Set the process environment.
    #[must_use]
    pub fn env(mut self, env: Vec<String>) -> Self {
        if let Some(ref mut process) = self.spec.process {
            process.env = env;
        }
        self
    }

    /// Add an environment variable.
    #[must_use]
    pub fn add_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        if let Some(ref mut process) = self.spec.process {
            process.env.push(format!("{}={}", key.into(), value.into()));
        }
        self
    }

    /// Set the working directory.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        if let Some(ref mut process) = self.spec.process {
            process.cwd = cwd.into();
        }
        self
    }

    /// Set the user.
    #[must_use]
    pub const fn user(mut self, uid: u32, gid: u32) -> Self {
        if let Some(ref mut process) = self.spec.process {
            if let Some(ref mut user) = process.user {
                user.uid = uid;
                user.gid = gid;
            }
        }
        self
    }

    /// Set the rootfs path.
    #[must_use]
    pub fn rootfs(mut self, path: impl Into<String>) -> Self {
        if let Some(ref mut root) = self.spec.root {
            root.path = path.into();
        }
        self
    }

    /// Set rootfs as read-only.
    #[must_use]
    pub const fn readonly_rootfs(mut self, readonly: bool) -> Self {
        if let Some(ref mut root) = self.spec.root {
            root.readonly = readonly;
        }
        self
    }

    /// Enable terminal.
    #[must_use]
    pub const fn terminal(mut self, terminal: bool) -> Self {
        if let Some(ref mut process) = self.spec.process {
            process.terminal = terminal;
        }
        self
    }

    /// Add an annotation.
    #[must_use]
    pub fn annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.spec.annotations.insert(key.into(), value.into());
        self
    }

    /// Add a mount.
    #[must_use]
    pub fn mount(mut self, mount: crate::config::Mount) -> Self {
        self.spec.mounts.push(mount);
        self
    }

    /// Build the bundle at the specified path.
    pub fn build<P: AsRef<Path>>(self, path: P) -> Result<Bundle> {
        Bundle::create(path, self.spec)
    }

    /// Get the spec without building.
    #[must_use]
    pub fn into_spec(self) -> Spec {
        self.spec
    }
}

/// Utilities for working with bundles.
pub mod utils {
    use super::{paths, OciError, Result};
    use std::path::{Path, PathBuf};

    /// Check if a directory is a valid OCI bundle.
    #[must_use]
    pub fn is_bundle<P: AsRef<Path>>(path: P) -> bool {
        let path = path.as_ref();
        path.is_dir() && path.join(paths::CONFIG_FILE).is_file()
    }

    /// Find all bundles in a directory (non-recursive).
    pub fn find_bundles<P: AsRef<Path>>(dir: P) -> Result<Vec<PathBuf>> {
        let mut bundles = Vec::new();
        let dir = dir.as_ref();

        if !dir.is_dir() {
            return Ok(bundles);
        }

        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if is_bundle(&path) {
                bundles.push(path);
            }
        }

        Ok(bundles)
    }

    /// Copy rootfs from source to bundle.
    pub fn copy_rootfs<P: AsRef<Path>, Q: AsRef<Path>>(source: P, bundle: Q) -> Result<()> {
        let source = source.as_ref();
        let dest = bundle.as_ref().join(paths::ROOTFS_DIR);

        if !source.exists() {
            return Err(OciError::InvalidPath(format!(
                "source rootfs does not exist: {}",
                source.display()
            )));
        }

        // For now, just create the directory. Actual copy would be more complex.
        std::fs::create_dir_all(&dest)?;

        // Copy directory contents (basic implementation).
        copy_dir_recursive(source, &dest)?;

        Ok(())
    }

    /// Recursively copy a directory.
    fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
        std::fs::create_dir_all(dst)?;

        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                copy_dir_recursive(&src_path, &dst_path)?;
            } else {
                std::fs::copy(&src_path, &dst_path)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn create_temp_bundle() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let config = r#"{
            "ociVersion": "1.2.0",
            "root": {
                "path": "rootfs"
            },
            "process": {
                "cwd": "/",
                "args": ["sh"]
            }
        }"#;

        let config_path = dir.path().join("config.json");
        let mut file = fs::File::create(&config_path).unwrap();
        file.write_all(config.as_bytes()).unwrap();

        let rootfs = dir.path().join("rootfs");
        fs::create_dir(&rootfs).unwrap();

        dir
    }

    #[test]
    fn test_load_bundle() {
        let dir = create_temp_bundle();
        let bundle = Bundle::load(dir.path()).unwrap();

        assert_eq!(bundle.spec().oci_version, "1.2.0");
        assert!(bundle.rootfs_exists());
    }

    #[test]
    fn test_bundle_not_found() {
        let result = Bundle::load("/nonexistent/path");
        assert!(matches!(result, Err(OciError::BundleNotFound(_))));
    }

    #[test]
    fn test_config_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = Bundle::load(dir.path());
        assert!(matches!(result, Err(OciError::ConfigNotFound(_))));
    }

    #[test]
    fn test_create_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        let bundle = Bundle::create_default(&bundle_path).unwrap();

        assert!(bundle.config_path().exists());
        assert!(bundle.rootfs_path().exists());
    }

    #[test]
    fn test_bundle_builder() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("built-bundle");

        let bundle = BundleBuilder::new()
            .hostname("test-container")
            .args(vec!["echo".to_string(), "hello".to_string()])
            .add_env("MY_VAR", "my_value")
            .cwd("/app")
            .user(1000, 1000)
            .readonly_rootfs(true)
            .annotation("org.test.key", "value")
            .build(&bundle_path)
            .unwrap();

        assert_eq!(bundle.spec().hostname, Some("test-container".to_string()));
        assert!(bundle.rootfs_readonly());
        assert!(bundle.spec().annotations.contains_key("org.test.key"));
    }

    #[test]
    fn test_is_bundle() {
        let dir = create_temp_bundle();
        assert!(utils::is_bundle(dir.path()));

        let empty_dir = tempfile::tempdir().unwrap();
        assert!(!utils::is_bundle(empty_dir.path()));
    }

    #[test]
    fn test_find_bundles() {
        let root = tempfile::tempdir().unwrap();

        // Create two bundles.
        for name in ["bundle1", "bundle2"] {
            let path = root.path().join(name);
            fs::create_dir(&path).unwrap();
            let config = r#"{"ociVersion": "1.2.0"}"#;
            fs::write(path.join("config.json"), config).unwrap();
        }

        // Create a non-bundle directory.
        fs::create_dir(root.path().join("not-a-bundle")).unwrap();

        let bundles = utils::find_bundles(root.path()).unwrap();
        assert_eq!(bundles.len(), 2);
    }

    #[test]
    fn test_bundle_path_accessors() {
        let dir = create_temp_bundle();
        let bundle = Bundle::load(dir.path()).unwrap();

        // Bundle path should be absolute.
        assert!(bundle.path().is_absolute());

        // Config path should end with config.json.
        assert!(bundle.config_path().ends_with("config.json"));

        // Rootfs path should end with rootfs.
        assert!(bundle.rootfs_path().ends_with("rootfs"));
    }

    #[test]
    fn test_bundle_save() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("save-test");

        let mut bundle = Bundle::create_default(&bundle_path).unwrap();

        // Modify the spec.
        bundle.spec_mut().hostname = Some("modified-hostname".to_string());
        bundle.save().unwrap();

        // Reload and verify.
        let reloaded = Bundle::load(&bundle_path).unwrap();
        assert_eq!(
            reloaded.spec().hostname,
            Some("modified-hostname".to_string())
        );
    }

    #[test]
    fn test_bundle_update_spec() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("update-test");

        let mut bundle = Bundle::create_default(&bundle_path).unwrap();

        // Create a new spec.
        let mut new_spec = Spec::default_linux();
        new_spec.hostname = Some("new-hostname".to_string());

        bundle.update_spec(new_spec).unwrap();

        // Reload and verify.
        let reloaded = Bundle::load(&bundle_path).unwrap();
        assert_eq!(reloaded.spec().hostname, Some("new-hostname".to_string()));
    }

    #[test]
    fn test_bundle_rootfs_path_relative() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("relative-rootfs");

        // Create bundle with relative rootfs path.
        let bundle = BundleBuilder::new()
            .rootfs("custom-rootfs")
            .build(&bundle_path)
            .unwrap();

        // Rootfs path should be resolved to absolute.
        let rootfs = bundle.rootfs_path();
        assert!(rootfs.is_absolute());
        assert!(rootfs.ends_with("custom-rootfs"));
    }

    #[test]
    fn test_bundle_rootfs_path_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("absolute-rootfs");
        let external_rootfs = dir.path().join("external-rootfs");
        fs::create_dir(&external_rootfs).unwrap();

        // Create bundle with absolute rootfs path.
        let mut spec = Spec::default_linux();
        spec.root = Some(crate::config::Root {
            path: external_rootfs.to_string_lossy().to_string(),
            readonly: false,
        });

        let bundle = Bundle::create(&bundle_path, spec).unwrap();

        // Rootfs path should be the absolute path.
        assert_eq!(bundle.rootfs_path(), external_rootfs);
    }

    #[test]
    fn test_bundle_rootfs_readonly() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("readonly-test");

        // Not readonly by default.
        let bundle = Bundle::create_default(&bundle_path).unwrap();
        assert!(!bundle.rootfs_readonly());

        // Create readonly bundle.
        let bundle_path2 = dir.path().join("readonly-test2");
        let bundle = BundleBuilder::new()
            .readonly_rootfs(true)
            .build(&bundle_path2)
            .unwrap();
        assert!(bundle.rootfs_readonly());
    }

    #[test]
    fn test_bundle_validate() {
        let dir = create_temp_bundle();
        let bundle = Bundle::load(dir.path()).unwrap();
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_bundle_builder_all_options() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("full-builder-test");

        let mount = crate::config::Mount {
            destination: "/data".to_string(),
            source: Some("/host/data".to_string()),
            mount_type: Some("bind".to_string()),
            options: Some(vec!["rbind".to_string(), "ro".to_string()]),
            ..Default::default()
        };

        let bundle = BundleBuilder::new()
            .hostname("full-test")
            .args(vec!["nginx".to_string(), "-g".to_string(), "daemon off;".to_string()])
            .env(vec!["PATH=/usr/bin".to_string()])
            .add_env("NGINX_HOST", "localhost")
            .cwd("/var/www")
            .user(1000, 1000)
            .rootfs("rootfs")
            .readonly_rootfs(false)
            .terminal(true)
            .annotation("org.test.key1", "value1")
            .annotation("org.test.key2", "value2")
            .mount(mount)
            .build(&bundle_path)
            .unwrap();

        let spec = bundle.spec();
        assert_eq!(spec.hostname, Some("full-test".to_string()));

        let process = spec.process.as_ref().unwrap();
        assert_eq!(process.args, vec!["nginx", "-g", "daemon off;"]);
        assert!(process.env.iter().any(|e| e == "PATH=/usr/bin"));
        assert!(process.env.iter().any(|e| e == "NGINX_HOST=localhost"));
        assert_eq!(process.cwd, "/var/www");
        assert!(process.terminal);

        let user = process.user.as_ref().unwrap();
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gid, 1000);

        assert_eq!(spec.annotations.len(), 2);

        // Check the added mount (after default mounts).
        assert!(spec.mounts.iter().any(|m| m.destination == "/data"));
    }

    #[test]
    fn test_bundle_builder_with_spec() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("custom-spec-test");

        let mut custom_spec = Spec::default_linux();
        custom_spec.hostname = Some("custom".to_string());

        let bundle = BundleBuilder::with_spec(custom_spec)
            .annotation("added", "later")
            .build(&bundle_path)
            .unwrap();

        assert_eq!(bundle.spec().hostname, Some("custom".to_string()));
        assert_eq!(
            bundle.spec().annotations.get("added"),
            Some(&"later".to_string())
        );
    }

    #[test]
    fn test_bundle_builder_into_spec() {
        let builder = BundleBuilder::new()
            .hostname("spec-only")
            .args(vec!["test".to_string()]);

        let spec = builder.into_spec();
        assert_eq!(spec.hostname, Some("spec-only".to_string()));
    }

    #[test]
    fn test_bundle_not_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not-a-dir");
        fs::write(&file_path, "content").unwrap();

        let result = Bundle::load(&file_path);
        assert!(matches!(result, Err(OciError::InvalidBundle(_))));
    }

    #[test]
    fn test_find_bundles_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let bundles = utils::find_bundles(dir.path()).unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn test_find_bundles_nonexistent() {
        let bundles = utils::find_bundles("/nonexistent/path").unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn test_is_bundle_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("file");
        fs::write(&file_path, "content").unwrap();
        assert!(!utils::is_bundle(&file_path));
    }

    #[test]
    fn test_bundle_with_hooks() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("hooks-test");

        let mut spec = Spec::default_linux();
        spec.hooks = Some(crate::hooks::Hooks {
            create_runtime: vec![crate::hooks::Hook::new("/usr/bin/setup")],
            poststart: vec![crate::hooks::Hook::new("/usr/bin/notify")],
            ..Default::default()
        });

        let bundle = Bundle::create(&bundle_path, spec).unwrap();
        assert!(bundle.spec().hooks.is_some());

        let hooks = bundle.spec().hooks.as_ref().unwrap();
        assert_eq!(hooks.create_runtime.len(), 1);
        assert_eq!(hooks.poststart.len(), 1);
    }

    #[test]
    fn test_copy_rootfs() {
        let dir = tempfile::tempdir().unwrap();

        // Create source rootfs with some files.
        let source = dir.path().join("source-rootfs");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file1.txt"), "content1").unwrap();
        fs::create_dir(source.join("subdir")).unwrap();
        fs::write(source.join("subdir/file2.txt"), "content2").unwrap();

        // Copy to bundle.
        let bundle_path = dir.path().join("bundle");
        fs::create_dir(&bundle_path).unwrap();

        utils::copy_rootfs(&source, &bundle_path).unwrap();

        // Verify files were copied.
        let dest_rootfs = bundle_path.join("rootfs");
        assert!(dest_rootfs.join("file1.txt").exists());
        assert!(dest_rootfs.join("subdir/file2.txt").exists());

        // Verify content.
        let content = fs::read_to_string(dest_rootfs.join("file1.txt")).unwrap();
        assert_eq!(content, "content1");
    }

    #[test]
    fn test_copy_rootfs_nonexistent_source() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("bundle");
        fs::create_dir(&bundle_path).unwrap();

        let result = utils::copy_rootfs("/nonexistent/source", &bundle_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_default_rootfs_when_root_none() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("no-root-test");
        fs::create_dir(&bundle_path).unwrap();

        // Create a spec without root.
        let spec = Spec {
            oci_version: "1.2.0".to_string(),
            root: None,
            process: None,
            hostname: None,
            domainname: None,
            mounts: vec![],
            hooks: None,
            annotations: std::collections::HashMap::new(),
            linux: None,
        };

        // Save config.json directly.
        let config_path = bundle_path.join("config.json");
        fs::write(&config_path, serde_json::to_string(&spec).unwrap()).unwrap();

        let bundle = Bundle::load(&bundle_path).unwrap();

        // Should default to "rootfs" subdirectory.
        assert!(bundle.rootfs_path().ends_with("rootfs"));
    }
}
