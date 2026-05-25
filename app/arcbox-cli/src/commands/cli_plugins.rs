//! Docker CLI plugin registration.
//!
//! Makes `docker compose` and `docker buildx` (space-separated subcommands)
//! discoverable by the upstream `docker` CLI, which looks plugins up via:
//!
//!   1. `cliPluginsExtraDirs` in `~/.docker/config.json`
//!   2. `~/.docker/cli-plugins/<name>`
//!   3. `/usr/local/lib/docker/cli-plugins/<name>`
//!   4. `/usr/lib/docker/cli-plugins/<name>`
//!
//! We wire up both (1) and (2) for belt-and-suspenders coverage:
//!
//! - **(2) symlinks** are the idiomatic registration mechanism and are what
//!   most users expect to see when auditing their Docker setup.
//! - **(1) extraDirs** serves as a fallback if a user wipes
//!   `~/.docker/cli-plugins/` or hasn't got it at all (it doesn't exist on
//!   a fresh machine without Docker Desktop installed).
//!
//! Both point at `~/.arcbox/bin/<name>`, which `setup::install()` has
//! already populated with symlinks into the app bundle or runtime bin.
//!
//! Plugin registration is per-user and decoupled from Docker context
//! `enable`/`disable`. Compose/buildx themselves are context-aware (they
//! honour `DOCKER_HOST` / the current context), so the binaries work
//! correctly even when the user has switched to another Docker backend.
//! This means `docker compose` keeps working after `abctl docker disable`
//! — it just talks to whichever backend the user switched to.
//!
//! The Docker config directory is resolved via `DOCKER_CONFIG` (matching
//! upstream `docker` CLI behaviour), falling back to `~/.docker`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

use arcbox_constants::paths::DOCKER_CLI_PLUGINS;

/// Summary of what a register/unregister call did.
#[derive(Debug, Default, Serialize)]
pub struct Outcome {
    /// Plugin symlinks created or removed under `~/.docker/cli-plugins/`.
    pub symlinks: Vec<PathBuf>,
    /// Whether `cliPluginsExtraDirs` in `~/.docker/config.json` was modified.
    pub config_updated: bool,
}

/// Current registration state — reported by `setup status`.
#[derive(Debug, Default, Serialize)]
pub struct RegistrationStatus {
    /// Plugins with a valid symlink under `~/.docker/cli-plugins/` pointing
    /// into `user_bin`.
    pub symlinked: Vec<String>,
    /// Whether `user_bin` appears in `cliPluginsExtraDirs`.
    pub extra_dirs_entry_present: bool,
}

/// Resolves the user's Docker config directory.
///
/// Honours the `DOCKER_CONFIG` environment variable (matching the
/// upstream `docker` CLI). Falls back to `~/.docker` when the variable
/// is unset or empty.
pub fn default_docker_config_dir() -> Result<PathBuf> {
    resolve_docker_config_dir(std::env::var_os("DOCKER_CONFIG"))
}

fn resolve_docker_config_dir(env_override: Option<std::ffi::OsString>) -> Result<PathBuf> {
    if let Some(value) = env_override {
        if !value.is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    dirs::home_dir()
        .map(|h| h.join(".docker"))
        .context("could not determine home directory")
}

/// Registers ArcBox's compose/buildx binaries as Docker CLI plugins.
///
/// Creates `<docker_config_dir>/cli-plugins/<plugin>` symlinks pointing to
/// `<user_bin>/<plugin>`, and — only if at least one plugin binary actually
/// exists under `user_bin` — adds `user_bin` to `cliPluginsExtraDirs` in
/// `<docker_config_dir>/config.json` (preserving all other keys).
///
/// ## Precedence caveat
///
/// Docker resolves plugins in this order: `cliPluginsExtraDirs` →
/// `~/.docker/cli-plugins/` → system dirs. Because `extraDirs` is searched
/// *first*, once `user_bin` is registered there, ArcBox's plugin wins even
/// when a foreign symlink (e.g. Docker Desktop's) is present at
/// `~/.docker/cli-plugins/<name>`. We keep the foreign symlink in place so
/// a human auditing `~/.docker/cli-plugins/` still sees it, but it is no
/// longer the selected binary at CLI invocation time.
///
/// This matches the practical expectation: if the user has ArcBox
/// installed, they almost certainly want ArcBox's compose/buildx over
/// Docker Desktop's (which would target Desktop's socket, not ArcBox's).
/// `unregister()` removes `user_bin` from `extraDirs` so Desktop becomes
/// selectable again on uninstall.
///
/// ## Idempotence
///
/// Safe to call repeatedly. Never overwrites a foreign symlink — those are
/// left untouched. Never mutates `config.json` if no plugin binary was
/// shipped (avoids churn on builds that don't bundle compose/buildx).
pub async fn register(user_bin: &Path, docker_config_dir: &Path) -> Result<Outcome> {
    let mut outcome = Outcome::default();

    // (B) symlinks — also tracks whether any plugin binary was actually
    //     present so we know to register (A) extraDirs.
    let plugins_dir = docker_config_dir.join("cli-plugins");
    tokio::fs::create_dir_all(&plugins_dir)
        .await
        .with_context(|| format!("failed to create {}", plugins_dir.display()))?;

    let mut any_plugin_present = false;

    for plugin in DOCKER_CLI_PLUGINS {
        let target = user_bin.join(plugin);
        if !target.exists() {
            // Nothing to register for this plugin — the binary wasn't linked
            // into ~/.arcbox/bin/ (e.g. missing from the app bundle). Skip
            // silently rather than creating a dangling symlink.
            continue;
        }
        any_plugin_present = true;

        let link = plugins_dir.join(plugin);
        match tokio::fs::symlink_metadata(&link).await {
            Ok(meta) if meta.file_type().is_symlink() => {
                if let Ok(existing) = tokio::fs::read_link(&link).await {
                    if existing == target {
                        continue;
                    }
                    if !is_arcbox_bin_target(&existing, user_bin) {
                        // Foreign symlink (e.g. Docker Desktop). Leave it
                        // alone — extraDirs below still makes ArcBox win at
                        // resolution time.
                        continue;
                    }
                    tokio::fs::remove_file(&link).await.ok();
                }
            }
            Ok(_) => {
                // Regular file or directory — not ours to touch.
                continue;
            }
            Err(_) => {}
        }

        #[cfg(unix)]
        {
            tokio::fs::symlink(&target, &link).await.with_context(|| {
                format!(
                    "failed to create plugin symlink {} -> {}",
                    link.display(),
                    target.display()
                )
            })?;
            outcome.symlinks.push(link);
        }
        #[cfg(not(unix))]
        {
            let _ = link;
        }
    }

    // (A) cliPluginsExtraDirs — only when we actually have plugins to
    //     advertise. Skipping the mutation on plugin-less installs keeps
    //     config.json clean.
    if any_plugin_present {
        let config_path = docker_config_dir.join("config.json");
        let user_bin_str = user_bin.to_string_lossy().into_owned();
        outcome.config_updated = update_extra_dirs(&config_path, &user_bin_str, true).await?;
    }

    Ok(outcome)
}

/// Reverses [`register`]. Only removes resources that still point at
/// `user_bin` — never touches foreign symlinks or extraDirs entries.
pub async fn unregister(user_bin: &Path, docker_config_dir: &Path) -> Result<Outcome> {
    let mut outcome = Outcome::default();

    let plugins_dir = docker_config_dir.join("cli-plugins");
    if plugins_dir.is_dir() {
        for plugin in DOCKER_CLI_PLUGINS {
            let link = plugins_dir.join(plugin);
            let Ok(meta) = tokio::fs::symlink_metadata(&link).await else {
                continue;
            };
            if !meta.file_type().is_symlink() {
                continue;
            }
            let Ok(target) = tokio::fs::read_link(&link).await else {
                continue;
            };
            if !is_arcbox_bin_target(&target, user_bin) {
                continue;
            }
            if tokio::fs::remove_file(&link).await.is_ok() {
                outcome.symlinks.push(link);
            }
        }
    }

    let config_path = docker_config_dir.join("config.json");
    let user_bin_str = user_bin.to_string_lossy().into_owned();
    outcome.config_updated = update_extra_dirs(&config_path, &user_bin_str, false).await?;

    Ok(outcome)
}

/// Reports the current registration state for status output.
pub async fn status(user_bin: &Path, docker_config_dir: &Path) -> RegistrationStatus {
    let mut result = RegistrationStatus::default();

    let plugins_dir = docker_config_dir.join("cli-plugins");
    for plugin in DOCKER_CLI_PLUGINS {
        let link = plugins_dir.join(plugin);
        if let Ok(target) = tokio::fs::read_link(&link).await {
            if is_arcbox_bin_target(&target, user_bin) {
                result.symlinked.push((*plugin).to_string());
            }
        }
    }

    let config_path = docker_config_dir.join("config.json");
    if let Ok(content) = tokio::fs::read_to_string(&config_path).await {
        if let Ok(serde_json::Value::Object(obj)) =
            serde_json::from_str::<serde_json::Value>(&content)
        {
            if let Some(serde_json::Value::Array(arr)) = obj.get("cliPluginsExtraDirs") {
                let user_bin_str = user_bin.to_string_lossy();
                result.extra_dirs_entry_present = arr
                    .iter()
                    .any(|v| v.as_str() == Some(user_bin_str.as_ref()));
            }
        }
    }

    result
}

/// True if `target` is a path inside `user_bin` (i.e. a symlink ArcBox owns).
fn is_arcbox_bin_target(target: &Path, user_bin: &Path) -> bool {
    target.starts_with(user_bin)
}

/// Reads `~/.docker/config.json`, adds or removes `user_bin` from the
/// `cliPluginsExtraDirs` array (preserving all other keys), and writes it
/// back. Returns `true` if the file was modified.
async fn update_extra_dirs(config_path: &Path, user_bin: &str, insert: bool) -> Result<bool> {
    // Load or start fresh. Missing file treated as empty object.
    let mut value: serde_json::Value = match tokio::fs::read_to_string(config_path).await {
        Ok(s) if s.trim().is_empty() => serde_json::json!({}),
        Ok(s) => serde_json::from_str(&s)
            .with_context(|| format!("failed to parse {}", config_path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if !insert {
                // Nothing to unregister when the file doesn't exist.
                return Ok(false);
            }
            serde_json::json!({})
        }
        Err(e) => {
            return Err(
                anyhow::Error::from(e).context(format!("failed to read {}", config_path.display()))
            );
        }
    };

    let obj = value
        .as_object_mut()
        .context("Docker config.json is not a JSON object")?;

    let modified = if insert {
        let entry = obj
            .entry("cliPluginsExtraDirs")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        let Some(array) = entry.as_array_mut() else {
            // Pre-existing non-array value (string, number, …) is foreign
            // state we did not create. Don't fail registration — the
            // symlink-based discovery path is still in place, and the user
            // is best served by leaving their oddly-shaped config alone.
            return Ok(false);
        };
        if array.iter().any(|v| v.as_str() == Some(user_bin)) {
            false
        } else {
            array.push(serde_json::Value::String(user_bin.to_string()));
            true
        }
    } else {
        let Some(entry) = obj.get_mut("cliPluginsExtraDirs") else {
            return Ok(false);
        };
        let Some(array) = entry.as_array_mut() else {
            return Ok(false);
        };
        let before = array.len();
        array.retain(|v| v.as_str() != Some(user_bin));
        let changed = array.len() != before;
        if array.is_empty() {
            obj.remove("cliPluginsExtraDirs");
        }
        changed
    };

    if !modified {
        return Ok(false);
    }

    // Ensure parent directory exists (covers first-ever write).
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await.ok();
    }

    let serialized = serde_json::to_string_pretty(&value)?;
    atomic_write(config_path, format!("{serialized}\n").as_bytes()).await?;
    Ok(true)
}

/// Write `contents` to `path` atomically: write into a sibling temp file
/// in the same directory, then `rename` over the destination.
///
/// `tokio::fs::write` opens with `O_TRUNC`, so a crash between truncate
/// and write completion would leave the destination empty — catastrophic
/// for files like `~/.docker/config.json` that hold the user's registry
/// credentials.
async fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("arcbox-tmp");
    // PID-scoped tmp name keeps concurrent processes from clobbering each
    // other's in-flight writes. Same-directory tmp guarantees `rename` is
    // atomic (same filesystem).
    let tmp_name = format!(".{}.{}.tmp", file_name, std::process::id());
    let tmp_path = path.with_file_name(tmp_name);

    if let Err(e) = tokio::fs::write(&tmp_path, contents).await {
        // Best-effort cleanup so a failed write doesn't leave a stale tmp.
        tokio::fs::remove_file(&tmp_path).await.ok();
        return Err(
            anyhow::Error::from(e).context(format!("failed to write {}", tmp_path.display()))
        );
    }

    tokio::fs::rename(&tmp_path, path).await.with_context(|| {
        format!(
            "failed to rename {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Creates a dummy executable at `<dir>/<name>` so symlink creation has a
    /// real target to point at.
    fn touch_exe(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = fs::metadata(&path).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(&path, perm).unwrap();
        }
        path
    }

    #[tokio::test]
    async fn register_creates_symlinks_and_extra_dirs() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("arcbox-bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        touch_exe(&user_bin, "docker-compose");
        touch_exe(&user_bin, "docker-buildx");

        let outcome = register(&user_bin, &docker_cfg).await.unwrap();

        assert_eq!(outcome.symlinks.len(), 2);
        assert!(outcome.config_updated);

        // Symlinks point to our binaries.
        let compose_link = docker_cfg.join("cli-plugins/docker-compose");
        assert_eq!(
            fs::read_link(&compose_link).unwrap(),
            user_bin.join("docker-compose")
        );

        // config.json contains extraDirs with user_bin.
        let cfg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(docker_cfg.join("config.json")).unwrap())
                .unwrap();
        let dirs = cfg
            .get("cliPluginsExtraDirs")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].as_str(), Some(user_bin.to_string_lossy().as_ref()));
    }

    #[tokio::test]
    async fn register_is_idempotent() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        touch_exe(&user_bin, "docker-compose");
        touch_exe(&user_bin, "docker-buildx");

        let first = register(&user_bin, &docker_cfg).await.unwrap();
        assert!(first.config_updated);
        assert_eq!(first.symlinks.len(), 2);

        let second = register(&user_bin, &docker_cfg).await.unwrap();
        assert!(!second.config_updated);
        assert!(second.symlinks.is_empty());
    }

    #[tokio::test]
    async fn register_preserves_other_config_keys() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        fs::create_dir_all(&docker_cfg).unwrap();
        touch_exe(&user_bin, "docker-compose");

        fs::write(
            docker_cfg.join("config.json"),
            r#"{"currentContext":"desktop-linux","auths":{"ghcr.io":{}}}"#,
        )
        .unwrap();

        register(&user_bin, &docker_cfg).await.unwrap();

        let cfg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(docker_cfg.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(cfg["currentContext"].as_str(), Some("desktop-linux"));
        assert!(cfg["auths"]["ghcr.io"].is_object());
        assert!(cfg["cliPluginsExtraDirs"].is_array());
    }

    #[tokio::test]
    async fn register_skips_foreign_symlinks() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        let other_bin = tmp.path().join("other");
        fs::create_dir_all(&user_bin).unwrap();
        fs::create_dir_all(&other_bin).unwrap();
        fs::create_dir_all(docker_cfg.join("cli-plugins")).unwrap();
        touch_exe(&user_bin, "docker-compose");
        let foreign_target = touch_exe(&other_bin, "docker-compose");

        // Pre-existing foreign symlink (simulating Docker Desktop).
        let foreign_link = docker_cfg.join("cli-plugins/docker-compose");
        std::os::unix::fs::symlink(&foreign_target, &foreign_link).unwrap();

        let outcome = register(&user_bin, &docker_cfg).await.unwrap();

        // The foreign symlink must be untouched.
        assert_eq!(fs::read_link(&foreign_link).unwrap(), foreign_target);
        assert!(!outcome.symlinks.contains(&foreign_link));
    }

    #[tokio::test]
    async fn register_without_plugin_binaries_leaves_config_untouched() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        // No plugin binaries touched into user_bin.

        let outcome = register(&user_bin, &docker_cfg).await.unwrap();

        assert!(outcome.symlinks.is_empty());
        assert!(
            !outcome.config_updated,
            "config.json must not be mutated when no plugins are present"
        );
        assert!(
            !docker_cfg.join("config.json").exists(),
            "config.json must not be created when nothing is registered"
        );
    }

    #[tokio::test]
    async fn register_skips_missing_plugin_binary() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        // Only compose exists; buildx is missing.
        touch_exe(&user_bin, "docker-compose");

        let outcome = register(&user_bin, &docker_cfg).await.unwrap();

        assert_eq!(outcome.symlinks.len(), 1);
        assert!(!docker_cfg.join("cli-plugins/docker-buildx").exists());
    }

    #[tokio::test]
    async fn unregister_removes_only_our_symlinks() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        let other_bin = tmp.path().join("other");
        fs::create_dir_all(&user_bin).unwrap();
        fs::create_dir_all(&other_bin).unwrap();
        fs::create_dir_all(docker_cfg.join("cli-plugins")).unwrap();
        touch_exe(&user_bin, "docker-compose");
        touch_exe(&user_bin, "docker-buildx");
        let foreign_target = touch_exe(&other_bin, "docker-buildx");

        register(&user_bin, &docker_cfg).await.unwrap();

        // Replace buildx with a foreign symlink before unregistering.
        let buildx_link = docker_cfg.join("cli-plugins/docker-buildx");
        fs::remove_file(&buildx_link).unwrap();
        std::os::unix::fs::symlink(&foreign_target, &buildx_link).unwrap();

        let outcome = unregister(&user_bin, &docker_cfg).await.unwrap();

        // compose removed, buildx preserved.
        assert!(
            !docker_cfg.join("cli-plugins/docker-compose").exists(),
            "our compose symlink should be gone"
        );
        assert_eq!(fs::read_link(&buildx_link).unwrap(), foreign_target);
        assert_eq!(outcome.symlinks.len(), 1);
    }

    #[tokio::test]
    async fn unregister_removes_only_our_extra_dirs_entry() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        fs::create_dir_all(&docker_cfg).unwrap();
        touch_exe(&user_bin, "docker-compose");

        fs::write(
            docker_cfg.join("config.json"),
            format!(
                r#"{{"cliPluginsExtraDirs":["/opt/other/cli-plugins","{}"]}}"#,
                user_bin.to_string_lossy()
            ),
        )
        .unwrap();

        unregister(&user_bin, &docker_cfg).await.unwrap();

        let cfg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(docker_cfg.join("config.json")).unwrap())
                .unwrap();
        let dirs = cfg["cliPluginsExtraDirs"].as_array().unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].as_str(), Some("/opt/other/cli-plugins"));
    }

    #[tokio::test]
    async fn unregister_drops_empty_extra_dirs_key() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        touch_exe(&user_bin, "docker-compose");

        register(&user_bin, &docker_cfg).await.unwrap();
        unregister(&user_bin, &docker_cfg).await.unwrap();

        let cfg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(docker_cfg.join("config.json")).unwrap())
                .unwrap();
        assert!(
            cfg.get("cliPluginsExtraDirs").is_none(),
            "empty extraDirs array should be removed"
        );
    }

    #[tokio::test]
    async fn unregister_is_idempotent_on_missing_config() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();

        // No ~/.docker at all — must not panic or error.
        let outcome = unregister(&user_bin, &docker_cfg).await.unwrap();
        assert!(outcome.symlinks.is_empty());
        assert!(!outcome.config_updated);
    }

    #[tokio::test]
    async fn status_reports_registration() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        touch_exe(&user_bin, "docker-compose");
        touch_exe(&user_bin, "docker-buildx");

        let before = status(&user_bin, &docker_cfg).await;
        assert!(before.symlinked.is_empty());
        assert!(!before.extra_dirs_entry_present);

        register(&user_bin, &docker_cfg).await.unwrap();

        let after = status(&user_bin, &docker_cfg).await;
        assert_eq!(after.symlinked.len(), 2);
        assert!(after.extra_dirs_entry_present);
    }

    #[test]
    fn resolve_docker_config_dir_honors_env_override() {
        let custom = PathBuf::from("/tmp/custom-docker");
        let resolved = resolve_docker_config_dir(Some(custom.as_os_str().to_os_string())).unwrap();
        assert_eq!(resolved, custom);
    }

    #[test]
    fn resolve_docker_config_dir_ignores_empty_env() {
        let resolved = resolve_docker_config_dir(Some(std::ffi::OsString::new())).unwrap();
        assert!(resolved.ends_with(".docker"));
    }

    #[tokio::test]
    async fn atomic_write_leaves_no_tmp_files_on_success() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("config.json");
        atomic_write(&target, b"{}\n").await.unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "{}\n");

        // Nothing of the form `.config.json.<pid>.tmp` should remain.
        let leftover = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover, "atomic_write must clean up its tmp file");
    }

    #[tokio::test]
    async fn register_preserves_top_level_key_order() {
        // With serde_json's `preserve_order` feature, round-tripping a
        // config object through `Value::Object` keeps insertion order
        // intact — so users diffing config.json see only the
        // cliPluginsExtraDirs append, not a spurious alphabetic resort.
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        fs::create_dir_all(&docker_cfg).unwrap();
        touch_exe(&user_bin, "docker-compose");

        fs::write(
            docker_cfg.join("config.json"),
            r#"{"currentContext":"desktop","credsStore":"osxkeychain","auths":{}}"#,
        )
        .unwrap();

        register(&user_bin, &docker_cfg).await.unwrap();

        let rewritten = fs::read_to_string(docker_cfg.join("config.json")).unwrap();
        let ctx = rewritten.find("currentContext").unwrap();
        let creds = rewritten.find("credsStore").unwrap();
        let auths = rewritten.find("auths").unwrap();
        let extra = rewritten.find("cliPluginsExtraDirs").unwrap();
        assert!(ctx < creds && creds < auths && auths < extra);
    }

    #[tokio::test]
    async fn register_tolerates_non_array_extra_dirs() {
        let tmp = tempdir().unwrap();
        let user_bin = tmp.path().join("bin");
        let docker_cfg = tmp.path().join("docker");
        fs::create_dir_all(&user_bin).unwrap();
        fs::create_dir_all(&docker_cfg).unwrap();
        touch_exe(&user_bin, "docker-compose");

        // Pre-existing config with cliPluginsExtraDirs as a string — foreign
        // state we shouldn't blow up on.
        fs::write(
            docker_cfg.join("config.json"),
            r#"{"cliPluginsExtraDirs":"/opt/plugins","auths":{"ghcr.io":{}}}"#,
        )
        .unwrap();

        let outcome = register(&user_bin, &docker_cfg).await.unwrap();

        // Symlink still gets created; only the config-side update is skipped.
        assert_eq!(outcome.symlinks.len(), 1);
        assert!(!outcome.config_updated);

        // The original (foreign) value is preserved verbatim.
        let cfg: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(docker_cfg.join("config.json")).unwrap())
                .unwrap();
        assert_eq!(cfg["cliPluginsExtraDirs"].as_str(), Some("/opt/plugins"));
        assert!(cfg["auths"]["ghcr.io"].is_object());
    }
}
