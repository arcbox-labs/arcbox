//! Host-to-guest path resolution for Docker bind mounts.
//!
//! On macOS, top-level directories like `/tmp`, `/var`, and `/etc` are symlinks
//! into `/private`. The guest VM mounts host `/private` via VirtioFS but keeps
//! its own `/tmp` and `/var` as isolated tmpfs. This module resolves the
//! top-level symlink so bind-mount source paths land on the VirtioFS share.
//!
//! On Linux hosts nothing is a symlink at the top level, so every function
//! here is a no-op without any `#[cfg]` gating.

use bytes::Bytes;
use std::borrow::Cow;
use std::path::{Component, Path};

/// Resolves the top-level symlink in a host path.
///
/// Checks whether the first path component (e.g. `/tmp`, `/var`) is a symlink
/// and, if so, replaces it with the symlink target. Deeper symlinks are left
/// untouched — only the macOS system-level mounts need resolving.
///
/// ```text
/// /tmp/foo          → /private/tmp/foo      (macOS: /tmp → private/tmp)
/// /var/folders/x/y  → /private/var/folders/x/y
/// /Users/me/proj    → /Users/me/proj        (/Users is not a symlink)
/// ```
pub fn resolve(path: &str) -> Cow<'_, str> {
    let p = Path::new(path);
    let mut components = p.components();

    // Must start with root `/`.
    if components.next() != Some(Component::RootDir) {
        return Cow::Borrowed(path);
    }

    // Grab the first real component (e.g. `tmp`, `var`).
    let Some(first) = components.next() else {
        return Cow::Borrowed(path);
    };

    let top = Path::new("/").join(first);
    let Ok(target) = top.read_link() else {
        // Not a symlink — return unchanged.
        return Cow::Borrowed(path);
    };

    // Resolve relative targets: /tmp → private/tmp means /private/tmp.
    let resolved = if target.is_relative() {
        Path::new("/").join(&target)
    } else {
        target
    };

    let rest: std::path::PathBuf = components.collect();
    let full = if rest.as_os_str().is_empty() {
        resolved
    } else {
        resolved.join(rest)
    };

    let s = full.to_string_lossy();
    if s == path {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(s.into_owned())
    }
}

/// Rewrites bind-mount source paths in a container-create request body.
///
/// Handles `HostConfig.Binds` (string array) and `HostConfig.Mounts`
/// (structured mount objects). Returns the original body unchanged if no
/// paths need rewriting.
pub fn rewrite_create_body(body: Bytes) -> Bytes {
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return body;
    };

    let mut changed = false;

    // HostConfig.Binds: ["host:container[:opts]", …]
    if let Some(binds) = v
        .pointer_mut("/HostConfig/Binds")
        .and_then(|v| v.as_array_mut())
    {
        for entry in binds {
            if let Some(s) = entry.as_str() {
                if let Some(rewritten) = rewrite_bind_entry(s) {
                    *entry = serde_json::Value::String(rewritten);
                    changed = true;
                }
            }
        }
    }

    // HostConfig.Mounts: [{Type: "bind", Source: "…", …}, …]
    if let Some(mounts) = v
        .pointer_mut("/HostConfig/Mounts")
        .and_then(|v| v.as_array_mut())
    {
        for mount in mounts {
            if mount.get("Type").and_then(|t| t.as_str()) != Some("bind") {
                continue;
            }
            if let Some(src) = mount.get("Source").and_then(|s| s.as_str()) {
                if let Cow::Owned(resolved) = resolve(src) {
                    mount["Source"] = serde_json::Value::String(resolved);
                    changed = true;
                }
            }
        }
    }

    if changed {
        serde_json::to_vec(&v).map_or(body, Bytes::from)
    } else {
        body
    }
}

/// Rewrites the host-path portion of a Binds entry (`"host:container[:opts]"`).
fn rewrite_bind_entry(entry: &str) -> Option<String> {
    let colon = entry.find(':')?;
    let host = &entry[..colon];
    if let Cow::Owned(resolved) = resolve(host) {
        Some(format!("{resolved}{}", &entry[colon..]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_leaves_non_symlink_paths_unchanged() {
        // /Users is a real directory on macOS, not a symlink.
        assert_eq!(resolve("/Users/me/project"), "/Users/me/project");
        assert_eq!(resolve("/nonexistent/path"), "/nonexistent/path");
        assert_eq!(resolve("/"), "/");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn resolve_follows_macos_tmp_symlink() {
        // On macOS, /tmp → private/tmp → /private/tmp.
        assert_eq!(resolve("/tmp"), "/private/tmp");
        assert_eq!(resolve("/tmp/foo"), "/private/tmp/foo");
        assert_eq!(
            resolve("/tmp/deep/nested/path"),
            "/private/tmp/deep/nested/path"
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn resolve_follows_macos_var_symlink() {
        assert_eq!(resolve("/var"), "/private/var");
        assert_eq!(resolve("/var/folders/xx/yy"), "/private/var/folders/xx/yy");
        assert_eq!(resolve("/var/tmp/foo"), "/private/var/tmp/foo");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn resolve_follows_macos_etc_symlink() {
        assert_eq!(resolve("/etc"), "/private/etc");
        assert_eq!(resolve("/etc/hosts"), "/private/etc/hosts");
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn resolve_already_private_is_unchanged() {
        assert_eq!(resolve("/private/tmp/foo"), "/private/tmp/foo");
        assert_eq!(
            resolve("/private/var/folders/xx"),
            "/private/var/folders/xx"
        );
    }

    #[test]
    fn rewrite_bind_entry_with_options() {
        // Only testable on macOS where /tmp is a symlink.
        if resolve("/tmp") == "/tmp" {
            return; // Not macOS — skip.
        }
        assert_eq!(
            rewrite_bind_entry("/tmp/foo:/app:ro"),
            Some("/private/tmp/foo:/app:ro".to_string())
        );
    }

    #[test]
    fn rewrite_bind_entry_no_change() {
        assert_eq!(rewrite_bind_entry("/Users/me/proj:/app"), None);
    }

    #[test]
    fn rewrite_create_body_binds() {
        if resolve("/tmp") == "/tmp" {
            return;
        }
        let body = serde_json::json!({
            "Image": "alpine",
            "HostConfig": {
                "Binds": ["/tmp/foo:/app", "/Users/me:/home:ro"]
            }
        });
        let input = Bytes::from(serde_json::to_vec(&body).unwrap());
        let output = rewrite_create_body(input);
        let v: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let binds = v["HostConfig"]["Binds"].as_array().unwrap();
        assert_eq!(binds[0], "/private/tmp/foo:/app");
        assert_eq!(binds[1], "/Users/me:/home:ro");
    }

    #[test]
    fn rewrite_create_body_mounts() {
        if resolve("/tmp") == "/tmp" {
            return;
        }
        let body = serde_json::json!({
            "Image": "alpine",
            "HostConfig": {
                "Mounts": [
                    {"Type": "bind", "Source": "/tmp/ctx", "Target": "/app"},
                    {"Type": "volume", "Source": "myvolume", "Target": "/data"},
                    {"Type": "bind", "Source": "/Users/me", "Target": "/home"}
                ]
            }
        });
        let input = Bytes::from(serde_json::to_vec(&body).unwrap());
        let output = rewrite_create_body(input);
        let v: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let mounts = v["HostConfig"]["Mounts"].as_array().unwrap();
        assert_eq!(mounts[0]["Source"], "/private/tmp/ctx");
        assert_eq!(mounts[1]["Source"], "myvolume"); // volume — untouched
        assert_eq!(mounts[2]["Source"], "/Users/me"); // not a symlink
    }

    #[test]
    fn rewrite_create_body_no_host_config_is_noop() {
        let body = Bytes::from(br#"{"Image":"alpine"}"#.to_vec());
        let output = rewrite_create_body(body.clone());
        assert_eq!(output, body);
    }

    #[test]
    fn rewrite_create_body_invalid_json_is_noop() {
        let body = Bytes::from(b"not json".to_vec());
        let output = rewrite_create_body(body.clone());
        assert_eq!(output, body);
    }
}
