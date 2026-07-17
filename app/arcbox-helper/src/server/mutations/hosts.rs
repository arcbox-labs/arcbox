//! `/etc/hosts` alias for the guest-data NFS mount.
//!
//! Finder's Locations sidebar displays a network mount by its source host
//! name, so mounting from `ArcBox:/` instead of `127.0.0.1:/` shows an
//! "ArcBox" location. The name resolves through this hosts entry.
//!
//! Only the fixed `127.0.0.1 ArcBox` line is ever written — the helper
//! offers no way to install caller-controlled hosts entries.

use std::fs;

const HOSTS_PATH: &str = "/etc/hosts";
/// Temp sibling for the atomic rewrite; same filesystem as `/etc/hosts`.
const HOSTS_TMP_PATH: &str = "/etc/hosts.arcbox.tmp";
/// The one managed line. The trailing comment marks it for uninstall.
const MANAGED_LINE: &str = "127.0.0.1\tArcBox\t# managed by arcbox-helper";
const MARKER: &str = "# managed by arcbox-helper";

/// Appends the ArcBox alias line to `/etc/hosts`.
///
/// Idempotent: returns Ok without rewriting when the managed line is
/// already present.
pub fn install() -> Result<(), String> {
    let content = read_hosts()?;
    match with_alias(&content) {
        Some(updated) => write_hosts(&updated),
        None => Ok(()),
    }
}

/// Removes the ArcBox alias line from `/etc/hosts`.
///
/// Idempotent: returns Ok when no managed line is present.
pub fn uninstall() -> Result<(), String> {
    let content = read_hosts()?;
    match without_alias(&content) {
        Some(updated) => write_hosts(&updated),
        None => Ok(()),
    }
}

/// Checks whether the ArcBox alias line is installed.
pub fn status() -> Result<bool, String> {
    Ok(read_hosts()?.lines().any(is_managed))
}

/// Returns the content with the alias appended, or `None` if present.
fn with_alias(content: &str) -> Option<String> {
    if content.lines().any(is_managed) {
        return None;
    }
    let mut updated = content.to_string();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(MANAGED_LINE);
    updated.push('\n');
    Some(updated)
}

/// Returns the content with managed lines removed, or `None` if none.
fn without_alias(content: &str) -> Option<String> {
    if !content.lines().any(is_managed) {
        return None;
    }
    let mut updated: String = content
        .lines()
        .filter(|line| !is_managed(line))
        .collect::<Vec<_>>()
        .join("\n");
    if !updated.is_empty() {
        updated.push('\n');
    }
    Some(updated)
}

fn is_managed(line: &str) -> bool {
    line.contains(MARKER)
}

fn read_hosts() -> Result<String, String> {
    fs::read_to_string(HOSTS_PATH).map_err(|e| format!("failed to read {HOSTS_PATH}: {e}"))
}

/// Replaces `/etc/hosts` atomically: write a temp sibling, fix its mode
/// (0644 — a truncated or partially written hosts file breaks name
/// resolution system-wide), then rename over the original.
fn write_hosts(content: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fs::write(HOSTS_TMP_PATH, content)
        .map_err(|e| format!("failed to write {HOSTS_TMP_PATH}: {e}"))?;
    fs::set_permissions(HOSTS_TMP_PATH, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("failed to chmod {HOSTS_TMP_PATH}: {e}"))?;
    fs::rename(HOSTS_TMP_PATH, HOSTS_PATH).map_err(|e| {
        let _ = fs::remove_file(HOSTS_TMP_PATH);
        format!("failed to replace {HOSTS_PATH}: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::{MANAGED_LINE, with_alias, without_alias};

    const BASE: &str = "##\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n";

    #[test]
    fn install_appends_one_managed_line() {
        let updated = with_alias(BASE).expect("alias missing, should rewrite");
        assert!(updated.starts_with(BASE));
        assert!(updated.ends_with(&format!("{MANAGED_LINE}\n")));
        // Idempotent: a second pass sees the line and does nothing.
        assert_eq!(with_alias(&updated), None);
    }

    #[test]
    fn install_handles_missing_trailing_newline() {
        let updated = with_alias("127.0.0.1\tlocalhost").expect("should rewrite");
        assert_eq!(updated, format!("127.0.0.1\tlocalhost\n{MANAGED_LINE}\n"));
    }

    #[test]
    fn uninstall_removes_only_managed_lines() {
        let installed = with_alias(BASE).expect("should rewrite");
        let removed = without_alias(&installed).expect("managed line present");
        assert_eq!(removed, BASE);
        // Idempotent: nothing left to remove.
        assert_eq!(without_alias(&removed), None);
    }

    #[test]
    fn uninstall_keeps_user_arcbox_entries() {
        // A user's own ArcBox line (no marker) must survive uninstall.
        let content = format!("10.0.0.1\tArcBox\n{MANAGED_LINE}\n");
        let removed = without_alias(&content).expect("managed line present");
        assert_eq!(removed, "10.0.0.1\tArcBox\n");
    }
}
