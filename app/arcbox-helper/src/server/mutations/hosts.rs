//! `/etc/hosts` alias for the guest-data NFS mount.

use std::fs;
use std::path::PathBuf;

use arcbox_helper::HelperError;
use arcbox_helper::{HOSTS_ALIAS_LINE as MANAGED_LINE, hosts_alias_installed};

use crate::server::fs_root;

const HOSTS_PATH: &str = "/etc/hosts";
const HOSTS_TMP_PATH: &str = "/etc/hosts.arcbox.tmp";
const MARKER: &str = "# managed by arcbox-helper";

fn hosts_path() -> PathBuf {
    fs_root::resolve(HOSTS_PATH)
}

fn hosts_tmp_path() -> PathBuf {
    fs_root::resolve(HOSTS_TMP_PATH)
}

pub fn install() -> Result<(), HelperError> {
    let content = read_hosts()?;
    match with_alias(&content) {
        Some(updated) => write_hosts(&updated),
        None => Ok(()),
    }
}

pub fn uninstall() -> Result<(), HelperError> {
    let content = read_hosts()?;
    match without_alias(&content) {
        Some(updated) => write_hosts(&updated),
        None => Ok(()),
    }
}

pub fn status() -> Result<bool, HelperError> {
    Ok(hosts_alias_installed(&read_hosts()?))
}

fn with_alias(content: &str) -> Option<String> {
    if hosts_alias_installed(content) {
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

fn read_hosts() -> Result<String, HelperError> {
    let path = hosts_path();
    match fs::read_to_string(&path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && fs_root::test_root().is_some() => {
            Ok(String::new())
        }
        Err(e) => Err(HelperError::io("read", &path, e)),
    }
}

fn write_hosts(content: &str) -> Result<(), HelperError> {
    use std::os::unix::fs::PermissionsExt;

    let hosts = hosts_path();
    let tmp = hosts_tmp_path();

    if let Some(parent) = hosts.parent() {
        fs::create_dir_all(parent).map_err(|e| HelperError::io("create_dir", parent, e))?;
    }

    fs::write(&tmp, content).map_err(|e| HelperError::io("write", &tmp, e))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
        .map_err(|e| HelperError::io("chmod", &tmp, e))?;
    fs::rename(&tmp, &hosts).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        HelperError::io("rename", &hosts, e)
    })
}

#[cfg(test)]
mod tests {
    use super::{MANAGED_LINE, MARKER, with_alias, without_alias};

    const BASE: &str = "##\n127.0.0.1\tlocalhost\n255.255.255.255\tbroadcasthost\n";

    #[test]
    fn managed_line_carries_the_uninstall_marker() {
        assert!(MANAGED_LINE.ends_with(MARKER));
    }

    #[test]
    fn install_appends_one_managed_line() {
        let updated = with_alias(BASE).expect("alias missing, should rewrite");
        assert!(updated.starts_with(BASE));
        assert!(updated.ends_with(&format!("{MANAGED_LINE}\n")));
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
        assert_eq!(without_alias(&removed), None);
    }

    #[test]
    fn uninstall_keeps_user_arcbox_entries() {
        let content = format!("10.0.0.1\tArcBox\n{MANAGED_LINE}\n");
        let removed = without_alias(&content).expect("managed line present");
        assert_eq!(removed, "10.0.0.1\tArcBox\n");
    }
}
