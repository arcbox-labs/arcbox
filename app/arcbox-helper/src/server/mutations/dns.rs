//! DNS resolver file management for `/etc/resolver/`.
//!
//! Creates or removes per-domain resolver files that point macOS's
//! `mDNSResponder` to the ArcBox DNS server running on localhost.

use std::fs;
use std::path::Path;

use arcbox_helper::validate::{DnsPort, Domain};

use crate::server::fs_root;

/// Directory where macOS looks for per-domain resolver files.
const RESOLVER_DIR: &str = "/etc/resolver";

/// Marker comment to identify files managed by ArcBox.
const MARKER: &str = "# managed by arcbox-helper";

/// Installs a resolver file for `domain` pointing to `127.0.0.1:port`.
///
/// Creates `/etc/resolver/<domain>` with a nameserver entry.
/// Idempotent: overwrites if the file already exists **and** is ours, or is
/// missing. Foreign resolver files (no marker) are refused so we never clobber
/// admin-managed DNS.
pub fn install(domain: &Domain, port: DnsPort) -> Result<(), String> {
    install_at(&fs_root::resolve(RESOLVER_DIR), domain, port)
}

/// Removes the resolver file for `domain` **only** when it carries the
/// ArcBox management marker. Foreign resolver files are left alone.
///
/// Idempotent: returns Ok if the file does not exist or is not ours.
pub fn uninstall(domain: &Domain) -> Result<(), String> {
    uninstall_at(&fs_root::resolve(RESOLVER_DIR), domain)
}

/// Checks if an ArcBox-managed resolver file is installed for `domain`.
///
/// Requires the management marker so a hand-written resolver file is not
/// reported as "ours".
pub fn status(domain: &Domain) -> Result<bool, String> {
    status_at(&fs_root::resolve(RESOLVER_DIR), domain)
}

fn install_at(resolver_dir: &Path, domain: &Domain, port: DnsPort) -> Result<(), String> {
    fs::create_dir_all(resolver_dir)
        .map_err(|e| format!("failed to create {}: {e}", resolver_dir.display()))?;

    let path = resolver_dir.join(domain.as_str());
    match fs::read_to_string(&path) {
        Ok(content) if !content.contains(MARKER) => {
            return Err(format!(
                "{} exists and is not ArcBox-managed (not overwriting)",
                path.display()
            ));
        }
        Ok(_) | Err(_) => {}
    }

    let content =
        format!("{MARKER}\nnameserver 127.0.0.1\nport {port}\nsearch_order 1\ntimeout 5\n");

    fs::write(&path, content).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn uninstall_at(resolver_dir: &Path, domain: &Domain) -> Result<(), String> {
    let path = resolver_dir.join(domain.as_str());
    match fs::read_to_string(&path) {
        Ok(content) if content.contains(MARKER) => {
            fs::remove_file(&path).map_err(|e| format!("failed to remove {}: {e}", path.display()))
        }
        Ok(_) => {
            // Present but not managed by us — do not delete.
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("failed to read {}: {e}", path.display())),
    }
}

fn status_at(resolver_dir: &Path, domain: &Domain) -> Result<bool, String> {
    let path = resolver_dir.join(domain.as_str());
    match fs::read_to_string(&path) {
        Ok(content) => Ok(content.contains(MARKER)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("failed to read {}: {e}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::{MARKER, install_at, status_at, uninstall_at};
    use arcbox_helper::validate::{DnsPort, Domain};
    use std::fs;

    fn domain() -> Domain {
        "arcbox.local".parse().unwrap()
    }

    fn port() -> DnsPort {
        DnsPort::try_from(5553_u16).unwrap()
    }

    #[test]
    fn install_writes_marker_and_status() {
        let dir = tempfile::tempdir().unwrap();
        let d = domain();
        let p = port();

        assert!(!status_at(dir.path(), &d).unwrap());
        install_at(dir.path(), &d, p).unwrap();
        assert!(status_at(dir.path(), &d).unwrap());

        let content = fs::read_to_string(dir.path().join(d.as_str())).unwrap();
        assert!(content.contains(MARKER));
        assert!(content.contains("nameserver 127.0.0.1"));
        assert!(content.contains("port 5553"));

        // Idempotent overwrite of our own file.
        install_at(dir.path(), &d, p).unwrap();
    }

    #[test]
    fn uninstall_removes_only_marked_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = domain();
        let p = port();

        install_at(dir.path(), &d, p).unwrap();
        uninstall_at(dir.path(), &d).unwrap();
        assert!(!dir.path().join(d.as_str()).exists());
        // Missing is ok.
        uninstall_at(dir.path(), &d).unwrap();
    }

    #[test]
    fn foreign_resolver_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let d = domain();
        let path = dir.path().join(d.as_str());
        fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        // install must refuse.
        let err = install_at(dir.path(), &d, port()).unwrap_err();
        assert!(err.contains("not ArcBox-managed"), "{err}");
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 1.1.1.1\n");

        // status is false (no marker).
        assert!(!status_at(dir.path(), &d).unwrap());

        // uninstall is a no-op.
        uninstall_at(dir.path(), &d).unwrap();
        assert!(path.exists());
    }
}
