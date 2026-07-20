//! DNS resolver file management for `/etc/resolver/`.

use std::fs;
use std::path::Path;

use arcbox_helper::HelperError;
use arcbox_helper::validate::{DnsPort, Domain};

use crate::server::fs_root;

const RESOLVER_DIR: &str = "/etc/resolver";
const MARKER: &str = "# managed by arcbox-helper";

pub fn install(domain: &Domain, port: DnsPort) -> Result<(), HelperError> {
    install_at(&fs_root::resolve(RESOLVER_DIR), domain, port)
}

pub fn uninstall(domain: &Domain) -> Result<(), HelperError> {
    uninstall_at(&fs_root::resolve(RESOLVER_DIR), domain)
}

pub fn status(domain: &Domain) -> Result<bool, HelperError> {
    status_at(&fs_root::resolve(RESOLVER_DIR), domain)
}

fn install_at(resolver_dir: &Path, domain: &Domain, port: DnsPort) -> Result<(), HelperError> {
    fs::create_dir_all(resolver_dir).map_err(|e| HelperError::io("create_dir", resolver_dir, e))?;

    let path = resolver_dir.join(domain.as_str());
    match fs::read_to_string(&path) {
        Ok(content) if !content.contains(MARKER) => {
            return Err(HelperError::foreign_managed(&path));
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(HelperError::io("read", &path, e)),
    }

    let content =
        format!("{MARKER}\nnameserver 127.0.0.1\nport {port}\nsearch_order 1\ntimeout 5\n");
    fs::write(&path, content).map_err(|e| HelperError::io("write", &path, e))
}

fn uninstall_at(resolver_dir: &Path, domain: &Domain) -> Result<(), HelperError> {
    let path = resolver_dir.join(domain.as_str());
    match fs::read_to_string(&path) {
        Ok(content) if content.contains(MARKER) => {
            fs::remove_file(&path).map_err(|e| HelperError::io("remove", &path, e))
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(HelperError::io("read", &path, e)),
    }
}

fn status_at(resolver_dir: &Path, domain: &Domain) -> Result<bool, HelperError> {
    let path = resolver_dir.join(domain.as_str());
    match fs::read_to_string(&path) {
        Ok(content) => Ok(content.contains(MARKER)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(HelperError::io("read", &path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::{MARKER, install_at, status_at, uninstall_at};
    use arcbox_helper::HelperError;
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
        install_at(dir.path(), &d, p).unwrap();
    }

    #[test]
    fn uninstall_removes_only_marked_files() {
        let dir = tempfile::tempdir().unwrap();
        let d = domain();
        install_at(dir.path(), &d, port()).unwrap();
        uninstall_at(dir.path(), &d).unwrap();
        assert!(!dir.path().join(d.as_str()).exists());
        uninstall_at(dir.path(), &d).unwrap();
    }

    #[test]
    fn foreign_resolver_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let d = domain();
        let path = dir.path().join(d.as_str());
        fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        let err = install_at(dir.path(), &d, port()).unwrap_err();
        assert!(
            matches!(err, HelperError::ForeignManagedFile { .. }),
            "{err}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "nameserver 1.1.1.1\n");
        assert!(!status_at(dir.path(), &d).unwrap());
        uninstall_at(dir.path(), &d).unwrap();
        assert!(path.exists());
    }
}
