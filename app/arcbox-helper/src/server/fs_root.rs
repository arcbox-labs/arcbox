//! Optional filesystem root override for local E2E tests.
//!
//! When `ARCBOX_HELPER_TEST_ROOT` is set **and** this is a debug build, every
//! privileged path (`/usr/local/bin`, `/var/run/docker.sock`, `/etc/resolver`,
//! `/etc/hosts`, helper log dir) is rewritten under that directory so the real
//! helper binary can exercise mutations without root and without touching the
//! live system.
//!
//! Release builds **ignore** the env var — a production helper must never be
//! redirected by a caller-controlled path.

use std::path::PathBuf;

/// Env var that relocates privileged paths under a sandbox (debug only).
///
/// Release builds never read this variable (see [`test_root`]).
#[cfg(debug_assertions)]
pub const TEST_ROOT_ENV: &str = "ARCBOX_HELPER_TEST_ROOT";

/// Returns the active test root, if any.
#[must_use]
pub fn test_root() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        std::env::var_os(TEST_ROOT_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// Maps an absolute production path into the test root when active.
///
/// `/usr/local/bin` → `$TEST_ROOT/usr/local/bin`
#[must_use]
pub fn resolve(production_absolute: &str) -> PathBuf {
    debug_assert!(
        production_absolute.starts_with('/'),
        "production path must be absolute: {production_absolute}"
    );
    match test_root() {
        Some(root) => root.join(production_absolute.trim_start_matches('/')),
        None => PathBuf::from(production_absolute),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_without_root_is_identity() {
        // May or may not have the env set in the process; identity path when
        // unset is the important production behaviour.
        if test_root().is_none() {
            assert_eq!(resolve("/usr/local/bin"), PathBuf::from("/usr/local/bin"));
            assert_eq!(
                resolve("/var/run/docker.sock"),
                PathBuf::from("/var/run/docker.sock")
            );
        }
    }
}
