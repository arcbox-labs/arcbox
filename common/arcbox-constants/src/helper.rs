//! Privileged helper version helpers shared by daemon, CLI, and (via the same
//! string format) the Desktop app.
//!
//! The helper crate (`arcbox-helper`) owns an **independent** Cargo version
//! (currently `1.0.3`), not `workspace.package.version`. Compare that version
//! — never the daemon/workspace crate version — when deciding whether to
//! reinstall the root binary.
//!
//! `arcbox-helper --version` and the helper `version` RPC both print:
//! ```text
//! arcbox-helper <semver>
//! ```

/// Minimum helper crate version the current daemon/CLI build requires.
///
/// Keep this equal to `arcbox-helper`'s package version after a required
/// helper upgrade. Lower it only when intentionally supporting older on-disk
/// helpers across an upgrade window.
///
/// Must stay in sync with `app/arcbox-helper/Cargo.toml` `version` (and the
/// workspace path-dep pin) whenever the floor moves.
pub const MIN_HELPER_VERSION: &str = "1.0.3";

/// Strips the optional `arcbox-helper ` prefix and whitespace from a version line.
#[must_use]
pub fn normalize_helper_version_line(version_output: &str) -> &str {
    let s = version_output.trim();
    s.strip_prefix("arcbox-helper")
        .map(str::trim)
        .filter(|rest| !rest.is_empty())
        .unwrap_or(s)
}

/// Parses a dotted numeric version into `(major, minor, patch)` components.
///
/// Strips any pre-release / build suffix (everything from the first `-` or
/// `+`), then reads up to three dot-separated numeric fields (missing minor
/// / patch default to `0`). Returns `None` when no leading numeric component
/// is present.
#[must_use]
pub fn parse_semver_triple(version: &str) -> Option<(u64, u64, u64)> {
    let core = version
        .split_once(['-', '+'])
        .map_or(version, |(core, _)| core)
        .trim();
    if core.is_empty() {
        return None;
    }
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().map_or(Ok(0), str::parse).ok()?;
    let patch = parts.next().map_or(Ok(0), str::parse).ok()?;
    Some((major, minor, patch))
}

/// Extracts a semver triple from a helper `--version` / RPC line.
///
/// - `arcbox-helper 1.0.0` → `Some((1, 0, 0))`
/// - `arcbox-helper 0.4.12` (legacy, workspace-tied) → `Some((0, 4, 12))`
/// - garbage → `None`
#[must_use]
pub fn parse_helper_version(version_output: &str) -> Option<(u64, u64, u64)> {
    parse_semver_triple(normalize_helper_version_line(version_output))
}

/// `true` when the installed helper is safe for a daemon that requires
/// `minimum`.
///
/// Rules:
/// - **Same major** as `minimum` (wire major; a future `2.x` helper is not
///   accepted by a `1.x` daemon even if `2.x > 1.x` numerically).
/// - `installed >= minimum` within that major (minor/patch floor).
///
/// A higher major must force reinstall / doctor fail so tarpc ordinal and
/// `HelperError` layout breaks cannot be silently driven into the wrong binary.
#[must_use]
pub fn helper_version_satisfies(installed: (u64, u64, u64), minimum: (u64, u64, u64)) -> bool {
    installed.0 == minimum.0 && installed >= minimum
}

/// Whether the on-disk helper should be replaced by the bundled binary.
///
/// Reinstall when:
/// - installed or bundled version is missing / unparseable
/// - **major differs** either way (wire break; including app downgrade that
///   left a newer-major helper on disk)
/// - installed is **strictly older** than bundled within the same major
///
/// Equal or newer minor/patch on the **same major** keeps the existing binary
/// so ordinary app downgrades do not thrash the admin-password prompt.
#[must_use]
pub fn helper_needs_reinstall(
    installed: Option<(u64, u64, u64)>,
    bundled: Option<(u64, u64, u64)>,
) -> bool {
    match (installed, bundled) {
        (_, None) => true,
        (None, Some(_)) => true,
        (Some(have), Some(want)) => have.0 != want.0 || have < want,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_prefix() {
        assert_eq!(
            normalize_helper_version_line("arcbox-helper 1.0.0"),
            "1.0.0"
        );
        assert_eq!(normalize_helper_version_line("1.2.3"), "1.2.3");
        assert_eq!(
            normalize_helper_version_line("  arcbox-helper   1.0.0\n"),
            "1.0.0"
        );
    }

    #[test]
    fn parses_helper_lines() {
        assert_eq!(parse_helper_version("arcbox-helper 1.0.0"), Some((1, 0, 0)));
        assert_eq!(
            parse_helper_version("arcbox-helper 0.4.12"),
            Some((0, 4, 12))
        );
        assert_eq!(parse_helper_version("arcbox-helper 2.1"), Some((2, 1, 0)));
        assert_eq!(parse_helper_version("not-a-helper"), None);
    }

    #[test]
    fn satisfies_and_reinstall_policy() {
        assert!(helper_version_satisfies((1, 0, 0), (1, 0, 0)));
        assert!(helper_version_satisfies((1, 0, 1), (1, 0, 0)));
        assert!(!helper_version_satisfies((0, 4, 24), (1, 0, 0)));
        // Higher major is a wire break — not "newer is fine".
        assert!(!helper_version_satisfies((2, 0, 0), (1, 0, 0)));
        assert!(!helper_version_satisfies((1, 0, 0), (2, 0, 0)));

        assert!(helper_needs_reinstall(None, Some((1, 0, 0))));
        assert!(helper_needs_reinstall(Some((0, 4, 12)), Some((1, 0, 0))));
        assert!(!helper_needs_reinstall(Some((1, 0, 0)), Some((1, 0, 0))));
        // Same major, newer patch/minor — keep (no password thrash on app downgrade).
        assert!(!helper_needs_reinstall(Some((1, 1, 0)), Some((1, 0, 0))));
        // Major mismatch either direction — replace.
        assert!(helper_needs_reinstall(Some((2, 0, 0)), Some((1, 0, 0))));
        assert!(helper_needs_reinstall(Some((1, 0, 0)), Some((2, 0, 0))));
    }

    /// `MIN_HELPER_VERSION` must parse and stay a proper semver triple.
    #[test]
    fn min_helper_version_is_valid_semver() {
        assert!(
            parse_semver_triple(MIN_HELPER_VERSION).is_some(),
            "MIN_HELPER_VERSION={MIN_HELPER_VERSION:?} must parse"
        );
    }
}
