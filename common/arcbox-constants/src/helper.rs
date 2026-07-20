//! Privileged helper version helpers shared by daemon, CLI, and (via the same
//! string format) the Desktop app.
//!
//! The helper crate (`arcbox-helper`) owns an **independent** Cargo version
//! (currently `1.0.0`), not `workspace.package.version`. Compare that version
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
pub const MIN_HELPER_VERSION: &str = "1.0.0";

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
/// Accepts optional pre-release / build suffixes by ignoring everything after
/// `-` or `+` on the last numeric component segment that is still pure digits.
/// Returns `None` when fewer than one numeric component is present.
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

/// `true` when `installed >= minimum` by major.minor.patch ordering.
#[must_use]
pub fn helper_version_satisfies(installed: (u64, u64, u64), minimum: (u64, u64, u64)) -> bool {
    installed >= minimum
}

/// Whether the on-disk helper should be replaced by the bundled binary.
///
/// Reinstall when installed is missing or **strictly older** than bundled.
/// Equal or newer (app downgrade) keeps the existing binary so admin prompts
/// are not thrashed.
#[must_use]
pub fn helper_needs_reinstall(
    installed: Option<(u64, u64, u64)>,
    bundled: Option<(u64, u64, u64)>,
) -> bool {
    match (installed, bundled) {
        (_, None) => true,
        (None, Some(_)) => true,
        (Some(have), Some(want)) => have < want,
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

        assert!(helper_needs_reinstall(None, Some((1, 0, 0))));
        assert!(helper_needs_reinstall(Some((0, 4, 12)), Some((1, 0, 0))));
        assert!(!helper_needs_reinstall(Some((1, 0, 0)), Some((1, 0, 0))));
        assert!(!helper_needs_reinstall(Some((1, 1, 0)), Some((1, 0, 0))));
    }
}
