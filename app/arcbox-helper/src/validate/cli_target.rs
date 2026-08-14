use std::path::Component;
use std::str::FromStr;

use arcbox_constants::paths::is_arcbox_owned;

/// A validated CLI symlink target path inside an app bundle.
///
/// Guarantees match [`is_arcbox_owned`]:
/// - Absolute path under `/Applications/` or `/Users/`
/// - Contains `.app/Contents/MacOS/xbin/` structure
/// - No `..` path traversal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliTarget(String);

impl CliTarget {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CliTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = std::path::Path::new(s);

        // Fast path: shared ownership predicate is the source of truth.
        if is_arcbox_owned(path) {
            return Ok(Self(s.to_owned()));
        }

        // Detailed errors only on the reject path (kept for RPC messages).
        if !path.is_absolute() {
            return Err(format!("CLI target '{s}' must be an absolute path"));
        }
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(format!("CLI target '{s}' contains '..' path traversal"));
        }
        if !s.starts_with("/Applications/") && !s.starts_with("/Users/") {
            return Err(format!(
                "CLI target '{s}' must be under /Applications/ or /Users/"
            ));
        }
        Err(format!(
            "CLI target '{s}' must be inside an .app bundle's Contents/MacOS/xbin/"
        ))
    }
}

impl std::fmt::Display for CliTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
