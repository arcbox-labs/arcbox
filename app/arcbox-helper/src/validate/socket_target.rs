use std::path::Component;
use std::str::FromStr;

/// A validated socket target path (e.g. `/Users/alice/.arcbox/run/docker.sock`).
///
/// Guarantees:
/// - Under `/Users/<username>/.arcbox/` or `/Users/<username>/.arcbox-dev/`
/// - Ends with `.sock` (strict lowercase)
/// - No `..` path traversal components
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketTarget(String);

impl SocketTarget {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SocketTarget {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = std::path::Path::new(s);

        let rest = s
            .strip_prefix("/Users/")
            .ok_or_else(|| format!("socket target '{s}' must be under /Users/"))?;

        let (username, after_user) = rest
            .split_once('/')
            .ok_or_else(|| format!("socket target '{s}' has no path after username"))?;

        if username.is_empty() {
            return Err(format!("socket target '{s}' has empty username"));
        }

        if !after_user.starts_with(".arcbox/") && !after_user.starts_with(".arcbox-dev/") {
            return Err(format!(
                "socket target '{s}' must be under ~/.arcbox/ or ~/.arcbox-dev/"
            ));
        }

        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        if !s.ends_with(".sock") {
            return Err(format!("socket target '{s}' must end with .sock"));
        }

        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(format!(
                "socket target '{s}' contains '..' path traversal component"
            ));
        }

        Ok(Self(s.to_owned()))
    }
}

impl std::fmt::Display for SocketTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
