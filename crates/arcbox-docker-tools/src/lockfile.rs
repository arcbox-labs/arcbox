//! Parser for the `[[tools]]` section of `assets.lock`.

use serde::Deserialize;

/// Top-level lockfile structure (only the parts we care about).
#[derive(Debug, Deserialize)]
pub struct AssetsLock {
    #[serde(default)]
    pub tools: Vec<ToolEntry>,
}

/// A single `[[tools]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub sha256_arm64: Option<String>,
    #[serde(default)]
    pub sha256_x86_64: Option<String>,
}

impl ToolEntry {
    /// Returns the SHA-256 checksum for the given architecture, if present.
    #[must_use]
    pub fn sha256_for_arch(&self, arch: &str) -> Option<&str> {
        match arch {
            "arm64" | "aarch64" => self.sha256_arm64.as_deref(),
            "x86_64" | "amd64" => self.sha256_x86_64.as_deref(),
            _ => None,
        }
    }
}

/// Parse the `[[tools]]` entries from `assets.lock` TOML content.
pub fn parse_tools(lock_toml: &str) -> Result<Vec<ToolEntry>, toml::de::Error> {
    let lock: AssetsLock = toml::from_str(lock_toml)?;
    Ok(lock.tools)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[boot]
version = "0.3.0"
cdn = "https://boot.arcboxcdn.com"

[[tools]]
name = "docker"
version = "27.5.1"
sha256_arm64 = "aaa"
sha256_x86_64 = "bbb"

[[tools]]
name = "docker-buildx"
version = "0.21.1"
sha256_arm64 = "ccc"
"#;

    #[test]
    fn parse_tool_entries() {
        let tools = parse_tools(SAMPLE).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "docker");
        assert_eq!(tools[0].version, "27.5.1");
        assert_eq!(tools[0].sha256_for_arch("arm64"), Some("aaa"));
        assert_eq!(tools[0].sha256_for_arch("x86_64"), Some("bbb"));
        assert_eq!(tools[1].sha256_for_arch("x86_64"), None);
    }
}
