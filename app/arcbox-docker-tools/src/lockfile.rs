//! Parser for the `[[tools]]` section of `assets.lock`.
//!
//! These tool entries pin both the **host-side CLI** binaries (installed to
//! `~/.arcbox/runtime/bin/`) and the **guest-side daemon** binaries (exposed
//! via VirtioFS to the VM). A single lockfile ensures the Docker CLI and guest
//! dockerd are always at the same version — no version-skew concerns on upgrade.

use std::collections::HashMap;

use serde::Deserialize;

/// Top-level lockfile structure (only the parts we care about).
#[derive(Debug, Deserialize)]
pub struct AssetsLock {
    #[serde(default)]
    pub tools: Vec<ToolEntry>,
}

/// Tool installation group.
///
/// New groups must be added here even if this crate does not consume them —
/// `parse_tools()` deserializes the entire `[[tools]]` array before filtering,
/// so an unknown group value would fail parsing for every caller. The
/// `Desktop` variant is consumed by `arcbox-desktop` (host-only binaries
/// embedded in the app bundle) and is inert for docker/kubernetes callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolGroup {
    Docker,
    Kubernetes,
    Desktop,
}

/// Per-architecture metadata for a tool.
#[derive(Debug, Clone, Deserialize)]
pub struct ArchEntry {
    pub sha256: String,
}

/// A single `[[tools]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    pub group: ToolGroup,
    pub version: String,
    #[serde(default)]
    pub arch: HashMap<String, ArchEntry>,
}

impl ToolEntry {
    /// Returns the SHA-256 checksum for the given architecture, if present.
    #[must_use]
    pub fn sha256_for_arch(&self, arch: &str) -> Option<&str> {
        // Accept common aliases.
        let key = match arch {
            "aarch64" => "arm64",
            "amd64" => "x86_64",
            _ => arch,
        };
        self.arch.get(key).map(|e| e.sha256.as_str())
    }
}

/// Parse the `[[tools]]` entries from `assets.lock` TOML content.
pub fn parse_tools(lock_toml: &str) -> Result<Vec<ToolEntry>, toml::de::Error> {
    let lock: AssetsLock = toml::from_str(lock_toml)?;
    Ok(lock.tools)
}

/// Parse the `[[tools]]` entries for a specific tool group.
pub fn parse_tools_for_group(
    lock_toml: &str,
    group: ToolGroup,
) -> Result<Vec<ToolEntry>, toml::de::Error> {
    Ok(parse_tools(lock_toml)?
        .into_iter()
        .filter(|tool| tool.group == group)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[boot]
version = "0.5.1"
cdn = "https://boot.arcboxcdn.com"

[[tools]]
name = "docker"
group = "docker"
version = "29.3.1"
arch.arm64.sha256 = "aaa"
arch.x86_64.sha256 = "bbb"

[[tools]]
name = "docker-buildx"
group = "docker"
version = "0.21.1"
arch.arm64.sha256 = "ccc"

[[tools]]
name = "kubectl"
group = "kubernetes"
version = "1.35.3"
arch.arm64.sha256 = "ddd"

[[tools]]
name = "pstramp"
group = "desktop"
version = "0.2.0"
arch.arm64.sha256 = "eee"
"#;

    #[test]
    fn parse_tool_entries() {
        let tools = parse_tools(SAMPLE).unwrap();
        assert_eq!(tools.len(), 4);
        assert_eq!(tools[0].name, "docker");
        assert_eq!(tools[0].group, ToolGroup::Docker);
        assert_eq!(tools[0].version, "29.3.1");
        assert_eq!(tools[0].sha256_for_arch("arm64"), Some("aaa"));
        assert_eq!(tools[0].sha256_for_arch("x86_64"), Some("bbb"));
        assert_eq!(tools[1].sha256_for_arch("x86_64"), None);
    }

    #[test]
    fn parse_tools_for_specific_group() {
        let docker_tools = parse_tools_for_group(SAMPLE, ToolGroup::Docker).unwrap();
        assert_eq!(docker_tools.len(), 2);
        assert!(
            docker_tools
                .iter()
                .all(|tool| tool.group == ToolGroup::Docker)
        );

        let kubernetes_tools = parse_tools_for_group(SAMPLE, ToolGroup::Kubernetes).unwrap();
        assert_eq!(kubernetes_tools.len(), 1);
        assert_eq!(kubernetes_tools[0].name, "kubectl");

        // Desktop group should parse cleanly even though this crate does not
        // consume it — docker/kubernetes flows must coexist with desktop tools.
        let desktop_tools = parse_tools_for_group(SAMPLE, ToolGroup::Desktop).unwrap();
        assert_eq!(desktop_tools.len(), 1);
        assert_eq!(desktop_tools[0].name, "pstramp");
    }

    #[test]
    fn arch_aliases() {
        let tools = parse_tools(SAMPLE).unwrap();
        // "aarch64" should resolve to "arm64"
        assert_eq!(tools[0].sha256_for_arch("aarch64"), Some("aaa"));
        // "amd64" should resolve to "x86_64"
        assert_eq!(tools[0].sha256_for_arch("amd64"), Some("bbb"));
    }
}
