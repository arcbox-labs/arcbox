//! Docker context JSON data structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Docker context metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContextMeta {
    /// Context name.
    pub name: String,
    /// Context metadata.
    pub metadata: ContextMetadata,
    /// Endpoints configuration.
    pub endpoints: ContextEndpoints,
}

/// Context metadata fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContextMetadata {
    /// Context description.
    pub description: String,
}

/// Context endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEndpoints {
    /// Docker endpoint.
    pub docker: DockerEndpoint,
}

/// Docker endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DockerEndpoint {
    /// Host URL (e.g., `unix:///path/to/socket`).
    pub host: String,
    /// Skip TLS verification.
    #[serde(default, rename = "SkipTLSVerify")]
    pub skip_tls_verify: bool,
}

/// Docker config.json structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DockerConfig {
    /// Current context name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_context: Option<String>,
    /// Other fields preserved as-is.
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// Status of `ArcBox` Docker integration.
#[derive(Debug, Clone)]
pub struct ContextStatus {
    /// Whether the `ArcBox` context exists.
    pub context_exists: bool,
    /// Whether `ArcBox` is the default context.
    pub is_default: bool,
    /// Path to the `ArcBox` socket.
    pub socket_path: PathBuf,
    /// Whether the socket file exists.
    pub socket_exists: bool,
}

impl std::fmt::Display for ContextStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ArcBox Docker Integration Status:")?;
        writeln!(
            f,
            "  Context exists: {}",
            if self.context_exists { "yes" } else { "no" }
        )?;
        writeln!(
            f,
            "  Is default:     {}",
            if self.is_default { "yes" } else { "no" }
        )?;
        writeln!(f, "  Socket path:    {}", self.socket_path.display())?;
        write!(
            f,
            "  Socket exists:  {}",
            if self.socket_exists { "yes" } else { "no" }
        )
    }
}
