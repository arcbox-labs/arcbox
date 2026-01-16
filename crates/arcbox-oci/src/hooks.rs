//! OCI lifecycle hooks.
//!
//! Hooks allow custom actions at various points in the container lifecycle.
//! Reference: <https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks>

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::{OciError, Result};
use crate::state::State;

/// Container lifecycle hooks.
///
/// Hooks are executed at specific points during the container lifecycle:
/// - `create_runtime`: After create operation, before `pivot_root`
/// - `create_container`: After `pivot_root`, before user process starts
/// - `start_container`: Before user process executes
/// - `poststart`: After user process starts
/// - `poststop`: After container process exits
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hooks {
    /// Hooks run after create operation (DEPRECATED).
    #[deprecated(note = "Use createRuntime instead")]
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prestart: Vec<Hook>,

    /// Hooks run during create operation, after environment setup.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub create_runtime: Vec<Hook>,

    /// Hooks run after `pivot_root` but before user process.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub create_container: Vec<Hook>,

    /// Hooks run before user process executes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub start_container: Vec<Hook>,

    /// Hooks run after user process starts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poststart: Vec<Hook>,

    /// Hooks run after container process exits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub poststop: Vec<Hook>,
}

impl Hooks {
    /// Create empty hooks configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if any hooks are configured.
    #[allow(deprecated)]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prestart.is_empty()
            && self.create_runtime.is_empty()
            && self.create_container.is_empty()
            && self.start_container.is_empty()
            && self.poststart.is_empty()
            && self.poststop.is_empty()
    }

    /// Validate all hooks.
    pub fn validate(&self) -> Result<()> {
        #[allow(deprecated)]
        for hook in &self.prestart {
            hook.validate()?;
        }
        for hook in &self.create_runtime {
            hook.validate()?;
        }
        for hook in &self.create_container {
            hook.validate()?;
        }
        for hook in &self.start_container {
            hook.validate()?;
        }
        for hook in &self.poststart {
            hook.validate()?;
        }
        for hook in &self.poststop {
            hook.validate()?;
        }
        Ok(())
    }
}

/// A single hook entry.
///
/// Hooks receive the container state JSON on stdin when executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hook {
    /// Absolute path to the hook executable.
    /// REQUIRED field.
    pub path: PathBuf,

    /// Arguments passed to the hook (including argv[0]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Environment variables for the hook.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,

    /// Timeout in seconds (0 or None means no timeout).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

impl Hook {
    /// Create a new hook with the given path.
    #[must_use]
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            args: Vec::new(),
            env: Vec::new(),
            timeout: None,
        }
    }

    /// Set hook arguments.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set hook environment.
    #[must_use]
    pub fn with_env(mut self, env: Vec<String>) -> Self {
        self.env = env;
        self
    }

    /// Set hook timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: u32) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Validate the hook configuration.
    pub fn validate(&self) -> Result<()> {
        // Path must be absolute.
        if !self.path.is_absolute() {
            return Err(OciError::InvalidConfig(format!(
                "hook path must be absolute: {}",
                self.path.display()
            )));
        }

        // Timeout must be positive if set.
        if let Some(timeout) = self.timeout {
            if timeout == 0 {
                return Err(OciError::InvalidConfig(
                    "hook timeout must be greater than 0".to_string(),
                ));
            }
        }

        Ok(())
    }
}

/// Hook execution context.
///
/// This structure holds the state that will be passed to hooks
/// during execution.
#[derive(Debug, Clone)]
pub struct HookContext {
    /// Container state to pass to hooks.
    pub state: State,
    /// Bundle path.
    pub bundle: PathBuf,
}

impl HookContext {
    /// Create a new hook context.
    #[must_use]
    pub const fn new(state: State, bundle: PathBuf) -> Self {
        Self { state, bundle }
    }

    /// Get the state JSON to pass to hooks via stdin.
    pub fn state_json(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.state)?)
    }
}

/// Hook execution result.
#[derive(Debug, Clone)]
pub struct HookResult {
    /// Exit code of the hook.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl HookResult {
    /// Check if the hook succeeded (exit code 0).
    #[must_use]
    pub const fn success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Hook type for categorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// Pre-start hooks (deprecated).
    Prestart,
    /// Create runtime hooks.
    CreateRuntime,
    /// Create container hooks.
    CreateContainer,
    /// Start container hooks.
    StartContainer,
    /// Post-start hooks.
    Poststart,
    /// Post-stop hooks.
    Poststop,
}

impl HookType {
    /// Get the hook type name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Prestart => "prestart",
            Self::CreateRuntime => "createRuntime",
            Self::CreateContainer => "createContainer",
            Self::StartContainer => "startContainer",
            Self::Poststart => "poststart",
            Self::Poststop => "poststop",
        }
    }
}

impl std::fmt::Display for HookType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hook_validation_absolute_path() {
        let hook = Hook::new("/usr/bin/hook");
        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_validation_relative_path() {
        let hook = Hook::new("relative/path");
        assert!(hook.validate().is_err());
    }

    #[test]
    fn test_hook_validation_zero_timeout() {
        let hook = Hook::new("/usr/bin/hook").with_timeout(0);
        assert!(hook.validate().is_err());
    }

    #[test]
    fn test_hook_builder() {
        let hook = Hook::new("/usr/bin/hook")
            .with_args(vec!["hook".to_string(), "--config".to_string()])
            .with_env(vec!["FOO=bar".to_string()])
            .with_timeout(30);

        assert_eq!(hook.path.to_str().unwrap(), "/usr/bin/hook");
        assert_eq!(hook.args.len(), 2);
        assert_eq!(hook.env.len(), 1);
        assert_eq!(hook.timeout, Some(30));
    }

    #[test]
    fn test_hooks_empty() {
        let hooks = Hooks::new();
        assert!(hooks.is_empty());
    }

    #[test]
    fn test_parse_hooks() {
        let json = r#"{
            "createRuntime": [
                {
                    "path": "/usr/bin/setup-network",
                    "args": ["setup-network", "--type=bridge"],
                    "timeout": 30
                }
            ],
            "poststart": [
                {
                    "path": "/usr/bin/notify",
                    "env": ["NOTIFY_SOCKET=/run/notify.sock"]
                }
            ]
        }"#;

        let hooks: Hooks = serde_json::from_str(json).unwrap();
        assert_eq!(hooks.create_runtime.len(), 1);
        assert_eq!(hooks.poststart.len(), 1);
        assert!(hooks.poststop.is_empty());
    }

    #[test]
    fn test_hooks_not_empty() {
        let mut hooks = Hooks::new();
        assert!(hooks.is_empty());

        hooks.create_runtime.push(Hook::new("/usr/bin/hook"));
        assert!(!hooks.is_empty());
    }

    #[test]
    fn test_hooks_validate_all_valid() {
        let hooks = Hooks {
            create_runtime: vec![Hook::new("/usr/bin/hook1")],
            create_container: vec![Hook::new("/usr/bin/hook2")],
            start_container: vec![Hook::new("/usr/bin/hook3")],
            poststart: vec![Hook::new("/usr/bin/hook4")],
            poststop: vec![Hook::new("/usr/bin/hook5")],
            ..Default::default()
        };

        assert!(hooks.validate().is_ok());
    }

    #[test]
    fn test_hooks_validate_invalid_in_create_runtime() {
        let hooks = Hooks {
            create_runtime: vec![Hook::new("relative/path")],
            ..Default::default()
        };

        assert!(hooks.validate().is_err());
    }

    #[test]
    fn test_hooks_validate_invalid_in_poststart() {
        let hooks = Hooks {
            poststart: vec![Hook::new("relative/path")],
            ..Default::default()
        };

        assert!(hooks.validate().is_err());
    }

    #[test]
    fn test_hooks_validate_invalid_in_poststop() {
        let hooks = Hooks {
            poststop: vec![Hook::new("relative/path")],
            ..Default::default()
        };

        assert!(hooks.validate().is_err());
    }

    #[test]
    fn test_hook_type_as_str() {
        assert_eq!(HookType::Prestart.as_str(), "prestart");
        assert_eq!(HookType::CreateRuntime.as_str(), "createRuntime");
        assert_eq!(HookType::CreateContainer.as_str(), "createContainer");
        assert_eq!(HookType::StartContainer.as_str(), "startContainer");
        assert_eq!(HookType::Poststart.as_str(), "poststart");
        assert_eq!(HookType::Poststop.as_str(), "poststop");
    }

    #[test]
    fn test_hook_type_display() {
        assert_eq!(HookType::Prestart.to_string(), "prestart");
        assert_eq!(HookType::CreateRuntime.to_string(), "createRuntime");
        assert_eq!(HookType::Poststart.to_string(), "poststart");
    }

    #[test]
    fn test_hook_result_success() {
        let success = HookResult {
            exit_code: 0,
            stdout: "output".to_string(),
            stderr: String::new(),
        };
        assert!(success.success());

        let failure = HookResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "error".to_string(),
        };
        assert!(!failure.success());
    }

    #[test]
    fn test_hook_context_new() {
        let state = State::new("test".to_string(), std::path::PathBuf::from("/bundle"));
        let context = HookContext::new(state.clone(), std::path::PathBuf::from("/bundle"));

        assert_eq!(context.state.id, "test");
        assert_eq!(context.bundle, std::path::PathBuf::from("/bundle"));
    }

    #[test]
    fn test_hook_context_state_json() {
        let state = State::new(
            "test-container".to_string(),
            std::path::PathBuf::from("/bundle"),
        );
        let context = HookContext::new(state, std::path::PathBuf::from("/bundle"));

        let json = context.state_json().unwrap();
        assert!(json.contains("test-container"));
        assert!(json.contains("creating"));
    }

    #[test]
    fn test_hook_serialization() {
        let hook = Hook::new("/usr/bin/test")
            .with_args(vec!["test".to_string(), "--flag".to_string()])
            .with_env(vec!["VAR=value".to_string()])
            .with_timeout(60);

        let json = serde_json::to_string(&hook).unwrap();
        assert!(json.contains("/usr/bin/test"));
        assert!(json.contains("--flag"));
        assert!(json.contains("VAR=value"));
        assert!(json.contains("60"));

        // Roundtrip.
        let parsed: Hook = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.path, hook.path);
        assert_eq!(parsed.args, hook.args);
        assert_eq!(parsed.env, hook.env);
        assert_eq!(parsed.timeout, hook.timeout);
    }

    #[test]
    fn test_hooks_serialization_roundtrip() {
        let hooks = Hooks {
            create_runtime: vec![Hook::new("/usr/bin/setup").with_timeout(30)],
            poststart: vec![
                Hook::new("/usr/bin/notify")
                    .with_args(vec!["notify".to_string()])
                    .with_env(vec!["SOCKET=/run/notify.sock".to_string()]),
            ],
            poststop: vec![Hook::new("/usr/bin/cleanup")],
            ..Default::default()
        };

        let json = serde_json::to_string(&hooks).unwrap();
        let parsed: Hooks = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.create_runtime.len(), 1);
        assert_eq!(parsed.poststart.len(), 1);
        assert_eq!(parsed.poststop.len(), 1);
    }

    #[test]
    fn test_parse_all_hook_types() {
        let json = r#"{
            "createRuntime": [{"path": "/bin/cr"}],
            "createContainer": [{"path": "/bin/cc"}],
            "startContainer": [{"path": "/bin/sc"}],
            "poststart": [{"path": "/bin/ps"}],
            "poststop": [{"path": "/bin/pp"}]
        }"#;

        let hooks: Hooks = serde_json::from_str(json).unwrap();
        assert_eq!(hooks.create_runtime.len(), 1);
        assert_eq!(hooks.create_container.len(), 1);
        assert_eq!(hooks.start_container.len(), 1);
        assert_eq!(hooks.poststart.len(), 1);
        assert_eq!(hooks.poststop.len(), 1);
    }

    #[test]
    fn test_hook_with_valid_timeout() {
        let hook = Hook::new("/usr/bin/hook").with_timeout(1);
        assert!(hook.validate().is_ok());

        let hook = Hook::new("/usr/bin/hook").with_timeout(3600);
        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_no_timeout() {
        let hook = Hook::new("/usr/bin/hook");
        assert!(hook.timeout.is_none());
        assert!(hook.validate().is_ok());
    }

    #[test]
    fn test_hook_empty_args_and_env() {
        let hook = Hook::new("/usr/bin/hook");
        assert!(hook.args.is_empty());
        assert!(hook.env.is_empty());
    }

    #[test]
    fn test_hook_type_equality() {
        assert_eq!(HookType::Prestart, HookType::Prestart);
        assert_ne!(HookType::Prestart, HookType::Poststart);
    }

    #[test]
    fn test_hooks_default() {
        let hooks = Hooks::default();
        assert!(hooks.is_empty());
        assert!(hooks.create_runtime.is_empty());
        assert!(hooks.create_container.is_empty());
        assert!(hooks.start_container.is_empty());
        assert!(hooks.poststart.is_empty());
        assert!(hooks.poststop.is_empty());
    }

    #[test]
    fn test_multiple_hooks_per_type() {
        let hooks = Hooks {
            poststart: vec![
                Hook::new("/usr/bin/hook1"),
                Hook::new("/usr/bin/hook2"),
                Hook::new("/usr/bin/hook3"),
            ],
            ..Default::default()
        };

        assert_eq!(hooks.poststart.len(), 3);
        assert!(hooks.validate().is_ok());
    }
}
