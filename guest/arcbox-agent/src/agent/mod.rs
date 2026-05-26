//! Agent main loop and request handling.
//!
//! The Agent listens on vsock port 1024 and handles RPC requests from the host.
//! It manages container lifecycle and executes commands in the guest VM.
//!
//! The actual implementation lives in [`linux`] (compiled on Linux guests) or
//! [`stub`] (a no-op kept buildable on non-Linux hosts for development).

use anyhow::Result;

pub mod ensure_runtime;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(not(target_os = "linux"))]
mod stub;

#[cfg(target_os = "linux")]
pub use linux::Agent;

#[cfg(not(target_os = "linux"))]
pub use stub::Agent;

/// Runs the agent.
pub async fn run() -> Result<()> {
    let agent = Agent::new();
    agent.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to parse Docker JSON log line for testing.
    fn parse_docker_log_line(line: &str, stdout: bool, stderr: bool) -> Option<String> {
        let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
        let stream = parsed.get("stream")?.as_str()?;
        let log = parsed.get("log")?.as_str()?;

        match stream {
            "stdout" if stdout => Some(log.to_string()),
            "stderr" if stderr => Some(log.to_string()),
            _ => None,
        }
    }

    #[test]
    fn test_parse_docker_log_stdout() {
        let line = r#"{"log":"hello world","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, Some("hello world".to_string()));

        // Should filter out when stdout=false
        let result = parse_docker_log_line(line, false, true);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_docker_log_stderr() {
        let line = r#"{"log":"error message","stream":"stderr","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, false, true);
        assert_eq!(result, Some("error message".to_string()));

        // Should filter out when stderr=false
        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_docker_log_both_streams() {
        let stdout_line = r#"{"log":"stdout msg","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;
        let stderr_line = r#"{"log":"stderr msg","stream":"stderr","time":"2024-01-08T12:00:00Z"}"#;

        // Both enabled
        assert_eq!(
            parse_docker_log_line(stdout_line, true, true),
            Some("stdout msg".to_string())
        );
        assert_eq!(
            parse_docker_log_line(stderr_line, true, true),
            Some("stderr msg".to_string())
        );
    }

    #[test]
    fn test_parse_docker_log_invalid_json() {
        let invalid = "not json";
        assert_eq!(parse_docker_log_line(invalid, true, true), None);

        let incomplete = r#"{"log":"test"}"#; // Missing stream field
        assert_eq!(parse_docker_log_line(incomplete, true, true), None);
    }

    #[test]
    fn test_parse_docker_log_special_characters() {
        // Test with escaped characters
        let line = r#"{"log":"line with \"quotes\" and \\backslash","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(
            result,
            Some(r#"line with "quotes" and \backslash"#.to_string())
        );
    }

    #[test]
    fn test_parse_docker_log_empty_content() {
        let line = r#"{"log":"","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, Some(String::new()));
    }

    #[test]
    fn test_parse_docker_log_multiline_content() {
        // Docker typically escapes newlines in log content
        let line = r#"{"log":"line1\\nline2","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert!(result.is_some());
        // The escaped newline should be preserved
        assert!(result.unwrap().contains("\\n"));
    }

    #[test]
    fn test_agent_creation() {
        let _agent = Agent::new();
    }
}
