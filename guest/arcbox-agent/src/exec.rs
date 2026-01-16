//! Command execution in guest.

use anyhow::Result;
use std::process::Stdio;
use tokio::process::Command;

/// Execute a command in the guest.
pub async fn exec(
    command: &[String],
    working_dir: Option<&str>,
    env: &[(String, String)],
    stdin: Option<&[u8]>,
) -> Result<ExecResult> {
    if command.is_empty() {
        anyhow::bail!("empty command");
    }

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    for (key, value) in env {
        cmd.env(key, value);
    }

    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let output = cmd.output().await?;

    Ok(ExecResult {
        exit_code: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

/// Result of command execution.
#[derive(Debug)]
pub struct ExecResult {
    /// Exit code.
    pub exit_code: i32,
    /// Standard output.
    pub stdout: Vec<u8>,
    /// Standard error.
    pub stderr: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_exec_simple_command() {
        let result = exec(&["echo".to_string(), "hello".to_string()], None, &[], None)
            .await
            .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "hello");
        assert!(result.stderr.is_empty());
    }

    #[tokio::test]
    async fn test_exec_command_with_multiple_args() {
        let result = exec(
            &[
                "echo".to_string(),
                "one".to_string(),
                "two".to_string(),
                "three".to_string(),
            ],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&result.stdout).trim(),
            "one two three"
        );
    }

    #[tokio::test]
    async fn test_exec_empty_command() {
        let result = exec(&[], None, &[], None).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty command"));
    }

    #[tokio::test]
    async fn test_exec_nonexistent_command() {
        let result = exec(
            &["this_command_does_not_exist_12345".to_string()],
            None,
            &[],
            None,
        )
        .await;

        // Should fail because command doesn't exist
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_exec_with_environment_variable() {
        let result = exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                "echo $TEST_VAR".to_string(),
            ],
            None,
            &[("TEST_VAR".to_string(), "hello_world".to_string())],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&result.stdout).trim(),
            "hello_world"
        );
    }

    #[tokio::test]
    async fn test_exec_with_multiple_env_vars() {
        let result = exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                "echo $VAR1-$VAR2".to_string(),
            ],
            None,
            &[
                ("VAR1".to_string(), "foo".to_string()),
                ("VAR2".to_string(), "bar".to_string()),
            ],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "foo-bar");
    }

    #[tokio::test]
    async fn test_exec_with_working_directory() {
        let result = exec(&["pwd".to_string()], Some("/tmp"), &[], None)
            .await
            .unwrap();

        assert_eq!(result.exit_code, 0);
        // On macOS, /tmp is a symlink to /private/tmp
        let output = String::from_utf8_lossy(&result.stdout);
        let output = output.trim();
        assert!(
            output == "/tmp" || output == "/private/tmp",
            "unexpected pwd output: {}",
            output
        );
    }

    #[tokio::test]
    async fn test_exec_nonzero_exit_code() {
        let result = exec(
            &["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 42);
    }

    #[tokio::test]
    async fn test_exec_stderr_output() {
        let result = exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                "echo error >&2".to_string(),
            ],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&result.stderr).trim(), "error");
    }

    #[tokio::test]
    async fn test_exec_mixed_stdout_stderr() {
        let result = exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                "echo out; echo err >&2".to_string(),
            ],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&result.stderr).trim(), "err");
    }

    #[tokio::test]
    async fn test_exec_binary_output() {
        // Generate some binary data
        let result = exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                "printf '\\x00\\x01\\x02\\x03'".to_string(),
            ],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, vec![0x00, 0x01, 0x02, 0x03]);
    }

    #[tokio::test]
    async fn test_exec_large_output() {
        // Generate a large output (100KB)
        let result = exec(
            &[
                "sh".to_string(),
                "-c".to_string(),
                "dd if=/dev/zero bs=1024 count=100 2>/dev/null | tr '\\0' 'A'".to_string(),
            ],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout.len(), 100 * 1024);
        assert!(result.stdout.iter().all(|&b| b == b'A'));
    }

    #[tokio::test]
    async fn test_exec_special_characters_in_args() {
        let result = exec(
            &[
                "echo".to_string(),
                "hello world".to_string(), // space
                "foo\tbar".to_string(),    // tab
                "a\"b".to_string(),        // quote
            ],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        let output = String::from_utf8_lossy(&result.stdout);
        assert!(output.contains("hello world"));
        assert!(output.contains("foo\tbar"));
        assert!(output.contains("a\"b"));
    }

    #[tokio::test]
    async fn test_exec_unicode_output() {
        let result = exec(
            &["echo".to_string(), "你好世界 🌍".to_string()],
            None,
            &[],
            None,
        )
        .await
        .unwrap();

        assert_eq!(result.exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&result.stdout).trim(),
            "你好世界 🌍"
        );
    }
}
