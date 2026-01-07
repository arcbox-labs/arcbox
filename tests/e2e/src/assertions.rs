//! Test assertions for E2E tests.
//!
//! Provides custom assertion macros and utilities for E2E testing.

/// Asserts that a command succeeded (exit code 0).
#[macro_export]
macro_rules! assert_success {
    ($result:expr) => {
        assert!(
            $result.success(),
            "Expected success but got exit code {}: stdout={}, stderr={}",
            $result.exit_code,
            $result.stdout,
            $result.stderr
        )
    };
    ($result:expr, $msg:expr) => {
        assert!(
            $result.success(),
            "{}: exit_code={}, stdout={}, stderr={}",
            $msg,
            $result.exit_code,
            $result.stdout,
            $result.stderr
        )
    };
}

/// Asserts that a command failed (exit code != 0).
#[macro_export]
macro_rules! assert_failure {
    ($result:expr) => {
        assert!(
            !$result.success(),
            "Expected failure but got success: stdout={}, stderr={}",
            $result.stdout,
            $result.stderr
        )
    };
    ($result:expr, $code:expr) => {
        assert_eq!(
            $result.exit_code, $code,
            "Expected exit code {} but got {}: stdout={}, stderr={}",
            $code,
            $result.exit_code,
            $result.stdout,
            $result.stderr
        )
    };
}

/// Asserts that output contains a substring.
#[macro_export]
macro_rules! assert_output_contains {
    ($result:expr, $substring:expr) => {
        assert!(
            $result.stdout.contains($substring) || $result.stderr.contains($substring),
            "Expected output to contain '{}', got stdout='{}', stderr='{}'",
            $substring,
            $result.stdout,
            $result.stderr
        )
    };
}

/// Asserts that stdout contains a substring.
#[macro_export]
macro_rules! assert_stdout_contains {
    ($result:expr, $substring:expr) => {
        assert!(
            $result.stdout.contains($substring),
            "Expected stdout to contain '{}', got '{}'",
            $substring,
            $result.stdout
        )
    };
}

/// Asserts that stderr contains a substring.
#[macro_export]
macro_rules! assert_stderr_contains {
    ($result:expr, $substring:expr) => {
        assert!(
            $result.stderr.contains($substring),
            "Expected stderr to contain '{}', got '{}'",
            $substring,
            $result.stderr
        )
    };
}

/// Asserts that a condition is met within a timeout.
#[macro_export]
macro_rules! assert_eventually {
    ($condition:expr, $timeout:expr, $interval:expr) => {{
        let deadline = std::time::Instant::now() + $timeout;
        let mut last_err = None;

        while std::time::Instant::now() < deadline {
            match (|| -> Result<bool, _> { Ok($condition) })() {
                Ok(true) => break,
                Ok(false) => {}
                Err(e) => last_err = Some(e),
            }
            std::thread::sleep($interval);
        }

        if std::time::Instant::now() >= deadline {
            if let Some(e) = last_err {
                panic!("Condition not met within {:?}: {:?}", $timeout, e);
            } else {
                panic!("Condition not met within {:?}", $timeout);
            }
        }
    }};
}

/// Retry configuration for flaky assertions.
pub struct RetryConfig {
    /// Maximum number of retries.
    pub max_retries: u32,
    /// Delay between retries.
    pub delay: std::time::Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            delay: std::time::Duration::from_millis(500),
        }
    }
}

/// Executes a closure with retries.
pub fn with_retry<T, E, F>(config: &RetryConfig, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
{
    let mut last_err = None;

    for _ in 0..=config.max_retries {
        match f() {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(config.delay);
            }
        }
    }

    Err(last_err.unwrap())
}
