//! Log file watcher for streaming container logs.
//!
//! Uses inotify (Linux) or kqueue (macOS) to watch log files for changes
//! and yields new log lines as they are appended.

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;

use arcbox_protocol::agent::LogEntry;
use arcbox_protocol::Timestamp;

/// Default buffer size for reading log lines.
const READ_BUFFER_SIZE: usize = 8192;

/// Options for log watching.
#[derive(Debug, Clone)]
pub struct LogWatchOptions {
    /// Include stdout stream.
    pub stdout: bool,
    /// Include stderr stream.
    pub stderr: bool,
    /// Include timestamps in output.
    pub timestamps: bool,
    /// Number of lines to tail before streaming (0 = all).
    pub tail: i64,
    /// Filter logs since this Unix timestamp (0 = no filter).
    pub since: i64,
    /// Filter logs until this Unix timestamp (0 = no filter).
    pub until: i64,
}

impl Default for LogWatchOptions {
    fn default() -> Self {
        Self {
            stdout: true,
            stderr: true,
            timestamps: false,
            tail: 0,
            since: 0,
            until: 0,
        }
    }
}

/// Watches a log file and streams new entries.
///
/// This function:
/// 1. Reads existing log content (applying tail filter if specified)
/// 2. Sets up a file watcher for new changes
/// 3. Streams new log entries as they are appended
///
/// The returned receiver will yield LogEntry messages until the sender is dropped.
pub async fn watch_log_file(
    log_path: impl AsRef<Path>,
    options: LogWatchOptions,
    cancel: mpsc::Receiver<()>,
) -> Result<mpsc::Receiver<LogEntry>> {
    let log_path = log_path.as_ref().to_path_buf();
    let (tx, rx) = mpsc::channel::<LogEntry>(64);

    // Spawn the watcher task
    tokio::spawn(async move {
        if let Err(e) = run_watcher(log_path, options, tx, cancel).await {
            tracing::error!("Log watcher error: {}", e);
        }
    });

    Ok(rx)
}

/// Internal watcher implementation.
async fn run_watcher(
    log_path: std::path::PathBuf,
    options: LogWatchOptions,
    tx: mpsc::Sender<LogEntry>,
    mut cancel: mpsc::Receiver<()>,
) -> Result<()> {
    // Open file or wait for it to be created
    let mut file = loop {
        match std::fs::File::open(&log_path) {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Wait a bit and retry, or check for cancellation
                tokio::select! {
                    _ = cancel.recv() => {
                        tracing::debug!("Log watcher cancelled while waiting for file");
                        return Ok(());
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        continue;
                    }
                }
            }
            Err(e) => return Err(e).context("failed to open log file"),
        }
    };

    // Read initial content with tail filter
    let initial_lines = read_with_tail(&mut file, options.tail)?;

    // Send initial lines
    for line in initial_lines {
        let entry = parse_log_line(&line, &options);
        if should_include_entry(&entry, &options) {
            if tx.send(entry).await.is_err() {
                // Receiver dropped
                return Ok(());
            }
        }
    }

    // Get current file position
    let mut pos = file.seek(SeekFrom::End(0))?;

    // Set up file watcher
    let (notify_tx, mut notify_rx) = mpsc::channel::<notify::Result<notify::Event>>(16);

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = notify_tx.blocking_send(res);
        },
        Config::default(),
    )
    .context("failed to create file watcher")?;

    watcher
        .watch(&log_path, RecursiveMode::NonRecursive)
        .context("failed to watch log file")?;

    tracing::debug!("Started watching log file: {:?}", log_path);

    // Watch for changes
    loop {
        tokio::select! {
            _ = cancel.recv() => {
                tracing::debug!("Log watcher cancelled");
                break;
            }
            Some(event) = notify_rx.recv() => {
                match event {
                    Ok(event) => {
                        if event.kind.is_modify() || event.kind.is_create() {
                            // Read new content
                            if let Ok(new_lines) = read_new_content(&mut file, &mut pos) {
                                for line in new_lines {
                                    let entry = parse_log_line(&line, &options);
                                    if should_include_entry(&entry, &options) {
                                        if tx.send(entry).await.is_err() {
                                            // Receiver dropped
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("File watcher error: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Reads the file with tail filter applied.
fn read_with_tail(file: &mut std::fs::File, tail: i64) -> Result<Vec<String>> {
    let reader = BufReader::with_capacity(READ_BUFFER_SIZE, &*file);
    let all_lines: Vec<String> = reader.lines().collect::<std::io::Result<Vec<_>>>()?;

    if tail <= 0 || tail as usize >= all_lines.len() {
        Ok(all_lines)
    } else {
        let start = all_lines.len() - tail as usize;
        Ok(all_lines[start..].to_vec())
    }
}

/// Reads new content from the file since the last position.
fn read_new_content(file: &mut std::fs::File, pos: &mut u64) -> Result<Vec<String>> {
    // Seek to last known position
    file.seek(SeekFrom::Start(*pos))?;

    let mut reader = BufReader::new(&*file);
    let mut lines = Vec::new();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Remove trailing newline
                let trimmed = line.trim_end_matches(&['\n', '\r'][..]).to_string();
                if !trimmed.is_empty() {
                    lines.push(trimmed);
                }
            }
            Err(e) => {
                tracing::warn!("Error reading log line: {}", e);
                break;
            }
        }
    }

    // Update position
    *pos = file.seek(SeekFrom::Current(0))?;

    Ok(lines)
}

/// Converts nanoseconds since Unix epoch to a protobuf Timestamp.
fn nanos_to_timestamp(nanos: i64) -> Timestamp {
    Timestamp {
        seconds: nanos / 1_000_000_000,
        nanos: (nanos % 1_000_000_000) as i32,
    }
}

/// Parses a log line into a LogEntry.
///
/// Supports two log formats:
/// 1. Docker JSON format: `{"log":"message\n","stream":"stdout","time":"2024-01-01T00:00:00Z"}`
/// 2. Legacy plain text formats:
///    - Plain text: "message"
///    - With stream prefix: "stdout: message" or "stderr: message"
///    - With timestamp: "2024-01-01T00:00:00Z stdout: message"
fn parse_log_line(line: &str, options: &LogWatchOptions) -> LogEntry {
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);

    // Try to parse Docker JSON format first.
    if line.starts_with('{') {
        if let Some((stream, message, timestamp_nanos)) = parse_docker_json_line(line) {
            // Build output message with optional timestamp.
            let output_message = if options.timestamps {
                let ts = chrono::DateTime::from_timestamp_nanos(timestamp_nanos);
                format!(
                    "{} {}",
                    ts.format("%Y-%m-%dT%H:%M:%S%.9fZ"),
                    String::from_utf8_lossy(&message)
                )
            } else {
                String::from_utf8_lossy(&message).to_string()
            };

            return LogEntry {
                stream,
                message: output_message.into_bytes(),
                timestamp: Some(nanos_to_timestamp(timestamp_nanos)),
            };
        }
    }

    // Fallback to legacy structured log format.
    // Format: [timestamp] [stream]: message
    let (timestamp, stream, data) = parse_structured_line(line);

    let final_timestamp_nanos = timestamp.unwrap_or(now);
    let final_stream = stream.unwrap_or_else(|| "stdout".to_string());

    // Build output message.
    let output_message = if options.timestamps {
        let ts = chrono::DateTime::from_timestamp_nanos(final_timestamp_nanos);
        format!("{} {}", ts.format("%Y-%m-%dT%H:%M:%S%.9fZ"), data)
    } else {
        data
    };

    LogEntry {
        stream: final_stream,
        message: output_message.into_bytes(),
        timestamp: Some(nanos_to_timestamp(final_timestamp_nanos)),
    }
}

/// Parses a Docker JSON format log line.
///
/// Format: `{"log":"message\n","stream":"stdout","time":"2024-01-01T00:00:00.123456789Z"}`
///
/// Returns (stream, message, timestamp_nanos) tuple.
fn parse_docker_json_line(line: &str) -> Option<(String, Vec<u8>, i64)> {
    // Manual parsing to avoid serde dependency overhead.
    // Extract "log" field.
    let log_start = line.find(r#""log":""#)? + 7;
    let log_end = find_json_string_end(line, log_start)?;
    let log_content = unescape_json_string(&line[log_start..log_end]);

    // Extract "stream" field.
    let stream_start = line.find(r#""stream":""#)? + 10;
    let stream_end = find_json_string_end(line, stream_start)?;
    let stream = line[stream_start..stream_end].to_string();

    // Extract "time" field and parse timestamp.
    let time_start = line.find(r#""time":""#)? + 8;
    let time_end = find_json_string_end(line, time_start)?;
    let time_str = &line[time_start..time_end];
    let timestamp_nanos = chrono::DateTime::parse_from_rfc3339(time_str)
        .ok()?
        .timestamp_nanos_opt()
        .unwrap_or(0);

    Some((stream, log_content.into_bytes(), timestamp_nanos))
}

/// Finds the end of a JSON string value (position of closing quote).
fn find_json_string_end(s: &str, start: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Some(i),
            b'\\' => i += 2, // Skip escaped character.
            _ => i += 1,
        }
    }
    None
}

/// Unescapes a JSON string value.
fn unescape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some('"') => result.push('"'),
                Some('\\') => result.push('\\'),
                Some('/') => result.push('/'),
                Some('u') => {
                    // Parse \uXXXX unicode escape.
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(code) {
                            result.push(ch);
                        }
                    }
                }
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Parses a structured log line.
///
/// Returns (timestamp, stream, message).
fn parse_structured_line(line: &str) -> (Option<i64>, Option<String>, String) {
    // Try to parse timestamp prefix
    if let Some((ts_str, rest)) = line.split_once(' ') {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts_str) {
            let timestamp = dt.timestamp_nanos_opt();

            // Check for stream prefix in rest
            if let Some((stream, msg)) = rest.split_once(": ") {
                if stream == "stdout" || stream == "stderr" {
                    return (timestamp, Some(stream.to_string()), msg.to_string());
                }
            }
            return (timestamp, None, rest.to_string());
        }
    }

    // Check for stream prefix without timestamp
    if let Some((stream, msg)) = line.split_once(": ") {
        if stream == "stdout" || stream == "stderr" {
            return (None, Some(stream.to_string()), msg.to_string());
        }
    }

    // Plain text
    (None, None, line.to_string())
}

/// Checks if an entry should be included based on options.
fn should_include_entry(entry: &LogEntry, options: &LogWatchOptions) -> bool {
    // Stream filter
    if entry.stream == "stdout" && !options.stdout {
        return false;
    }
    if entry.stream == "stderr" && !options.stderr {
        return false;
    }

    // Time filters - extract seconds from Timestamp if present.
    if let Some(ref ts) = entry.timestamp {
        if options.since > 0 && ts.seconds < options.since {
            return false;
        }
        if options.until > 0 && ts.seconds > options.until {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plain_line() {
        let options = LogWatchOptions::default();
        let entry = parse_log_line("hello world", &options);

        assert_eq!(entry.stream, "stdout");
        assert_eq!(String::from_utf8_lossy(&entry.message), "hello world");
    }

    #[test]
    fn test_parse_line_with_stream_prefix() {
        let options = LogWatchOptions::default();

        let entry = parse_log_line("stderr: error message", &options);
        assert_eq!(entry.stream, "stderr");
        assert_eq!(String::from_utf8_lossy(&entry.message), "error message");

        let entry = parse_log_line("stdout: info message", &options);
        assert_eq!(entry.stream, "stdout");
        assert_eq!(String::from_utf8_lossy(&entry.message), "info message");
    }

    #[test]
    fn test_parse_line_with_timestamp() {
        let options = LogWatchOptions::default();
        let entry = parse_log_line("2024-01-15T10:30:00Z stdout: test message", &options);

        assert_eq!(entry.stream, "stdout");
        assert_eq!(String::from_utf8_lossy(&entry.message), "test message");
        // Timestamp should be parsed.
        assert!(entry.timestamp.is_some());
        assert!(entry.timestamp.unwrap().seconds > 0);
    }

    #[test]
    fn test_should_include_entry_stdout_only() {
        let options = LogWatchOptions {
            stdout: true,
            stderr: false,
            ..Default::default()
        };

        let stdout_entry = LogEntry {
            stream: "stdout".to_string(),
            message: vec![],
            timestamp: Some(Timestamp { seconds: 0, nanos: 0 }),
        };
        let stderr_entry = LogEntry {
            stream: "stderr".to_string(),
            message: vec![],
            timestamp: Some(Timestamp { seconds: 0, nanos: 0 }),
        };

        assert!(should_include_entry(&stdout_entry, &options));
        assert!(!should_include_entry(&stderr_entry, &options));
    }

    #[test]
    fn test_should_include_entry_time_filter() {
        let options = LogWatchOptions {
            since: 1000,
            until: 2000,
            ..Default::default()
        };

        let before = LogEntry {
            stream: "stdout".to_string(),
            message: vec![],
            timestamp: Some(Timestamp { seconds: 500, nanos: 0 }),
        };
        let during = LogEntry {
            stream: "stdout".to_string(),
            message: vec![],
            timestamp: Some(Timestamp { seconds: 1500, nanos: 0 }),
        };
        let after = LogEntry {
            stream: "stdout".to_string(),
            message: vec![],
            timestamp: Some(Timestamp { seconds: 2500, nanos: 0 }),
        };

        assert!(!should_include_entry(&before, &options));
        assert!(should_include_entry(&during, &options));
        assert!(!should_include_entry(&after, &options));
    }

    #[test]
    fn test_parse_structured_line() {
        // Plain text
        let (ts, stream, msg) = parse_structured_line("hello world");
        assert!(ts.is_none());
        assert!(stream.is_none());
        assert_eq!(msg, "hello world");

        // With stream prefix
        let (ts, stream, msg) = parse_structured_line("stderr: error");
        assert!(ts.is_none());
        assert_eq!(stream, Some("stderr".to_string()));
        assert_eq!(msg, "error");

        // With timestamp and stream
        let (ts, stream, msg) = parse_structured_line("2024-01-15T10:30:00+00:00 stdout: message");
        assert!(ts.is_some());
        assert_eq!(stream, Some("stdout".to_string()));
        assert_eq!(msg, "message");
    }

    #[test]
    fn test_parse_docker_json_line() {
        // Standard Docker JSON format.
        let line =
            r#"{"log":"hello world\n","stream":"stdout","time":"2024-01-15T10:30:00.123456789Z"}"#;
        let (stream, message, timestamp_nanos) = parse_docker_json_line(line).unwrap();

        assert_eq!(stream, "stdout");
        assert_eq!(String::from_utf8_lossy(&message), "hello world\n");
        assert!(timestamp_nanos > 0);
    }

    #[test]
    fn test_parse_docker_json_line_stderr() {
        let line = r#"{"log":"error message\n","stream":"stderr","time":"2024-01-15T10:30:00Z"}"#;
        let (stream, message, _) = parse_docker_json_line(line).unwrap();

        assert_eq!(stream, "stderr");
        assert_eq!(String::from_utf8_lossy(&message), "error message\n");
    }

    #[test]
    fn test_parse_docker_json_line_with_escapes() {
        // Test JSON escape sequences.
        let line = r#"{"log":"line with \"quotes\" and \\backslash\n","stream":"stdout","time":"2024-01-15T10:30:00Z"}"#;
        let (_, message, _) = parse_docker_json_line(line).unwrap();

        assert_eq!(
            String::from_utf8_lossy(&message),
            "line with \"quotes\" and \\backslash\n"
        );
    }

    #[test]
    fn test_parse_log_line_docker_format() {
        let options = LogWatchOptions::default();
        let line = r#"{"log":"test message\n","stream":"stdout","time":"2024-01-15T10:30:00Z"}"#;
        let entry = parse_log_line(line, &options);

        assert_eq!(entry.stream, "stdout");
        assert_eq!(String::from_utf8_lossy(&entry.message), "test message\n");
    }

    #[test]
    fn test_unescape_json_string() {
        assert_eq!(unescape_json_string("hello"), "hello");
        assert_eq!(unescape_json_string("hello\\n"), "hello\n");
        assert_eq!(unescape_json_string("\\\"quoted\\\""), "\"quoted\"");
        assert_eq!(unescape_json_string("back\\\\slash"), "back\\slash");
        assert_eq!(unescape_json_string("tab\\there"), "tab\there");
    }

    #[test]
    fn test_find_json_string_end() {
        assert_eq!(find_json_string_end(r#"hello""#, 0), Some(5));
        assert_eq!(find_json_string_end(r#"he\"llo""#, 0), Some(7));
        assert_eq!(find_json_string_end(r#"no closing quote"#, 0), None);
    }
}
