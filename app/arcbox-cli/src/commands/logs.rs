//! `abctl logs` — view daemon and component log files.

use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

/// Arguments for the logs command.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Component to show logs for.
    #[arg(long, short = 'c', default_value = "daemon")]
    pub component: LogComponent,

    /// Follow log output (like tail -f).
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Number of lines to show from end of file.
    #[arg(long, short = 'n', default_value = "100")]
    pub lines: usize,

    /// Data directory for ArcBox.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

/// Log components.
#[derive(Debug, Clone, ValueEnum)]
pub enum LogComponent {
    /// Daemon log (JSON).
    Daemon,
    /// Privileged helper log (JSON, requires root).
    Helper,
    /// Guest agent log (plain text, via VirtioFS).
    Agent,
    /// Guest dockerd log (plain text, via VirtioFS).
    Dockerd,
    /// Guest containerd log (plain text, via VirtioFS).
    Containerd,
}

/// Execute the logs command.
pub async fn execute(args: LogsArgs) -> Result<()> {
    let log_path = resolve_log_path(&args);

    if !log_path.exists() {
        bail!(
            "Log file not found: {}\nIs the {} running?",
            log_path.display(),
            args.component.label()
        );
    }

    if args.follow {
        tail_follow(&log_path, args.lines).await
    } else {
        tail_lines(&log_path, args.lines)
    }
}

impl LogComponent {
    fn label(&self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Helper => "helper",
            Self::Agent => "agent",
            Self::Dockerd => "dockerd",
            Self::Containerd => "containerd",
        }
    }
}

fn resolve_log_path(args: &LogsArgs) -> PathBuf {
    match args.component {
        LogComponent::Helper => {
            PathBuf::from(arcbox_constants::paths::privileged_log::HELPER_LOG_DIR)
                .join(arcbox_constants::paths::privileged_log::HELPER_LOG)
        }
        _ => {
            let data_dir = resolve_data_dir(args.data_dir.as_ref());
            let log_dir = data_dir.join(arcbox_constants::paths::host::LOG);
            let file_name = match args.component {
                LogComponent::Daemon => arcbox_constants::paths::host::DAEMON_LOG,
                LogComponent::Agent => arcbox_constants::paths::host::AGENT_LOG,
                LogComponent::Dockerd => "dockerd.log",
                LogComponent::Containerd => "containerd.log",
                LogComponent::Helper => unreachable!(),
            };
            log_dir.join(file_name)
        }
    }
}

/// Print the last `n` lines of a file by scanning backwards from the end.
///
/// Reads at most 64 KB chunks from the tail to avoid loading the entire file.
fn tail_lines(path: &Path, n: usize) -> Result<()> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let file_len = file.metadata()?.len();

    if file_len == 0 || n == 0 {
        return Ok(());
    }

    // Scan backwards in 64 KB chunks to find the last `n` newlines.
    const CHUNK: u64 = 64 * 1024;
    let mut newlines_found = 0usize;
    let mut scan_pos = file_len;
    let mut start_offset = 0u64;

    'outer: while scan_pos > 0 {
        let read_size = scan_pos.min(CHUNK);
        scan_pos -= read_size;
        file.seek(SeekFrom::Start(scan_pos))?;
        let mut buf = vec![0u8; read_size as usize];
        file.read_exact(&mut buf)?;

        for (idx, &b) in buf.iter().enumerate().rev() {
            if b == b'\n' {
                newlines_found += 1;
                // n+1 because the last byte of a file is often '\n' itself.
                if newlines_found > n {
                    start_offset = scan_pos + idx as u64 + 1;
                    break 'outer;
                }
            }
        }
    }

    // Seek to the computed start and print everything after it.
    file.seek(SeekFrom::Start(start_offset))?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        println!("{}", line?);
    }
    Ok(())
}

/// Print the last `n` lines then follow new output.
///
/// Detects log rotation (file replaced via rename) by checking whether the
/// inode or file size changes, and reopens the path when it does.
async fn tail_follow(path: &Path, n: usize) -> Result<()> {
    tail_lines(path, n)?;

    let mut file =
        std::fs::File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let mut last_inode = file_inode(&file);
    file.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // No new data. Check if the file was rotated (inode changed).
                if let Ok(new_file) = std::fs::File::open(path) {
                    let new_inode = file_inode(&new_file);
                    if new_inode != last_inode {
                        // File was rotated — switch to the new file.
                        last_inode = new_inode;
                        reader = BufReader::new(new_file);
                        continue;
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Ok(_) => {
                print!("{line}");
            }
            Err(e) => {
                bail!("Error reading log file: {e}");
            }
        }
    }
}

/// Get the inode number for rotation detection.
#[cfg(unix)]
fn file_inode(file: &std::fs::File) -> u64 {
    use std::os::unix::fs::MetadataExt;
    file.metadata().map_or(0, |m| m.ino())
}

#[cfg(not(unix))]
fn file_inode(_file: &std::fs::File) -> u64 {
    0
}

fn resolve_data_dir(data_dir: Option<&PathBuf>) -> PathBuf {
    arcbox_constants::paths::HostLayout::resolve(data_dir.map(PathBuf::as_path)).data_dir
}
