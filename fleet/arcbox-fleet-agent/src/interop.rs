//! WSL Windows-interop support: the bridge that lets the Linux agent, running
//! inside WSL2, serve `windows` jobs by executing the host's pre-installed
//! Windows runner across the interop boundary.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Translate an absolute Windows path (`C:\actions-runner\run.cmd`) to its
/// WSL mount view (`/mnt/c/actions-runner/run.cmd`) via `wslpath -u`.
///
/// The shape is validated first because `wslpath -u` passes non-Windows
/// input through unchanged instead of failing. Translation is textual for
/// mounted drives — the file itself need not exist — so callers that care
/// check the returned path. Fails cleanly outside WSL (no `wslpath`) or for
/// an unmounted drive letter.
pub fn windows_path_to_unix(windows_path: &str) -> Result<PathBuf> {
    let mut chars = windows_path.chars();
    let drive_prefixed = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.next() == Some(':')
        && chars.next() == Some('\\');
    if !drive_prefixed {
        bail!("{windows_path} is not an absolute Windows path (expected e.g. C:\\...)");
    }

    let output = Command::new("wslpath")
        .arg("-u")
        .arg(windows_path)
        .output()
        .context("running wslpath (is this a WSL distro?)")?;
    if !output.status.success() {
        bail!(
            "wslpath -u {windows_path} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let translated = String::from_utf8(output.stdout).context("wslpath emitted non-UTF-8")?;
    Ok(PathBuf::from(translated.trim_end_matches('\n')))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape validation happens before `wslpath` is ever invoked, so these
    /// pass on any host, WSL or not.
    #[test]
    fn rejects_paths_that_are_not_absolute_windows_paths() {
        for bad in [
            "",
            "run.cmd",
            "/mnt/c/actions-runner/run.cmd",
            "actions-runner\\run.cmd",
            "C:/actions-runner/run.cmd",
            ":\\no-drive",
        ] {
            let err = windows_path_to_unix(bad).expect_err(bad);
            assert!(
                err.to_string().contains("not an absolute Windows path"),
                "{bad}: {err}"
            );
        }
    }
}
