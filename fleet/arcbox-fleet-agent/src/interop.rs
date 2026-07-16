//! WSL Windows-interop support: the bridge that lets the Linux agent, running
//! inside WSL2, serve `windows` jobs by executing the host's pre-installed
//! Windows runner across the interop boundary.
//!
//! Interop process management is asymmetric, which shapes the whole design
//! (verified empirically on WSL2):
//!
//! - Spawning works like any exec: the Linux-side process is a **relay**
//!   that pipes stdio and mirrors the Windows process's exit code.
//! - Killing does not: SIGKILL on the relay **orphans** the Windows process,
//!   so the Unix process-group teardown the host-runner path uses cannot
//!   cancel a windows job.
//!
//! [`InteropRunner::spawn`] therefore launches the runner through a
//! PowerShell wrapper that prints the Windows PID (`WINPID=<n>`) before
//! waiting on the process, and [`InteropJob::kill`] cancels by asking
//! Windows itself — `taskkill /T /F /PID` across the same interop boundary —
//! which tears down the whole Windows tree and unblocks the relay's wait.
//!
//! Known limitations, accepted by design: admission telemetry measures the
//! WSL utility VM (not the Windows host the jobs actually burn), and the
//! composed `cmd.exe` command line is capped at ~8k chars (cmd's limit), so
//! oversized JIT configs are rejected up front with a clear reason.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, warn};

/// Fixed Windows locations of the interop tools, translated through
/// `wslpath` at startup so a non-default automount root still resolves.
/// Windows PowerShell 5.1 ships with every Windows 10/11 install (unlike
/// `pwsh`), and both paths are identical on x64 and ARM64.
const POWERSHELL_WINDOWS_PATH: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const TASKKILL_WINDOWS_PATH: &str = r"C:\Windows\System32\taskkill.exe";

/// Budget for the startup probe (`powershell -Command "exit 0"`): the first
/// interop spawn after a WSL boot can take a few seconds, a hung one means
/// interop is unusable.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Budget for the `WINPID=` handshake after spawn. Generous: the wrapper
/// prints it right after `Start-Process` returns, well before the runner
/// does any work.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Ceiling for the composed `cmd.exe` command line. cmd refuses lines over
/// 8191 chars; staying under with margin turns a too-large JIT config into
/// a clean upfront rejection instead of a cryptic mid-spawn failure.
const CMD_LINE_BUDGET: usize = 8000;

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

/// Runs windows jobs on the WSL host via interop. Constructed once at
/// startup; the runner script is frozen at construction — restart-scoped,
/// like the host path's `runner_script`.
#[derive(Clone)]
pub struct InteropRunner {
    /// WSL-mount view of Windows PowerShell 5.1, the wrapper interpreter.
    powershell: PathBuf,
    /// WSL-mount view of `taskkill.exe`, the cancellation mechanism.
    taskkill: PathBuf,
    /// Windows-style path to the runner entry point (`run.cmd`).
    script: String,
}

impl InteropRunner {
    /// Resolve the interop tools and prove interop actually executes:
    /// translate the fixed tool paths and `script` through `wslpath`
    /// (fails cleanly outside WSL), require all three to exist under the
    /// mount view, then run a trivial PowerShell command end-to-end —
    /// translation alone cannot detect interop disabled via `wsl.conf`.
    pub async fn new(script: &str) -> Result<Self> {
        let powershell = windows_path_to_unix(POWERSHELL_WINDOWS_PATH)?;
        let taskkill = windows_path_to_unix(TASKKILL_WINDOWS_PATH)?;
        for (name, path) in [("powershell", &powershell), ("taskkill", &taskkill)] {
            ensure!(
                path.is_file(),
                "{name} not found at {} — is the Windows drive mounted?",
                path.display()
            );
        }
        let script_unix = windows_path_to_unix(script)?;
        ensure!(
            script_unix.is_file(),
            "windows runner script {script} not found (checked {})",
            script_unix.display()
        );

        let probe = tokio::process::Command::new(&powershell)
            .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status();
        let status = tokio::time::timeout(PROBE_TIMEOUT, probe)
            .await
            .context("interop probe timed out — is interop enabled in wsl.conf?")?
            .context("spawning the interop probe")?;
        ensure!(status.success(), "interop probe exited with {status}");

        Ok(Self {
            powershell,
            taskkill,
            script: script.to_owned(),
        })
    }

    /// Test constructor bypassing `wslpath` and the probe, so the spawn/
    /// wait/kill contract is exercisable anywhere with stub executables
    /// standing in for powershell and taskkill. Crate-visible for the
    /// runner's routing tests.
    #[cfg(test)]
    pub(crate) fn with_paths(powershell: PathBuf, taskkill: PathBuf, script: &str) -> Self {
        Self {
            powershell,
            taskkill,
            script: script.to_owned(),
        }
    }

    /// Start the Windows runner for one job and complete the `WINPID=`
    /// handshake, so the returned job is provably running on the Windows
    /// side and carries the PID that can cancel it. Any failure past the
    /// spawn reaps the relay before returning, so an error never leaks a
    /// process.
    pub async fn spawn(&self, encoded_jit_config: &str) -> Result<InteropJob> {
        validate_jit_config(&self.script, encoded_jit_config)?;

        let mut child = tokio::process::Command::new(&self.powershell)
            .args(["-NoProfile", "-NonInteractive", "-Command"])
            .arg(wrapper_command(&self.script, encoded_jit_config))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("spawning the interop wrapper")?;

        let stdout = child
            .stdout
            .take()
            .context("interop wrapper spawned without a stdout pipe")?;
        let mut lines = BufReader::new(stdout).lines();
        let handshake = async {
            while let Some(line) = lines.next_line().await? {
                if let Some(pid) = line.strip_prefix("WINPID=") {
                    return pid
                        .trim()
                        .parse::<u32>()
                        .with_context(|| format!("malformed handshake line {line:?}"));
                }
                debug!(line, "interop wrapper output before handshake");
            }
            bail!("interop wrapper exited without reporting WINPID");
        };
        let windows_pid = match tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake).await {
            Ok(Ok(pid)) => pid,
            Ok(Err(e)) => {
                reap(&mut child).await;
                return Err(e);
            }
            Err(_) => {
                reap(&mut child).await;
                bail!("interop wrapper did not report WINPID within {HANDSHAKE_TIMEOUT:?}");
            }
        };

        // Keep the pipe drained for the rest of the job — the runner's
        // output flows through the wrapper's console — so a chatty runner
        // can never fill the pipe and wedge itself. Ends at EOF when the
        // relay exits; detaching the handle is deliberate.
        tokio::spawn(async move {
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => debug!(line, "windows runner output"),
                    Ok(None) => break,
                    Err(e) => {
                        debug!(error = %e, "windows runner output stream failed");
                        break;
                    }
                }
            }
        });

        Ok(InteropJob {
            windows_pid,
            child,
            taskkill: self.taskkill.clone(),
        })
    }
}

/// Kill and reap the relay after a failed handshake. Losing the Windows
/// process is acceptable here: either it never started (`Start-Process`
/// failed) or the wrapper is defective — there is no PID to taskkill.
async fn reap(child: &mut tokio::process::Child) {
    if let Err(e) = child.kill().await {
        warn!(error = %e, "killing the interop wrapper failed");
    }
}

/// A windows job running on the WSL host: the interop relay (whose exit
/// mirrors the Windows process's) plus the Windows PID that can kill it.
#[derive(Debug)]
pub struct InteropJob {
    windows_pid: u32,
    child: tokio::process::Child,
    taskkill: PathBuf,
}

impl InteropJob {
    /// The Windows-side PID, for logs and diagnostics.
    pub fn windows_pid(&self) -> u32 {
        self.windows_pid
    }

    /// Wait for the runner to exit; the relay mirrors its exit status.
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    /// Cancel: `taskkill /T /F` the Windows tree, then reap the relay
    /// (whose `WaitForExit` returns once the tree is gone). Killing the
    /// relay instead would orphan the Windows process — see the module doc.
    /// Falls back to exactly that (with a warning) if taskkill itself
    /// fails, so the job slot is always released either way.
    pub async fn kill(&mut self) {
        let killed = tokio::process::Command::new(&self.taskkill)
            .args(["/T", "/F", "/PID", &self.windows_pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .status()
            .await;
        match killed {
            Ok(status) if status.success() => {}
            Ok(status) => {
                warn!(
                    windows_pid = self.windows_pid,
                    %status,
                    "taskkill failed; killing the relay (the Windows tree may be orphaned)"
                );
                reap(&mut self.child).await;
            }
            Err(e) => {
                warn!(
                    windows_pid = self.windows_pid,
                    error = %e,
                    "spawning taskkill failed; killing the relay (the Windows tree may be orphaned)"
                );
                reap(&mut self.child).await;
            }
        }
        if let Err(e) = self.child.wait().await {
            warn!(error = %e, "reaping the interop relay failed");
        }
    }
}

/// Compose the PowerShell wrapper: start the runner via `cmd.exe`, report
/// its Windows PID, then block until it exits and mirror its exit code.
/// `-NoNewWindow` keeps the runner's output on the wrapper's console, which
/// the relay pipes back to us.
///
/// Quoting: the script path is embedded in a PowerShell single-quoted
/// string (only `'` is special, doubled) *and* wrapped in `"` for the
/// cmd.exe layer (`"` cannot occur in a Windows path); the JIT config's
/// charset is pre-validated, so it needs no quoting at either layer.
fn wrapper_command(script: &str, encoded_jit_config: &str) -> String {
    let script_ps = script.replace('\'', "''");
    format!(
        "$p = Start-Process -FilePath 'cmd.exe' \
         -ArgumentList '/c','\"{script_ps}\"','--jitconfig','{encoded_jit_config}' \
         -PassThru -NoNewWindow; \
         Write-Output \"WINPID=$($p.Id)\"; \
         $p.WaitForExit(); \
         exit $p.ExitCode"
    )
}

/// Boundary validation before anything is spawned: the JIT config must be
/// base64-shaped (GitHub's encoded JIT config always is), so it can be
/// embedded without quoting hazards, and the composed `cmd.exe` line must
/// fit cmd's length limit.
fn validate_jit_config(script: &str, encoded_jit_config: &str) -> Result<()> {
    ensure!(
        !encoded_jit_config.is_empty(),
        "encoded JIT config is empty"
    );
    ensure!(
        encoded_jit_config
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')),
        "encoded JIT config contains non-base64 characters"
    );
    // `cmd.exe /c "<script>" --jitconfig <blob>` plus slack for quotes.
    let composed = "cmd.exe /c \"\" --jitconfig ".len() + script.len() + encoded_jit_config.len();
    ensure!(
        composed <= CMD_LINE_BUDGET,
        "composed command line ({composed} chars) exceeds cmd.exe's limit — \
         the JIT config is too large to pass through cmd"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

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

    #[test]
    fn wrapper_embeds_script_and_jitconfig_and_doubles_quotes() {
        let cmd = wrapper_command(r"C:\runners\o'brien\run.cmd", "abc123=");
        assert!(cmd.contains(r#"'"C:\runners\o''brien\run.cmd"'"#), "{cmd}");
        assert!(cmd.contains("'--jitconfig','abc123='"), "{cmd}");
        assert!(cmd.contains("WINPID=$($p.Id)"), "{cmd}");
        assert!(cmd.contains("exit $p.ExitCode"), "{cmd}");
    }

    #[test]
    fn jit_config_validation_rejects_hostile_or_oversized_input() {
        let script = r"C:\actions-runner\run.cmd";
        assert!(validate_jit_config(script, "eyJhbGciOi+/=_-c9").is_ok());

        for bad in ["", "abc def", "abc'def", "abc\"def", "abc;rm -rf"] {
            assert!(validate_jit_config(script, bad).is_err(), "{bad:?}");
        }

        let oversized = "A".repeat(CMD_LINE_BUDGET);
        let err = validate_jit_config(script, &oversized).expect_err("oversized");
        assert!(err.to_string().contains("too large"), "{err}");
    }

    /// Write an executable stub script for the fake powershell/taskkill.
    fn stub(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// [`InteropRunner::spawn`], retrying the brief ETXTBSY window: a
    /// concurrently forking test can hold a just-written stub open for
    /// writing until its own exec, and executing a file open for writing
    /// fails with "Text file busy". Test-suite artifact only — production
    /// spawns long-existing Windows binaries, never freshly written ones.
    async fn spawn_retrying(runner: &InteropRunner, jit: &str) -> Result<InteropJob> {
        for _ in 0..100 {
            match runner.spawn(jit).await {
                Err(e) if format!("{e:#}").contains("Text file busy") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                other => return other,
            }
        }
        panic!("spawn kept hitting ETXTBSY");
    }

    /// The spawn handshake parses `WINPID=` from the wrapper's stdout, and
    /// a normal exit propagates the exit code through `wait`.
    #[tokio::test]
    async fn spawn_handshakes_winpid_and_wait_mirrors_the_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let powershell = stub(dir.path(), "powershell", "echo 'WINPID=4242'\nexit 7");
        let taskkill = stub(dir.path(), "taskkill", "exit 0");
        let runner = InteropRunner::with_paths(powershell, taskkill, r"C:\r\run.cmd");

        let mut job = spawn_retrying(&runner, "dGVzdA==")
            .await
            .expect("handshake");
        assert_eq!(job.windows_pid(), 4242);
        let status = job.wait().await.expect("wait");
        assert_eq!(status.code(), Some(7));
    }

    /// Pre-handshake chatter on stdout is tolerated; the handshake scans
    /// for the `WINPID=` line rather than requiring it first.
    #[tokio::test]
    async fn spawn_skips_pre_handshake_output() {
        let dir = tempfile::tempdir().unwrap();
        let powershell = stub(
            dir.path(),
            "powershell",
            "echo 'starting up'\necho 'WINPID=7'\nexit 0",
        );
        let taskkill = stub(dir.path(), "taskkill", "exit 0");
        let runner = InteropRunner::with_paths(powershell, taskkill, r"C:\r\run.cmd");

        let job = spawn_retrying(&runner, "dGVzdA==")
            .await
            .expect("handshake");
        assert_eq!(job.windows_pid(), 7);
    }

    /// A wrapper that exits without reporting a PID is a spawn failure —
    /// the caller rejects the offer instead of accepting a ghost job.
    #[tokio::test]
    async fn spawn_fails_when_the_wrapper_never_reports_winpid() {
        let dir = tempfile::tempdir().unwrap();
        let powershell = stub(dir.path(), "powershell", "echo 'no pid here'\nexit 1");
        let taskkill = stub(dir.path(), "taskkill", "exit 0");
        let runner = InteropRunner::with_paths(powershell, taskkill, r"C:\r\run.cmd");

        let err = spawn_retrying(&runner, "dGVzdA==")
            .await
            .expect_err("no handshake");
        assert!(
            err.to_string().contains("without reporting WINPID"),
            "{err}"
        );
    }

    /// Cancellation goes through taskkill (here a stub that SIGKILLs the
    /// reported PID — the stub reports its own, standing in for the Windows
    /// tree), after which the relay's exit is reaped by `kill` itself.
    #[tokio::test]
    async fn kill_invokes_taskkill_with_the_windows_pid_and_reaps_the_relay() {
        let dir = tempfile::tempdir().unwrap();
        // The fake powershell reports its own PID then parks, exactly like
        // the real wrapper parks in WaitForExit until the tree dies.
        let powershell = stub(
            dir.path(),
            "powershell",
            "echo \"WINPID=$$\"\nexec sleep 30",
        );
        // The fake taskkill records its arguments, then kills the "tree".
        let log = dir.path().join("taskkill.log");
        let taskkill = stub(
            dir.path(),
            "taskkill",
            &format!("echo \"$@\" > {}\nkill -9 \"$4\"", log.display()),
        );
        let runner = InteropRunner::with_paths(powershell, taskkill, r"C:\r\run.cmd");

        let mut job = spawn_retrying(&runner, "dGVzdA==")
            .await
            .expect("handshake");
        let pid = job.windows_pid();
        let start = tokio::time::Instant::now();
        job.kill().await;
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "kill must not wait out the stub's 30s sleep"
        );
        let recorded = std::fs::read_to_string(&log).expect("taskkill invoked");
        assert_eq!(recorded.trim(), format!("/T /F /PID {pid}"));
    }

    /// Live end-to-end against real interop — requires a WSL2 host, so it
    /// is ignored by default:
    /// `cargo test -p arcbox-fleet-agent -- --ignored interop`.
    /// Stages a stub `run.cmd` in the Windows user's `%TEMP%` (resolved
    /// across the same interop boundary under test).
    #[tokio::test]
    #[ignore = "requires a WSL2 host with Windows interop enabled"]
    async fn live_wsl_spawn_and_kill_round_trip() {
        let cmd_exe = windows_path_to_unix(r"C:\Windows\System32\cmd.exe").expect("wslpath");
        let output = std::process::Command::new(cmd_exe)
            .args(["/c", "echo %TEMP%"])
            .output()
            .expect("resolving %TEMP% via interop");
        let temp_win = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let script = format!("{temp_win}\\arcbox-interop-test.cmd");
        let staged = windows_path_to_unix(&script).expect("translate %TEMP%");
        std::fs::write(&staged, "@echo off\r\nping -n 60 127.0.0.1 >NUL\r\n").unwrap();

        let runner = InteropRunner::new(&script).await.expect("probe");
        let mut job = runner.spawn("dGVzdA==").await.expect("spawn");
        assert!(job.windows_pid() > 0);

        let start = tokio::time::Instant::now();
        job.kill().await;
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "taskkill must unblock the relay well before the 60s ping ends"
        );
        let _ = std::fs::remove_file(&staged);
    }
}
