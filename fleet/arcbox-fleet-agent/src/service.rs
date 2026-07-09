//! `install-service` / `uninstall-service` — user LaunchAgent installer for
//! macOS. Renders the plist with runtime-resolved paths
//! (`env::current_exe()`, `$HOME`) and drives `launchctl`, so a plain
//! `arcbox-fleet-agent install-service` sets up start-on-login without
//! sudo, static plist files, or manual `launchctl` incantations.
//!
//! macOS-only for now. Linux systemd (user unit) is planned as a follow-up.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use plist::{Dictionary, Value};

use crate::config::AgentConfig;

/// Reverse-DNS Label for the LaunchAgent job. Mirrors the pattern used by
/// `com.arcboxlabs.desktop.helper` so operators can eyeball ArcBox jobs
/// in a single `launchctl print` output.
const LABEL: &str = "com.arcboxlabs.fleet.agent";

/// Install the LaunchAgent so `arcbox-fleet-agent serve` starts on the next
/// user login (and immediately if the user is already logged in). Renders
/// the plist against the binary that invoked this command
/// (`env::current_exe()`) and the agent's configured data directory, writes
/// it to `~/Library/LaunchAgents/`, and bootstraps it into the current GUI
/// session. Idempotent-refusal on second run: if the job is already loaded,
/// prints an actionable message asking the operator to `uninstall-service`
/// first instead of silently overwriting a live install.
pub fn install(config: &AgentConfig) -> Result<()> {
    let binary = std::env::current_exe().context("resolving the current binary path")?;

    let plist_path = plist_path()?;
    let plist_dir = plist_path
        .parent()
        .ok_or_else(|| anyhow!("LaunchAgents plist path has no parent"))?;
    std::fs::create_dir_all(plist_dir)
        .with_context(|| format!("creating {}", plist_dir.display()))?;

    if plist_path.exists() {
        bail!(
            "{LABEL} is already installed at {}; run `arcbox-fleet-agent uninstall-service` \
             first (or delete the plist by hand) before reinstalling",
            plist_path.display()
        );
    }

    let log_dir = config.data_dir.join("log");
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("creating log dir {}", log_dir.display()))?;

    let plist = launch_agent_plist(&binary, &log_dir);
    plist::to_file_xml(&plist_path, &plist)
        .with_context(|| format!("writing {}", plist_path.display()))?;

    let uid = current_uid();
    let target = format!("gui/{uid}");
    let output = Command::new("launchctl")
        .args(["bootstrap", &target])
        .arg(&plist_path)
        .output()
        .context("invoking `launchctl bootstrap`")?;
    if !output.status.success() {
        // Leave the plist on disk — the operator can inspect it and either
        // fix the environment or `uninstall-service` to clean up.
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`launchctl bootstrap {target} {}` failed ({}): {}",
            plist_path.display(),
            output.status,
            stderr.trim()
        );
    }

    println!("installed LaunchAgent {LABEL}");
    println!("  plist:  {}", plist_path.display());
    println!("  binary: {}", binary.display());
    println!("  status: launchctl print {target}/{LABEL}");
    Ok(())
}

/// Remove the LaunchAgent installed by [`install`]. Idempotent: a `bootout`
/// error when the job isn't loaded is treated as success, and a missing
/// plist file is treated as success — the desired end state is "not
/// installed," regardless of which piece was already gone.
pub fn uninstall() -> Result<()> {
    let plist_path = plist_path()?;
    let uid = current_uid();
    let target = format!("gui/{uid}/{LABEL}");

    let output = Command::new("launchctl")
        .args(["bootout", &target])
        .output()
        .context("invoking `launchctl bootout`")?;
    // `bootout` exits non-zero when the job isn't loaded; we want the same
    // outcome as when it *was* loaded and we successfully removed it, so
    // ignore the exit code and just log the stderr for visibility. A real
    // failure (e.g., malformed target) still surfaces via the printed
    // stderr, without preventing plist cleanup below.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if !stderr.is_empty() {
            eprintln!("launchctl bootout: {stderr}");
        }
    }

    match std::fs::remove_file(&plist_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(anyhow!(e).context(format!("removing {}", plist_path.display())));
        }
    }

    println!("uninstalled LaunchAgent {LABEL}");
    Ok(())
}

/// Compose the LaunchAgent plist. `binary` is the absolute path to the
/// current agent binary (so a rename or move requires re-installing);
/// `log_dir` is where launchd tees stdout/stderr — ideally the same
/// directory the agent's own logger uses, so early-startup output before
/// [`arcbox_logging::init`] has a chance to land in the same place.
fn launch_agent_plist(binary: &Path, log_dir: &Path) -> Value {
    let stdout = log_dir.join("fleet-agent.stdout.log");
    let stderr = log_dir.join("fleet-agent.stderr.log");

    let mut dict = Dictionary::new();
    dict.insert("Label".into(), Value::String(LABEL.into()));
    dict.insert(
        "ProgramArguments".into(),
        Value::Array(vec![
            Value::String(binary.to_string_lossy().into_owned()),
            Value::String("serve".into()),
        ]),
    );
    dict.insert("RunAtLoad".into(), Value::Boolean(true));

    // SuccessfulExit=false: launchd respawns non-zero exits only, so a
    // SIGTERM shutdown from `launchctl bootout` doesn't get resurrected.
    let mut keep_alive = Dictionary::new();
    keep_alive.insert("SuccessfulExit".into(), Value::Boolean(false));
    dict.insert("KeepAlive".into(), Value::Dictionary(keep_alive));

    // Ceiling between SIGTERM and SIGKILL. Comfortably above the agent's
    // own SHUTDOWN_GRACE for runner drain, with headroom for zombie reap.
    dict.insert("ExitTimeOut".into(), Value::Integer(60.into()));

    // launchd's tee of stdout/stderr, so anything the agent writes before
    // it opens its own log file still lands next to the real logs.
    dict.insert(
        "StandardOutPath".into(),
        Value::String(stdout.to_string_lossy().into_owned()),
    );
    dict.insert(
        "StandardErrorPath".into(),
        Value::String(stderr.to_string_lossy().into_owned()),
    );

    Value::Dictionary(dict)
}

/// Path where the plist is installed. LaunchAgents in `~/Library/LaunchAgents`
/// load per-user on GUI login; a system-wide install would need
/// `/Library/LaunchAgents` (all users) or `/Library/LaunchDaemons` (root,
/// no session) — deliberately out of scope for the per-user install.
fn plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("could not resolve home directory"))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist")))
}

/// Read the effective UID via `libc::getuid`. LaunchAgents live under
/// `gui/{uid}`; we need the numeric id, not the login name.
fn current_uid() -> u32 {
    // SAFETY: getuid is a POSIX system call with no preconditions and no
    // failure mode — always returns the caller's real UID.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_string<'a>(dict: &'a Dictionary, key: &str) -> &'a str {
        dict.get(key)
            .and_then(Value::as_string)
            .unwrap_or_else(|| panic!("plist missing string key {key}"))
    }

    #[test]
    fn plist_carries_label_binary_serve_and_log_paths() {
        let plist = launch_agent_plist(
            Path::new("/usr/local/bin/arcbox-fleet-agent"),
            Path::new("/home/user/.arcbox/fleet/log"),
        );
        let dict = plist.as_dictionary().expect("root is a dict");

        assert_eq!(expect_string(dict, "Label"), LABEL);
        assert_eq!(
            expect_string(dict, "StandardOutPath"),
            "/home/user/.arcbox/fleet/log/fleet-agent.stdout.log"
        );
        assert_eq!(
            expect_string(dict, "StandardErrorPath"),
            "/home/user/.arcbox/fleet/log/fleet-agent.stderr.log"
        );

        let args = dict
            .get("ProgramArguments")
            .and_then(Value::as_array)
            .expect("ProgramArguments is an array");
        let args: Vec<&str> = args.iter().filter_map(Value::as_string).collect();
        assert_eq!(args, ["/usr/local/bin/arcbox-fleet-agent", "serve"]);
    }

    #[test]
    fn plist_respawns_only_on_crash_not_clean_exit() {
        let plist = launch_agent_plist(Path::new("/x"), Path::new("/y"));
        let dict = plist.as_dictionary().expect("root is a dict");
        assert_eq!(
            dict.get("RunAtLoad").and_then(Value::as_boolean),
            Some(true)
        );

        // SuccessfulExit=false: SIGTERM shutdowns don't get resurrected;
        // only genuine crashes trigger a respawn.
        let keep_alive = dict
            .get("KeepAlive")
            .and_then(Value::as_dictionary)
            .expect("KeepAlive is a dict");
        assert_eq!(
            keep_alive.get("SuccessfulExit").and_then(Value::as_boolean),
            Some(false)
        );
    }

    #[test]
    fn plist_serializes_to_valid_xml_with_correct_doctype() {
        let plist = launch_agent_plist(
            Path::new("/usr/local/bin/arcbox-fleet-agent"),
            Path::new("/log"),
        );
        let mut buf: Vec<u8> = Vec::new();
        plist::to_writer_xml(&mut buf, &plist).expect("plist serializes");
        let xml = String::from_utf8(buf).expect("plist crate emits UTF-8");
        assert!(xml.contains("<!DOCTYPE plist PUBLIC"));
        assert!(xml.contains("<key>Label</key>"));
    }
}
