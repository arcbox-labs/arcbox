//! Scaffolding this crate's tests share: stand-ins for the binaries the
//! block-device and device-mapper paths shell out to.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Write an executable stand-in for `name` into `dir`: a shell script that
/// logs every invocation's arguments to `<name>.calls` and runs `body` (a
/// `case "$*"` over them). Returns the script and the call log.
///
/// Tests hand these scripts `/dev/loop9999`, a device no host has, so the
/// sysfs verification finds nothing to compare and the script stays the
/// only authority on what happened.
pub fn fake_tool(dir: &Path, name: &str, body: &str) -> (PathBuf, PathBuf) {
    let calls = dir.join(format!("{name}.calls"));
    let script = dir.join(name);
    write_script(
        &script,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\ncase \"$*\" in\n{body}\nesac\n",
            calls.display()
        ),
    );
    // The probe in `write_script` ran it, so every test starts from an
    // empty record.
    std::fs::remove_file(&calls).ok();
    (script, calls)
}

/// Every line a [`fake_tool`] stand-in recorded, in invocation order.
pub fn calls(log: &Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Write `body` to `path`, make it executable, and do not return until the
/// kernel agrees to exec it.
///
/// A sibling test thread that forks — every test driving one of these
/// stand-ins does — between this thread's `create` and `close` leaves its
/// child holding a write fd to the script, and Linux will not exec a file
/// that is open for writing (`ETXTBSY`). The window closes as soon as that
/// child execs and never reopens, since nothing writes the script again;
/// exec'ing it until it runs is what proves the window is shut. Skipping
/// this is a flake that only shows up as the test binary's thread count
/// grows.
pub fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match Command::new(path).output() {
            Err(error) if error.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{} stayed busy for 5s",
                    path.display()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            other => {
                other.unwrap();
                return;
            }
        }
    }
}
