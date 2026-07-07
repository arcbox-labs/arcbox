//! Embeds the git build identity (`ARCBOX_BUILD_SHA`) so a running daemon can
//! be matched to a source revision. The dev workflow relies on this: the
//! packaged desktop app ships and restores its own daemon binary, so swapping a
//! local build into the bundle is unreliable — always confirm the running
//! daemon logs the expected SHA. With no `rerun-if-*` emitted, cargo re-runs
//! this script whenever the crate is rebuilt, keeping the SHA/dirty flag fresh.
use std::process::Command;

fn main() {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    };

    let sha = git(&["rev-parse", "--short=12", "HEAD"])
        .map_or_else(|| "unknown".to_string(), |s| s.trim().to_string());
    let dirty = git(&["status", "--porcelain"]).is_some_and(|s| !s.trim().is_empty());

    println!(
        "cargo:rustc-env=ARCBOX_BUILD_SHA={sha}{}",
        if dirty { "-dirty" } else { "" }
    );
}
