//! Idempotent code signing for locally built test binaries.
//!
//! Booting VMs requires the `com.apple.security.virtualization` /
//! `com.apple.security.hypervisor` entitlements on the binary. Only
//! `com.apple.vm.networking` (bridged vmnet) needs a Developer ID
//! signature backed by a provisioning profile; the dev entitlements omit
//! it, so an ad-hoc signature boots HV/VZ VMs on any Apple Silicon
//! machine. Mirrors `make sign-daemon` (Developer ID) / `make sign`
//! (ad-hoc), both of which sign with `bundle/arcbox.dev.entitlements`.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::repo_root;

/// Ensures `binary` carries the virtualization entitlement, signing it in
/// place when necessary.
///
/// A cargo relink leaves only the bare linker ad-hoc signature without
/// entitlements, so callers run this before every spawn; a binary that
/// already verifies with the entitlement is left untouched.
pub fn ensure_signed(binary: &Path) -> Result<()> {
    if is_signed_for_virtualization(binary) {
        return Ok(());
    }

    let entitlements = repo_root().join("bundle/arcbox.dev.entitlements");
    let identity = developer_id_identity().unwrap_or_else(|| "-".to_string());
    tracing::info!(
        binary = %binary.display(),
        identity = %identity,
        "signing test binary with virtualization entitlements"
    );
    let status = Command::new("codesign")
        .args(["--force", "--options", "runtime", "--entitlements"])
        .arg(&entitlements)
        .args(["--sign", &identity])
        .arg(binary)
        .status()
        .with_context(|| format!("running codesign on {}", binary.display()))?;
    if !status.success() {
        bail!("codesign failed for {} with {status}", binary.display());
    }
    Ok(())
}

/// True when the binary's signature verifies and its entitlements include
/// `com.apple.security.virtualization`.
fn is_signed_for_virtualization(binary: &Path) -> bool {
    let verified = Command::new("codesign")
        .args(["--verify", "--strict"])
        .arg(binary)
        .status()
        .is_ok_and(|s| s.success());
    if !verified {
        return false;
    }
    Command::new("codesign")
        .args(["-d", "--entitlements", ":-"])
        .arg(binary)
        .output()
        .is_ok_and(|out| {
            // codesign has printed entitlements to stdout or stderr
            // depending on the macOS release; check both.
            let text = [out.stdout, out.stderr].concat();
            String::from_utf8_lossy(&text).contains("com.apple.security.virtualization")
        })
}

/// First `Developer ID Application: ArcBox` identity in the keychain, if
/// any — the same detection as `make sign-daemon`.
fn developer_id_identity() -> Option<String> {
    let out = Command::new("security")
        .args(["find-identity", "-v", "-p", "codesigning"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines().find_map(|line| {
        let start = line.find("\"Developer ID Application: ArcBox")?;
        let rest = &line[start + 1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    })
}
