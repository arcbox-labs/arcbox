//! Self-update executor: download → verify → probe → swap → re-exec.
//!
//! Runs when the gateway pushes an [`AgentUpdate`] carrying a download
//! (`binary_url` + `binary_sha256`). The checksum from the gateway — not the
//! download host — is the integrity root; the `--version` probe of the
//! downloaded binary is the loop-breaker (a mis-registered release whose
//! binary reports the wrong version can never be installed, so the agent can
//! never exec itself into an update cycle).
//!
//! Self-update only manages binaries it owns: the running executable must be
//! the managed path (`<data_dir>/bin/arcbox-fleet-agent`, where
//! `quick install-service` and the install script place it). A dev build or
//! a hand-installed binary elsewhere parks on the expected version exactly
//! as before self-update existed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use arcbox_fleet_proto::v1::AgentUpdate;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::config::AgentConfig;

/// Name of the previous binary, kept beside the managed one after a swap —
/// forensics only; recovery from a bad release is re-promoting the previous
/// version server-side, not a local rollback.
const PREVIOUS_SUFFIX: &str = "arcbox-fleet-agent.prev";

/// A pushed update that actually carries a download. Wire payloads without a
/// URL (pre-registry gateways, releases missing this platform's asset) stay
/// on the park path and never construct one of these.
#[derive(Debug, Clone)]
pub struct UpdatePayload {
    pub expected_version: String,
    pub binary_url: String,
    pub binary_sha256: String,
}

impl UpdatePayload {
    /// Extract the downloadable payload from a wire `AgentUpdate`; `None`
    /// when the gateway sent only an expected version (the park path).
    pub fn from_wire(update: &AgentUpdate) -> Option<Self> {
        if update.binary_url.is_empty() {
            return None;
        }
        Some(Self {
            expected_version: update.expected_version.clone(),
            binary_url: update.binary_url.clone(),
            binary_sha256: update.binary_sha256.clone(),
        })
    }
}

/// The running executable is not the managed binary, so self-update declines
/// to touch it. Typed so callers park (operator manages this binary) instead
/// of retrying.
#[derive(Debug, thiserror::Error)]
#[error("running binary {current} is not the managed {managed}; self-update declined")]
pub struct UnmanagedBinary {
    current: String,
    managed: String,
}

/// The path `quick install-service` and the self-updater own.
pub fn managed_binary(config: &AgentConfig) -> PathBuf {
    config.data_dir.join("bin").join("arcbox-fleet-agent")
}

/// Root of the release CDN's fleet-agent layout. The manual self-update
/// path (`quick self-update`) resolves versions and asset URLs here, in
/// lockstep with the publish pipeline (see `.github/workflows/
/// release-fleet-agent.yml`). Gateway-pushed updates use the URL the
/// gateway sends and don't depend on this constant.
const CDN_FLEET_AGENT_BASE: &str = "https://release.arcboxcdn.com/runner/fleet-agent";

/// Resolve the latest published version from the CDN and build the
/// corresponding [`UpdatePayload`] for this host's platform. Two client →
/// CDN contracts are pinned here: `latest.json`'s `{"version": "vX.Y.Z"}`
/// schema, and the `arcbox-fleet-agent-<os>-<arch>` asset layout with a
/// `<hex>  <name>` `.sha256` sidecar. Kept narrow: this is the
/// recovery/bootstrap path — gateway pushes remain the authoritative
/// rollout mechanism.
pub async fn resolve_latest(host_os: &str, host_arch: &str) -> Result<UpdatePayload> {
    #[derive(serde::Deserialize)]
    struct Latest {
        version: String,
    }

    let latest_url = format!("{CDN_FLEET_AGENT_BASE}/latest.json");
    let latest_body = reqwest::get(&latest_url)
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching {latest_url}"))?
        .text()
        .await
        .with_context(|| format!("reading body of {latest_url}"))?;
    let latest: Latest = serde_json::from_str(&latest_body)
        .with_context(|| format!("parsing {latest_url}"))?;

    let asset_name = format!("arcbox-fleet-agent-{host_os}-{host_arch}");
    let binary_url = format!("{CDN_FLEET_AGENT_BASE}/{}/{asset_name}", latest.version);
    let sha_url = format!("{binary_url}.sha256");
    let sha_body = reqwest::get(&sha_url)
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching {sha_url}"))?
        .text()
        .await
        .with_context(|| format!("reading body of {sha_url}"))?;
    // `shasum -a 256`-style sidecar: `<hex>  <name>`, hash first.
    let binary_sha256 = sha_body
        .split_whitespace()
        .next()
        .with_context(|| format!("empty sha256 sidecar at {sha_url}"))?
        .to_owned();

    // `latest.json`'s `version` carries the `v` prefix (the tag minus
    // `fleet-agent-`); `--version` output is bare `CARGO_PKG_VERSION`, and
    // `probe_version` compares the two directly.
    let expected_version = latest
        .version
        .strip_prefix('v')
        .unwrap_or(&latest.version)
        .to_owned();

    Ok(UpdatePayload {
        expected_version,
        binary_url,
        binary_sha256,
    })
}

/// Download, verify, probe, and swap `payload` into the managed path, then
/// re-exec it with this process's arguments. Returns only on failure; on
/// success the process image is replaced (same PID, so launchd's job
/// bookkeeping is undisturbed).
pub async fn apply_and_exec(config: &AgentConfig, payload: &UpdatePayload) -> anyhow::Error {
    let managed = match apply(config, payload).await {
        Ok(managed) => managed,
        Err(error) => return error,
    };
    exec_replacement(&managed)
}

/// Everything up to (not including) the exec: leaves the verified new binary
/// at the managed path and the old one beside it as `.prev`. Split from
/// [`apply_and_exec`] so tests can exercise the full pipeline — exec is
/// untestable in-process.
async fn apply(config: &AgentConfig, payload: &UpdatePayload) -> Result<PathBuf> {
    let managed = managed_binary(config);
    let current = std::env::current_exe().context("resolving the current binary path")?;
    ensure_managed(&current, &managed)?;

    info!(
        version = %payload.expected_version,
        url = %payload.binary_url,
        "self-update: downloading"
    );
    let staged = download_verified(config, payload).await?;
    probe_version(&staged, &payload.expected_version).await?;

    // Two renames, not a copy: the running image keeps its (now unlinked
    // via .prev) inode, and the managed path atomically becomes the new
    // binary — there is no instant where the path is missing or truncated.
    let previous = managed.with_file_name(PREVIOUS_SUFFIX);
    tokio::fs::rename(&managed, &previous)
        .await
        .with_context(|| format!("parking previous binary at {}", previous.display()))?;
    tokio::fs::rename(&staged, &managed)
        .await
        .with_context(|| format!("installing new binary at {}", managed.display()))?;
    info!(version = %payload.expected_version, "self-update: binary swapped; re-executing");
    Ok(managed)
}

/// Replace this process image with `binary`, preserving argv. Returns only
/// the exec error.
fn exec_replacement(binary: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let error = std::process::Command::new(binary)
        .args(std::env::args_os().skip(1))
        .exec();
    anyhow::Error::new(error).context(format!("exec {}", binary.display()))
}

/// Self-update owns exactly the managed path; refuse anything else.
/// Canonicalized on both sides so a symlinked data dir still matches.
fn ensure_managed(current: &Path, managed: &Path) -> Result<()> {
    let canonical_current = current
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", current.display()))?;
    let canonical_managed = managed
        .canonicalize()
        .unwrap_or_else(|_| managed.to_path_buf());
    if canonical_current != canonical_managed {
        bail!(UnmanagedBinary {
            current: canonical_current.display().to_string(),
            managed: managed.display().to_string(),
        });
    }
    Ok(())
}

/// Fetch the binary into `<data_dir>/updates/` and require its SHA-256 to
/// match the gateway-pinned digest before anything executes or moves it.
async fn download_verified(config: &AgentConfig, payload: &UpdatePayload) -> Result<PathBuf> {
    let staging_dir = config.data_dir.join("updates");
    tokio::fs::create_dir_all(&staging_dir)
        .await
        .with_context(|| format!("creating {}", staging_dir.display()))?;

    let response = reqwest::get(&payload.binary_url)
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("downloading {}", payload.binary_url))?;
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("reading body of {}", payload.binary_url))?;

    let digest = hex_digest(&bytes);
    if !digest.eq_ignore_ascii_case(payload.binary_sha256.trim()) {
        bail!(
            "downloaded binary digest {digest} does not match the gateway-pinned {} for version {}",
            payload.binary_sha256,
            payload.expected_version,
        );
    }

    let staged = staging_dir.join(format!("arcbox-fleet-agent-{}", payload.expected_version));
    tokio::fs::write(&staged, &bytes)
        .await
        .with_context(|| format!("writing {}", staged.display()))?;
    // HTTP carries no file modes; the exec bit is always set here.
    let executable = std::fs::Permissions::from_mode(0o755);
    tokio::fs::set_permissions(&staged, executable)
        .await
        .with_context(|| format!("marking {} executable", staged.display()))?;
    Ok(staged)
}

use std::os::unix::fs::PermissionsExt;

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
            hex
        })
}

/// Run the downloaded binary with `--version` and require it to report
/// exactly the expected version. Catches a wrong-arch binary (exec fails), a
/// truncated or corrupt file, and — critically — a release registered under
/// a version its binary does not report, which would otherwise exec-loop.
async fn probe_version(binary: &Path, expected: &str) -> Result<()> {
    let output = tokio::process::Command::new(binary)
        .arg("--version")
        .output()
        .await
        .with_context(|| format!("probing {} --version", binary.display()))?;
    if !output.status.success() {
        bail!(
            "downloaded binary failed the --version probe ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // clap prints "arcbox-fleet-agent <version>"; compare the version token.
    let reported = stdout.trim().rsplit(' ').next().unwrap_or_default();
    if reported != expected {
        bail!("downloaded binary reports version {reported}, expected {expected}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    fn test_config(data_dir: &Path) -> AgentConfig {
        AgentConfig {
            gateway: "http://127.0.0.1:1".to_owned(),
            runner_script: None,
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            data_dir: data_dir.to_path_buf(),
            docker: crate::config::DockerConfig {
                mode: crate::config::DockerMode::Disabled,
                linux_runner_image: "img".to_owned(),
            },
            vm: crate::config::VmConfig {
                mode: crate::config::VmMode::Disabled,
                macos_runner_image: "tahoe-base".to_owned(),
                daemon_socket: PathBuf::from("/nonexistent/arcbox.sock"),
            },
            credential_store: crate::config::CredentialMode::File,
        }
    }

    /// Serve `body` once over plain HTTP/1.1 and return the URL.
    async fn serve_once(body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/arcbox-fleet-agent-darwin-arm64",
            listener.local_addr().unwrap()
        );
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(header.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        url
    }

    fn payload(url: String, body: &[u8], version: &str) -> UpdatePayload {
        UpdatePayload {
            expected_version: version.to_owned(),
            binary_url: url,
            binary_sha256: hex_digest(body),
        }
    }

    #[test]
    fn from_wire_requires_a_url() {
        assert!(
            UpdatePayload::from_wire(&AgentUpdate {
                expected_version: "0.5.1".into(),
                binary_url: String::new(),
                binary_sha256: String::new(),
            })
            .is_none()
        );
        let payload = UpdatePayload::from_wire(&AgentUpdate {
            expected_version: "0.5.1".into(),
            binary_url: "https://example.com/x".into(),
            binary_sha256: "aa".into(),
        })
        .expect("url present");
        assert_eq!(payload.expected_version, "0.5.1");
    }

    #[tokio::test]
    async fn download_rejects_a_wrong_checksum() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let url = serve_once(b"binary bytes".to_vec()).await;
        let mut bad = payload(url, b"binary bytes", "0.5.1");
        bad.binary_sha256 = hex_digest(b"different bytes");

        let error = download_verified(&config, &bad)
            .await
            .expect_err("checksum mismatch must fail");
        assert!(error.to_string().contains("does not match"));
        // Nothing staged on failure.
        assert!(
            !config
                .data_dir
                .join("updates")
                .join("arcbox-fleet-agent-0.5.1")
                .exists()
        );
    }

    #[tokio::test]
    async fn download_stages_an_executable_verified_binary() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let body = b"#!/bin/sh\necho arcbox-fleet-agent 0.5.1\n".to_vec();
        let url = serve_once(body.clone()).await;

        let staged = download_verified(&config, &payload(url, &body, "0.5.1"))
            .await
            .expect("download succeeds");
        let mode = std::fs::metadata(&staged).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        assert_eq!(std::fs::read(&staged).unwrap(), body);
    }

    #[tokio::test]
    async fn probe_accepts_matching_version_and_rejects_drift() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-agent");
        std::fs::write(&fake, "#!/bin/sh\necho arcbox-fleet-agent 0.5.1\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        probe_version(&fake, "0.5.1")
            .await
            .expect("version matches");
        let error = probe_version(&fake, "0.5.2")
            .await
            .expect_err("version drift must fail the probe");
        assert!(error.to_string().contains("reports version 0.5.1"));
    }

    #[tokio::test]
    async fn unmanaged_binary_is_a_typed_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());
        let url = serve_once(Vec::new()).await;
        let error = apply(&config, &payload(url, &[], "0.5.1"))
            .await
            .expect_err("test binary does not run from the managed path");
        assert!(
            error
                .chain()
                .any(|c| c.downcast_ref::<UnmanagedBinary>().is_some()),
            "expected UnmanagedBinary, got: {error:#}"
        );
    }
}
