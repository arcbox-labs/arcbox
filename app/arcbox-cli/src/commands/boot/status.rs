use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Result, bail};
use arcbox_core::boot_assets::{BootAssetConfig, BootAssetManifest, BootAssetProvider};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

use super::super::OutputFormat;
use super::StatusArgs;

#[derive(Debug, Serialize)]
struct StatusOutput {
    version: String,
    arch: String,
    cache_dir: String,
    complete: bool,
    artifacts: Vec<ArtifactStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest: Option<ManifestInfo>,
    reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_version_error: Option<String>,
    update_available: bool,
}

#[derive(Debug, Serialize)]
struct ArtifactStatus {
    name: &'static str,
    path: String,
    required: bool,
    present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct ManifestInfo {
    schema_version: u32,
    asset_version: String,
    built_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sha: Option<String>,
}

pub(super) async fn status(
    root_data_dir: &Path,
    config: BootAssetConfig,
    args: StatusArgs,
    format: OutputFormat,
) -> Result<()> {
    let provider = BootAssetProvider::with_config(config.clone())?;
    let manifest = provider
        .read_cached_manifest_required()
        .await
        .map_err(|error| format!("{error:#}"));
    let runtime_bin_dir = root_data_dir
        .join("runtime")
        .join(&config.version)
        .join("bin");
    let runtime_binaries = if manifest.is_ok() {
        provider
            .validate_cached_binaries(&runtime_bin_dir)
            .await
            .map_err(|error| format!("{error:#}"))
    } else {
        Err("manifest unavailable".to_owned())
    };
    let mut report = build_report(root_data_dir, &config, manifest, runtime_binaries).await;

    if !args.offline {
        match provider.fetch_latest_version().await {
            Ok(version) => report.latest_version = version,
            Err(error) => report.latest_version_error = Some(format!("{error:#}")),
        }
    }
    report.update_available = report
        .latest_version
        .as_ref()
        .is_some_and(|latest| latest != &report.version);

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
        OutputFormat::Table => println!("{}", render_table(&report)),
        OutputFormat::Quiet => bail!("quiet output is not supported for boot status"),
    }
    if !report.complete {
        bail!("boot assets are incomplete");
    }
    Ok(())
}

async fn build_report(
    root_data_dir: &Path,
    config: &BootAssetConfig,
    manifest_result: std::result::Result<BootAssetManifest, String>,
    runtime_binaries: std::result::Result<(), String>,
) -> StatusOutput {
    let version_dir = config.version_cache_dir();
    let kernel_path = config
        .custom_kernel
        .clone()
        .unwrap_or_else(|| version_dir.join("kernel"));
    let mut artifacts = vec![
        inspect_artifact("manifest", &version_dir.join("manifest.json"), true),
        inspect_artifact("kernel", &kernel_path, true),
        inspect_artifact("rootfs", &version_dir.join("rootfs.erofs"), true),
    ];
    let mut reasons = Vec::new();
    let mut manifest_info = None;

    match manifest_result {
        Err(error) => {
            artifacts[0].detail = Some(error.clone());
            if artifacts[0].present {
                reasons.push(format!("manifest: {error}"));
            }
        }
        Ok(manifest) => {
            manifest_info = Some(ManifestInfo {
                schema_version: manifest.schema_version,
                asset_version: manifest.asset_version.clone(),
                built_at: manifest.built_at.clone(),
                source_sha: manifest.source_sha.clone(),
            });
            if manifest.asset_version != config.version {
                reasons.push(format!(
                    "manifest selects version {}, expected {}",
                    manifest.asset_version, config.version
                ));
            }
            match manifest.targets.get(&config.arch) {
                Some(target) => {
                    if config.custom_kernel.is_none() {
                        artifacts[1].source_path = Some(target.kernel.path.clone());
                        artifacts[1].version.clone_from(&target.kernel.version);
                        verify_artifact_checksum(
                            &mut artifacts[1],
                            &kernel_path,
                            &target.kernel.sha256,
                            &mut reasons,
                        )
                        .await;
                    } else if artifacts[1].present {
                        artifacts[1].detail = Some("configured custom kernel".to_owned());
                    }
                    artifacts[2].source_path = Some(target.rootfs.path.clone());
                    artifacts[2].version.clone_from(&target.rootfs.version);
                    verify_artifact_checksum(
                        &mut artifacts[2],
                        &version_dir.join("rootfs.erofs"),
                        &target.rootfs.sha256,
                        &mut reasons,
                    )
                    .await;
                    if let Some(runtime) = &target.runtime {
                        let mut artifact =
                            inspect_artifact("runtime", &version_dir.join("runtime.erofs"), false);
                        artifact.source_path = Some(runtime.path.clone());
                        artifact.version.clone_from(&runtime.version);
                        artifact.detail = Some(
                            "legacy manifest entry; current ArcBox uses guest-cached runtime binaries"
                                .to_owned(),
                        );
                        artifacts.push(artifact);
                    }
                }
                None => reasons.push(format!(
                    "manifest has no target for architecture {}",
                    config.arch
                )),
            }
        }
    }

    let (present, detail) = match runtime_binaries {
        Ok(()) => (true, None),
        Err(error) => (false, Some(error)),
    };
    artifacts.push(ArtifactStatus {
        name: "runtime-binaries",
        path: root_data_dir
            .join("runtime")
            .join(&config.version)
            .display()
            .to_string(),
        required: true,
        present,
        size_bytes: None,
        source_path: None,
        version: manifest_info
            .as_ref()
            .map(|manifest| manifest.asset_version.clone()),
        detail,
    });

    for artifact in artifacts.iter().filter(|artifact| artifact.required) {
        if !artifact.present {
            reasons.push(format!(
                "{}: {}",
                artifact.name,
                artifact
                    .detail
                    .as_deref()
                    .unwrap_or("missing required artifact")
            ));
        }
    }
    let complete = reasons.is_empty();
    StatusOutput {
        version: config.version.clone(),
        arch: config.arch.clone(),
        cache_dir: version_dir.display().to_string(),
        complete,
        artifacts,
        manifest: manifest_info,
        reasons,
        repair: (!complete)
            .then_some("Fix the reported path or run `abctl boot prefetch --force`."),
        latest_version: None,
        latest_version_error: None,
        update_available: false,
    }
}

async fn verify_artifact_checksum(
    artifact: &mut ArtifactStatus,
    path: &Path,
    expected: &str,
    reasons: &mut Vec<String>,
) {
    if !artifact.present {
        return;
    }
    let detail = match sha256_file(path).await {
        Ok(actual) if actual == expected => return,
        Ok(actual) => format!("SHA-256 mismatch: expected {expected}, got {actual}"),
        Err(error) => format!("could not calculate SHA-256: {error}"),
    };
    reasons.push(format!("{}: {detail}", artifact.name));
    artifact.detail = Some(detail);
}

async fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn inspect_artifact(name: &'static str, path: &Path, required: bool) -> ArtifactStatus {
    let metadata = std::fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file() && metadata.len() > 0);
    let present = metadata.is_some();
    ArtifactStatus {
        name,
        path: path.display().to_string(),
        required,
        present,
        size_bytes: metadata.map(|metadata| metadata.len()),
        source_path: None,
        version: None,
        detail: (path.exists() && !present)
            .then(|| "artifact is empty or is not a regular file".to_owned()),
    }
}

fn render_table(report: &StatusOutput) -> String {
    let mut output = String::from("Boot Asset Status\n=================\n\n");
    writeln!(output, "Cache directory: {}", report.cache_dir)
        .expect("writing to a String cannot fail");
    writeln!(output, "Current version: {}", report.version)
        .expect("writing to a String cannot fail");
    writeln!(output, "Architecture:    {}", report.arch).expect("writing to a String cannot fail");
    if let Some(latest) = &report.latest_version {
        writeln!(output, "Latest version:  {latest}").expect("writing to a String cannot fail");
    }
    if let Some(error) = &report.latest_version_error {
        writeln!(output, "Latest version:  unavailable ({error})")
            .expect("writing to a String cannot fail");
    }
    writeln!(
        output,
        "\nStatus: {}",
        if report.complete {
            "complete"
        } else {
            "incomplete"
        }
    )
    .expect("writing to a String cannot fail");

    for artifact in &report.artifacts {
        write!(
            output,
            "  [{}] {:<10} {}",
            if artifact.present { "+" } else { "-" },
            artifact.name,
            artifact.path
        )
        .expect("writing to a String cannot fail");
        if let Some(size) = artifact.size_bytes {
            write!(output, " ({size} bytes)").expect("writing to a String cannot fail");
        }
        if !artifact.required {
            output.push_str(" [legacy, not required]");
        }
        if let Some(detail) = &artifact.detail {
            write!(output, " — {detail}").expect("writing to a String cannot fail");
        }
        output.push('\n');
    }
    for reason in &report.reasons {
        writeln!(output, "  Reason: {reason}").expect("writing to a String cannot fail");
    }
    if let Some(repair) = report.repair {
        writeln!(output, "\nRepair: {repair}").expect("writing to a String cannot fail");
    }
    output.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL: &[u8] = b"kernel";
    const ROOTFS: &[u8] = b"rootfs.erofs";

    fn config(root_data_dir: &Path) -> BootAssetConfig {
        let mut config =
            BootAssetConfig::with_cache_dir(root_data_dir.join("boot")).with_version("0.8.4");
        config.arch = "arm64".to_owned();
        config
    }

    fn write_required_assets(config: &BootAssetConfig) {
        let version_dir = config.version_cache_dir();
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::write(version_dir.join("manifest.json"), "{}").unwrap();
        std::fs::write(version_dir.join("kernel"), KERNEL).unwrap();
        std::fs::write(version_dir.join("rootfs.erofs"), ROOTFS).unwrap();
    }

    fn manifest(runtime: bool) -> BootAssetManifest {
        let kernel_sha256 = format!("{:x}", Sha256::digest(KERNEL));
        let rootfs_sha256 = format!("{:x}", Sha256::digest(ROOTFS));
        let runtime = if runtime {
            r#", "runtime": {"path": "arm64/runtime.erofs", "sha256": "03", "version": "29.0"}"#
        } else {
            ""
        };
        serde_json::from_str(&format!(
            r#"{{
                "schema_version": 0,
                "asset_version": "0.8.4",
                "built_at": "2026-08-10T00:00:00Z",
                "targets": {{
                    "arm64": {{
                        "kernel": {{"path": "arm64/kernel", "sha256": "{kernel_sha256}"}},
                        "rootfs": {{"path": "arm64/rootfs.erofs", "sha256": "{rootfs_sha256}"}},
                        "kernel_cmdline": "console=hvc0"{runtime}
                    }}
                }},
                "binaries": []
            }}"#
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn missing_required_artifact_is_reported_in_json_and_table() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        let version_dir = config.version_cache_dir();
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::write(version_dir.join("manifest.json"), "{}").unwrap();
        std::fs::write(version_dir.join("kernel"), KERNEL).unwrap();
        let report = build_report(directory.path(), &config, Ok(manifest(false)), Ok(())).await;

        assert!(!report.complete);
        assert!(
            report
                .reasons
                .contains(&"rootfs: missing required artifact".to_owned())
        );
        assert!(render_table(&report).contains("Reason: rootfs: missing required artifact"));
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["complete"], false);
        assert_eq!(json["reasons"][0], "rootfs: missing required artifact");
    }

    #[tokio::test]
    async fn corrupt_required_artifacts_are_reported_in_json_and_table() {
        for (file_name, artifact_name) in [("kernel", "kernel"), ("rootfs.erofs", "rootfs")] {
            let directory = tempfile::tempdir().unwrap();
            let config = config(directory.path());
            write_required_assets(&config);
            std::fs::write(config.version_cache_dir().join(file_name), b"corrupt").unwrap();

            let report = build_report(directory.path(), &config, Ok(manifest(false)), Ok(())).await;

            assert!(!report.complete);
            let artifact = report
                .artifacts
                .iter()
                .find(|artifact| artifact.name == artifact_name)
                .unwrap();
            assert!(artifact.present);
            assert!(
                artifact
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.starts_with("SHA-256 mismatch:"))
            );
            let reason = format!("Reason: {artifact_name}: SHA-256 mismatch:");
            assert!(render_table(&report).contains(&reason));
            let json = serde_json::to_value(report).unwrap();
            assert_eq!(json["complete"], false);
            let reason = format!("{artifact_name}: SHA-256 mismatch:");
            assert!(json["reasons"][0].as_str().unwrap().starts_with(&reason));
        }
    }

    #[tokio::test]
    async fn legacy_runtime_entry_is_enumerated_but_not_required() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        write_required_assets(&config);
        let report = build_report(directory.path(), &config, Ok(manifest(true)), Ok(())).await;

        assert!(report.complete);
        let runtime = report
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "runtime")
            .unwrap();
        assert!(!runtime.required);
        assert!(!runtime.present);
        assert_eq!(runtime.version.as_deref(), Some("29.0"));
    }

    #[tokio::test]
    async fn runtime_binary_validation_is_part_of_the_status_contract() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());
        write_required_assets(&config);
        let validation_error =
            "cached runtime binary validation failed: binary 'dockerd' not found".to_owned();

        let report = build_report(
            directory.path(),
            &config,
            Ok(manifest(false)),
            Err(validation_error.clone()),
        )
        .await;

        assert!(!report.complete);
        let runtime = report
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "runtime-binaries")
            .unwrap();
        assert!(runtime.required);
        assert!(!runtime.present);
        assert_eq!(runtime.detail.as_deref(), Some(validation_error.as_str()));
        assert_eq!(
            report.reasons,
            [format!("runtime-binaries: {validation_error}")]
        );
        let table = render_table(&report);
        assert!(table.contains("[-] runtime-binaries"));
        assert!(table.contains(&format!("Reason: runtime-binaries: {validation_error}")));
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["complete"], false);
        assert_eq!(
            json["reasons"][0],
            format!("runtime-binaries: {validation_error}")
        );
    }

    #[tokio::test]
    async fn configured_custom_kernel_is_reported_without_release_checksum_validation() {
        let directory = tempfile::tempdir().unwrap();
        let custom_kernel = directory.path().join("custom-kernel");
        let mut config = config(directory.path());
        config.custom_kernel = Some(custom_kernel.clone());
        let version_dir = config.version_cache_dir();
        std::fs::create_dir_all(&version_dir).unwrap();
        std::fs::write(version_dir.join("manifest.json"), "{}").unwrap();
        std::fs::write(version_dir.join("rootfs.erofs"), ROOTFS).unwrap();
        std::fs::write(&custom_kernel, b"custom kernel with a different checksum").unwrap();

        let report = build_report(directory.path(), &config, Ok(manifest(false)), Ok(())).await;

        assert!(report.complete);
        let kernel = report
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "kernel")
            .unwrap();
        assert_eq!(kernel.path, custom_kernel.display().to_string());
        assert!(kernel.present);
        assert_eq!(kernel.source_path, None);
        assert_eq!(kernel.version, None);
        assert_eq!(kernel.detail.as_deref(), Some("configured custom kernel"));
        let table = render_table(&report);
        assert!(table.contains(&custom_kernel.display().to_string()));
        assert!(table.contains("configured custom kernel"));
        let json = serde_json::to_value(report).unwrap();
        let kernel = json["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|artifact| artifact["name"] == "kernel")
            .unwrap();
        assert_eq!(kernel["path"], custom_kernel.display().to_string());
        assert_eq!(kernel["detail"], "configured custom kernel");

        std::fs::remove_file(&custom_kernel).unwrap();
        std::fs::create_dir(&custom_kernel).unwrap();
        let report = build_report(directory.path(), &config, Ok(manifest(false)), Ok(())).await;
        assert!(!report.complete);
        let kernel = report
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "kernel")
            .unwrap();
        assert_eq!(
            kernel.detail.as_deref(),
            Some("artifact is empty or is not a regular file")
        );
        assert!(
            report
                .reasons
                .iter()
                .any(|reason| { reason == "kernel: artifact is empty or is not a regular file" })
        );

        std::fs::remove_dir(&custom_kernel).unwrap();
        let report = build_report(directory.path(), &config, Ok(manifest(false)), Ok(())).await;
        assert!(!report.complete);
        assert!(
            report
                .reasons
                .contains(&"kernel: missing required artifact".to_owned())
        );
    }

    #[tokio::test]
    async fn runtime_binaries_remain_required_when_the_manifest_is_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let config = config(directory.path());

        let report = build_report(
            directory.path(),
            &config,
            Err("manifest pin validation failed".to_owned()),
            Err("manifest unavailable".to_owned()),
        )
        .await;

        let runtime = report
            .artifacts
            .iter()
            .find(|artifact| artifact.name == "runtime-binaries")
            .unwrap();
        assert!(runtime.required);
        assert!(!runtime.present);
        assert_eq!(runtime.version, None);
        assert_eq!(runtime.detail.as_deref(), Some("manifest unavailable"));
        assert!(
            report
                .reasons
                .contains(&"runtime-binaries: manifest unavailable".to_owned())
        );
        assert_eq!(
            report.reasons,
            [
                "manifest: manifest pin validation failed".to_owned(),
                "kernel: missing required artifact".to_owned(),
                "rootfs: missing required artifact".to_owned(),
                "runtime-binaries: manifest unavailable".to_owned(),
            ]
        );
    }
}
