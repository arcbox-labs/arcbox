//! Instance-aware CLI selection derived from explicit environment or standard paths.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use arcbox_constants::paths::{ArcboxProfile, HostLayout};

/// Returns the data root for a standard `<data>/run/docker.sock` path.
#[must_use]
pub fn data_dir_from_docker_socket(socket: &Path) -> Option<PathBuf> {
    if socket.file_name()? != "docker.sock" {
        return None;
    }
    let run_dir = socket.parent()?;
    if run_dir.file_name()? != "run" {
        return None;
    }
    run_dir.parent().map(Path::to_path_buf)
}

/// Resolves the Docker context owned by the selected runtime instance.
///
/// `ARCBOX_DOCKER_CONTEXT` is authoritative. Otherwise production and legacy
/// development use their profile names, while Desktop's standard per-instance
/// data path maps to `arcbox-dev-<instance>`.
pub fn docker_context_name() -> Result<String> {
    if let Ok(context) = std::env::var(arcbox_constants::env::DOCKER_CONTEXT)
        && !context.is_empty()
    {
        return Ok(context);
    }

    let profile = ArcboxProfile::from_env_or_default();
    let data_dir = HostLayout::from_env_or_default().data_dir;
    docker_context_name_for(profile, &data_dir).with_context(|| {
        format!(
            "cannot derive a Docker context for {}; set {} explicitly",
            data_dir.display(),
            arcbox_constants::env::DOCKER_CONTEXT
        )
    })
}

/// Derives a context name without reading process state.
#[must_use]
pub fn docker_context_name_for(profile: ArcboxProfile, data_dir: &Path) -> Option<String> {
    if let Some(instance) = development_instance_id(data_dir) {
        return Some(format!("arcbox-dev-{instance}"));
    }

    (data_dir == profile.default_data_dir()).then(|| profile.docker_context_name().to_owned())
}

/// Identifies Desktop's standard isolated development data path.
#[must_use]
pub fn is_development_instance(data_dir: &Path) -> bool {
    development_instance_id(data_dir).is_some()
}

fn development_instance_id(data_dir: &Path) -> Option<&str> {
    let instance = data_dir.file_name()?.to_str()?;
    let instances = data_dir.parent()?;
    let development_root = instances.parent()?;
    (instances.file_name()? == "instances"
        && development_root.file_name()? == ".arcbox-dev"
        && valid_instance_id(instance))
    .then_some(instance)
}

fn valid_instance_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_socket_and_instance_path_select_one_runtime_tuple() {
        let socket = Path::new("/Users/test/.arcbox-dev/instances/worktree-1/run/docker.sock");
        let data_dir = data_dir_from_docker_socket(socket).unwrap();

        assert_eq!(
            data_dir,
            Path::new("/Users/test/.arcbox-dev/instances/worktree-1")
        );
        assert_eq!(
            docker_context_name_for(ArcboxProfile::Development, &data_dir).as_deref(),
            Some("arcbox-dev-worktree-1")
        );
        assert_eq!(
            docker_context_name_for(ArcboxProfile::Production, &data_dir).as_deref(),
            Some("arcbox-dev-worktree-1")
        );
        assert!(is_development_instance(&data_dir));
        assert!(data_dir_from_docker_socket(Path::new("/tmp/custom.sock")).is_none());
        assert!(
            docker_context_name_for(
                ArcboxProfile::Development,
                Path::new("/tmp/arbitrary-development")
            )
            .is_none()
        );
    }
}
