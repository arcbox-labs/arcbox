//! Download URL construction and extraction logic for each Docker tool.

/// Format of the downloaded artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFormat {
    /// A `.tgz` archive; the `docker` binary lives inside at `docker/docker`.
    Tgz,
    /// A bare binary — download and use directly.
    Binary,
}

/// Returns the download URL for the given tool name, version, and architecture.
///
/// `arch` should be `"arm64"` or `"x86_64"`.
///
/// # Panics
///
/// Panics if `name` is not a known tool.
#[must_use]
pub fn download_url(name: &str, version: &str, arch: &str) -> String {
    match name {
        "docker" => {
            let docker_arch = match arch {
                "arm64" => "aarch64",
                _ => "x86_64",
            };
            format!(
                "https://download.docker.com/mac/static/stable/{docker_arch}/docker-{version}.tgz"
            )
        }
        "docker-buildx" => {
            let gh_arch = match arch {
                "arm64" => "arm64",
                _ => "amd64",
            };
            format!(
                "https://github.com/docker/buildx/releases/download/v{version}/buildx-v{version}.darwin-{gh_arch}"
            )
        }
        "docker-compose" => {
            let compose_arch = match arch {
                "arm64" => "aarch64",
                _ => "x86_64",
            };
            format!(
                "https://github.com/docker/compose/releases/download/v{version}/docker-compose-darwin-{compose_arch}"
            )
        }
        "docker-credential-osxkeychain" => {
            let gh_arch = match arch {
                "arm64" => "arm64",
                _ => "amd64",
            };
            format!(
                "https://github.com/docker/docker-credential-helpers/releases/download/v{version}/docker-credential-osxkeychain-v{version}.darwin-{gh_arch}"
            )
        }
        _ => panic!("unknown docker tool: {name}"),
    }
}

/// Returns the artifact format for a given tool name.
#[must_use]
pub fn artifact_format(name: &str) -> ArtifactFormat {
    match name {
        "docker" => ArtifactFormat::Tgz,
        _ => ArtifactFormat::Binary,
    }
}

/// Returns the name of the binary inside the archive for tgz artifacts.
/// For example, the `docker` tgz contains `docker/docker`.
#[must_use]
pub fn tgz_inner_path(name: &str) -> &'static str {
    match name {
        "docker" => "docker/docker",
        _ => panic!("no tgz inner path for {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_url_arm64() {
        let url = download_url("docker", "27.5.1", "arm64");
        assert_eq!(
            url,
            "https://download.docker.com/mac/static/stable/aarch64/docker-27.5.1.tgz"
        );
    }

    #[test]
    fn docker_url_x86() {
        let url = download_url("docker", "27.5.1", "x86_64");
        assert_eq!(
            url,
            "https://download.docker.com/mac/static/stable/x86_64/docker-27.5.1.tgz"
        );
    }

    #[test]
    fn buildx_url() {
        let url = download_url("docker-buildx", "0.21.1", "arm64");
        assert!(url.contains("buildx-v0.21.1.darwin-arm64"));
    }

    #[test]
    fn compose_url() {
        let url = download_url("docker-compose", "2.33.1", "arm64");
        assert!(url.contains("docker-compose-darwin-aarch64"));
    }

    #[test]
    fn credential_url() {
        let url = download_url("docker-credential-osxkeychain", "0.9.1", "x86_64");
        assert!(url.contains("docker-credential-osxkeychain-v0.9.1.darwin-amd64"));
    }

    #[test]
    fn artifact_formats() {
        assert_eq!(artifact_format("docker"), ArtifactFormat::Tgz);
        assert_eq!(artifact_format("docker-buildx"), ArtifactFormat::Binary);
    }
}
