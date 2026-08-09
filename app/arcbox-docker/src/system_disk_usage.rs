//! Host-side Docker disk-usage query.

use std::path::Path;
use std::time::Duration;

use arcbox_error::CommonError;
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

use crate::{DockerError, Result};

const SYSTEM_DISK_USAGE_PATH: &str = "/v1.52/system/df";
const SYSTEM_DISK_USAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bytes Docker reports as removable by its supported cleanup operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct DockerReclaimableSpace {
    /// Bytes held by unused images.
    pub images_bytes: u64,
    /// Bytes held by inactive containers.
    pub containers_bytes: u64,
    /// Bytes held by unused volumes.
    pub volumes_bytes: u64,
    /// Bytes held by unused build cache.
    pub build_cache_bytes: u64,
    /// Checked sum of all reclaimable categories.
    pub total_bytes: u64,
}

#[derive(Deserialize)]
struct SystemDiskUsageResponse {
    #[serde(rename = "ImageUsage")]
    images: ReclaimableUsage,
    #[serde(rename = "ContainerUsage")]
    containers: ReclaimableUsage,
    #[serde(rename = "VolumeUsage")]
    volumes: ReclaimableUsage,
    #[serde(rename = "BuildCacheUsage")]
    build_cache: ReclaimableUsage,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ReclaimableUsage {
    #[serde(default)]
    reclaimable: u64,
}

impl TryFrom<SystemDiskUsageResponse> for DockerReclaimableSpace {
    type Error = DockerError;

    fn try_from(response: SystemDiskUsageResponse) -> Result<Self> {
        let values = [
            response.images.reclaimable,
            response.containers.reclaimable,
            response.volumes.reclaimable,
            response.build_cache.reclaimable,
        ];
        let total_bytes = values
            .into_iter()
            .try_fold(0_u64, u64::checked_add)
            .ok_or_else(|| CommonError::internal("Docker reclaimable byte total overflowed u64"))?;

        Ok(Self {
            images_bytes: values[0],
            containers_bytes: values[1],
            volumes_bytes: values[2],
            build_cache_bytes: values[3],
            total_bytes,
        })
    }
}

/// Queries Docker's server-computed reclaimable byte counts over a Unix socket.
///
/// # Errors
///
/// Returns an error when the socket transport, HTTP response, response schema,
/// or checked category total is invalid.
pub async fn query_reclaimable_space(socket_path: &Path) -> Result<DockerReclaimableSpace> {
    query_reclaimable_space_with_timeout(socket_path, SYSTEM_DISK_USAGE_TIMEOUT).await
}

async fn query_reclaimable_space_with_timeout(
    socket_path: &Path,
    deadline: Duration,
) -> Result<DockerReclaimableSpace> {
    tokio::time::timeout(deadline, query_reclaimable_space_inner(socket_path))
        .await
        .map_err(|_| {
            CommonError::internal(format!(
                "Docker disk-usage request timed out after {} seconds",
                deadline.as_secs_f64()
            ))
        })?
}

async fn query_reclaimable_space_inner(socket_path: &Path) -> Result<DockerReclaimableSpace> {
    let stream = UnixStream::connect(socket_path).await.map_err(|error| {
        CommonError::internal(format!("connect {}: {error}", socket_path.display()))
    })?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|error| CommonError::internal(format!("Docker HTTP handshake failed: {error}")))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "Docker disk-usage connection closed");
        }
    });

    let request = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(SYSTEM_DISK_USAGE_PATH)
        .header(hyper::header::HOST, "localhost")
        .body(Empty::<Bytes>::new())
        .map_err(|error| {
            CommonError::internal(format!("build Docker disk-usage request: {error}"))
        })?;
    let response = sender.send_request(request).await.map_err(|error| {
        CommonError::internal(format!("send Docker disk-usage request: {error}"))
    })?;
    if !response.status().is_success() {
        return Err(DockerError::Server(format!(
            "Docker disk-usage request returned HTTP {}",
            response.status()
        )));
    }

    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|error| {
            CommonError::internal(format!("read Docker disk-usage response: {error}"))
        })?
        .to_bytes();
    parse_reclaimable_space(&body)
}

fn parse_reclaimable_space(body: &[u8]) -> Result<DockerReclaimableSpace> {
    let response: SystemDiskUsageResponse = serde_json::from_slice(body).map_err(|error| {
        CommonError::internal(format!("parse Docker disk-usage response: {error}"))
    })?;
    DockerReclaimableSpace::try_from(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_checked_sums_reclaimable_categories() {
        let usage = parse_reclaimable_space(
            br#"{
                "ImageUsage": {"Reclaimable": 11},
                "ContainerUsage": {"Reclaimable": 22},
                "VolumeUsage": {"Reclaimable": 33},
                "BuildCacheUsage": {"Reclaimable": 44}
            }"#,
        )
        .unwrap();

        assert_eq!(
            usage,
            DockerReclaimableSpace {
                images_bytes: 11,
                containers_bytes: 22,
                volumes_bytes: 33,
                build_cache_bytes: 44,
                total_bytes: 110,
            }
        );
    }

    #[test]
    fn treats_omitted_reclaimable_field_as_zero() {
        let usage = parse_reclaimable_space(
            br#"{
                "ImageUsage": {"Reclaimable": 11},
                "ContainerUsage": {},
                "VolumeUsage": {"Reclaimable": 33},
                "BuildCacheUsage": {"Reclaimable": 44}
            }"#,
        )
        .unwrap();

        assert_eq!(usage.containers_bytes, 0);
        assert_eq!(usage.total_bytes, 88);
    }

    #[test]
    fn rejects_overflowing_reclaimable_total() {
        let body = format!(
            r#"{{
                "ImageUsage": {{"Reclaimable": {}}},
                "ContainerUsage": {{"Reclaimable": 1}},
                "VolumeUsage": {{"Reclaimable": 0}},
                "BuildCacheUsage": {{"Reclaimable": 0}}
            }}"#,
            u64::MAX
        );

        assert!(parse_reclaimable_space(body.as_bytes()).is_err());
    }

    #[test]
    fn rejects_missing_reclaimable_category() {
        assert!(
            parse_reclaimable_space(
                br#"{
                    "ImageUsage": {"Reclaimable": 11},
                    "ContainerUsage": {"Reclaimable": 22},
                    "VolumeUsage": {"Reclaimable": 33}
                }"#
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn times_out_an_unresponsive_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });

        let error = query_reclaimable_space_with_timeout(&socket, Duration::from_millis(20))
            .await
            .unwrap_err();
        server.abort();

        assert!(error.to_string().contains("timed out"));
    }
}
