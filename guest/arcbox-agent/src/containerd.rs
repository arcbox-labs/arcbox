//! Minimal containerd snapshots-service client.
//!
//! Resolves a container's overlayfs snapshot directories by asking containerd
//! for the snapshot's mount spec. With dockerd's containerd image store the
//! layer data lives under `/var/lib/containerd` and `docker inspect` exposes
//! no `GraphDriver` paths, so this is the only supported way to map a
//! container to its filesystem layers (the snapshotter's bolt metadata is
//! private and unsafe to read while containerd is live).
//!
//! Only the one unary method this needs is implemented, against hand-written
//! prost mirrors of the stable containerd API messages — no vendored protos,
//! no build-time codegen.

use prost::Message;

/// Mirrors `containerd.types.Mount`
/// (containerd `api/types/mount.proto`).
#[derive(Clone, PartialEq, Message)]
pub struct Mount {
    #[prost(string, tag = "1")]
    pub r#type: String,
    #[prost(string, tag = "2")]
    pub source: String,
    #[prost(string, tag = "3")]
    pub target: String,
    #[prost(string, repeated, tag = "4")]
    pub options: Vec<String>,
}

/// Mirrors `containerd.services.snapshots.v1.MountsRequest`
/// (containerd `api/services/snapshots/v1/snapshots.proto`).
#[derive(Clone, PartialEq, Message)]
pub struct MountsRequest {
    #[prost(string, tag = "1")]
    pub snapshotter: String,
    #[prost(string, tag = "2")]
    pub key: String,
}

/// Mirrors `containerd.services.snapshots.v1.MountsResponse`.
#[derive(Clone, PartialEq, Message)]
pub struct MountsResponse {
    #[prost(message, repeated, tag = "1")]
    pub mounts: Vec<Mount>,
}

/// Mirrors `containerd.services.snapshots.v1.ViewSnapshotRequest` (the
/// `labels` map field is deliberately omitted — unused, and proto3 treats
/// an absent field as empty).
#[derive(Clone, PartialEq, Message)]
pub struct ViewSnapshotRequest {
    #[prost(string, tag = "1")]
    pub snapshotter: String,
    #[prost(string, tag = "2")]
    pub key: String,
    #[prost(string, tag = "3")]
    pub parent: String,
}

/// Mirrors `containerd.services.snapshots.v1.ViewSnapshotResponse`.
#[derive(Clone, PartialEq, Message)]
pub struct ViewSnapshotResponse {
    #[prost(message, repeated, tag = "1")]
    pub mounts: Vec<Mount>,
}

/// Mirrors `containerd.services.snapshots.v1.RemoveSnapshotRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct RemoveSnapshotRequest {
    #[prost(string, tag = "1")]
    pub snapshotter: String,
    #[prost(string, tag = "2")]
    pub key: String,
}

/// Mirrors `google.protobuf.Empty` (the Remove response).
#[derive(Clone, PartialEq, Message)]
pub struct Empty {}

/// A snapshot's filesystem layer directories, top-most lower first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPaths {
    /// The writable layer; `None` for read-only views.
    pub upper_dir: Option<String>,
    pub lower_dirs: Vec<String>,
}

/// Extracts the layer directories from a snapshot mount spec.
///
/// The overlayfs snapshotter returns exactly one mount: `overlay` with
/// `upperdir=`/`lowerdir=` options for layered snapshots, or a plain `bind`
/// of the single layer directory when there is no parent (read-only bind for
/// views, writable for active snapshots).
pub fn parse_snapshot_paths(mounts: &[Mount]) -> Result<SnapshotPaths, String> {
    let mount = mounts
        .first()
        .ok_or_else(|| "snapshot mount spec is empty".to_string())?;

    match mount.r#type.as_str() {
        "overlay" => {
            let mut upper_dir = None;
            let mut lower_dirs = Vec::new();
            for option in &mount.options {
                if let Some(upper) = option.strip_prefix("upperdir=") {
                    upper_dir = Some(upper.to_string());
                } else if let Some(lowers) = option.strip_prefix("lowerdir=") {
                    lower_dirs = lowers.split(':').map(str::to_string).collect();
                }
            }
            if upper_dir.is_none() && lower_dirs.is_empty() {
                return Err(format!(
                    "overlay mount carries neither upperdir nor lowerdir: {:?}",
                    mount.options
                ));
            }
            Ok(SnapshotPaths {
                upper_dir,
                lower_dirs,
            })
        }
        "bind" | "rbind" => {
            if mount.options.iter().any(|o| o == "ro") {
                Ok(SnapshotPaths {
                    upper_dir: None,
                    lower_dirs: vec![mount.source.clone()],
                })
            } else {
                Ok(SnapshotPaths {
                    upper_dir: Some(mount.source.clone()),
                    lower_dirs: Vec::new(),
                })
            }
        }
        other => Err(format!("unsupported snapshot mount type '{other}'")),
    }
}

#[cfg(target_os = "linux")]
mod client {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use arcbox_constants::paths::CONTAINERD_SOCKET;
    use http::Uri;
    use http::uri::PathAndQuery;
    use hyper_util::rt::TokioIo;
    use tokio::net::UnixStream;
    use tonic::transport::Endpoint;
    use tower::Service;

    use super::{
        MountsRequest, RemoveSnapshotRequest, SnapshotPaths, ViewSnapshotRequest,
        parse_snapshot_paths,
    };

    /// dockerd runs everything in the fixed `moby` containerd namespace.
    const NAMESPACE: &str = "moby";
    /// The snapshotter dockerd's containerd image store uses on this guest;
    /// its snapshot key for a container is the container ID, and for an
    /// image layer chain the top layer's chain ID (`sha256:<digest>`).
    const SNAPSHOTTER: &str = "overlayfs";

    /// Resolves a container's snapshot layer directories via containerd.
    pub async fn container_snapshot_paths(container_id: &str) -> Result<SnapshotPaths, String> {
        let mut grpc = connect().await?;
        let response: super::MountsResponse = unary(
            &mut grpc,
            "/containerd.services.snapshots.v1.Snapshots/Mounts",
            MountsRequest {
                snapshotter: SNAPSHOTTER.to_string(),
                key: container_id.to_string(),
            },
        )
        .await
        .map_err(|e| format!("snapshots.Mounts({container_id}) failed: {e}"))?;

        parse_snapshot_paths(&response.mounts)
    }

    /// Resolves an image's layer directories via containerd.
    ///
    /// Committed snapshots have no mount spec of their own, so this creates
    /// an ephemeral read-only View child of the image's top chain-ID
    /// snapshot, reads the layer directories off the View's mounts, and
    /// removes the View again. The returned directories belong to the
    /// committed parents and outlive the View.
    pub async fn image_snapshot_paths(top_chain_id: &str) -> Result<SnapshotPaths, String> {
        let mut grpc = connect().await?;
        let view_key = format!("arcbox-browse-{}", uuid::Uuid::new_v4());

        let response: super::ViewSnapshotResponse = unary(
            &mut grpc,
            "/containerd.services.snapshots.v1.Snapshots/View",
            ViewSnapshotRequest {
                snapshotter: SNAPSHOTTER.to_string(),
                key: view_key.clone(),
                parent: top_chain_id.to_string(),
            },
        )
        .await
        .map_err(|e| format!("snapshots.View({top_chain_id}) failed: {e}"))?;

        // Best-effort: a leaked view is inert metadata and the next GC or a
        // retried browse never depends on it being gone.
        let removed: Result<super::Empty, String> = unary(
            &mut grpc,
            "/containerd.services.snapshots.v1.Snapshots/Remove",
            RemoveSnapshotRequest {
                snapshotter: SNAPSHOTTER.to_string(),
                key: view_key.clone(),
            },
        )
        .await;
        if let Err(e) = removed {
            tracing::warn!(view_key, error = %e, "failed to remove browse view snapshot");
        }

        parse_snapshot_paths(&response.mounts)
    }

    /// Connects to the containerd socket and waits for service readiness.
    async fn connect() -> Result<tonic::client::Grpc<tonic::transport::Channel>, String> {
        // The URI is required by the HTTP/2 layer but unused: the connector
        // dials the fixed containerd Unix socket.
        let channel = Endpoint::from_static("http://[::1]")
            .connect_with_connector(UnixConnector)
            .await
            .map_err(|e| format!("connect {CONTAINERD_SOCKET} failed({e})"))?;

        let mut grpc = tonic::client::Grpc::new(channel);
        grpc.ready()
            .await
            .map_err(|e| format!("containerd not ready({e})"))?;
        Ok(grpc)
    }

    /// One unary call in the moby namespace.
    async fn unary<Req, Resp>(
        grpc: &mut tonic::client::Grpc<tonic::transport::Channel>,
        path: &'static str,
        message: Req,
    ) -> Result<Resp, String>
    where
        Req: prost::Message + 'static,
        Resp: prost::Message + Default + 'static,
    {
        grpc.ready()
            .await
            .map_err(|e| format!("containerd not ready({e})"))?;
        let mut request = tonic::Request::new(message);
        request.metadata_mut().insert(
            "containerd-namespace",
            NAMESPACE.parse().expect("static namespace is valid ascii"),
        );

        let response: tonic::Response<Resp> = grpc
            .unary(
                request,
                PathAndQuery::from_static(path),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map_err(|status| format!("{} {}", status.code(), status.message()))?;
        Ok(response.into_inner())
    }

    /// Minimal tower connector dialing the fixed containerd Unix socket.
    struct UnixConnector;

    impl Service<Uri> for UnixConnector {
        type Response = TokioIo<UnixStream>;
        type Error = std::io::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: Uri) -> Self::Future {
            Box::pin(async {
                let stream = UnixStream::connect(CONTAINERD_SOCKET).await?;
                Ok(TokioIo::new(stream))
            })
        }
    }
}

#[cfg(target_os = "linux")]
pub use client::{container_snapshot_paths, image_snapshot_paths};

#[cfg(test)]
mod tests {
    use super::{Mount, parse_snapshot_paths};

    fn overlay_mount(options: &[&str]) -> Mount {
        Mount {
            r#type: "overlay".to_string(),
            source: "overlay".to_string(),
            target: String::new(),
            options: options.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn overlay_mount_yields_upper_and_ordered_lowers() {
        let mounts = [overlay_mount(&[
            "index=off",
            "workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/269/work",
            "upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/269/fs",
            "lowerdir=/s/265/fs:/s/247/fs:/s/211/fs",
        ])];
        let paths = parse_snapshot_paths(&mounts).expect("valid overlay mount");
        assert_eq!(
            paths.upper_dir.as_deref(),
            Some("/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/269/fs")
        );
        assert_eq!(paths.lower_dirs, ["/s/265/fs", "/s/247/fs", "/s/211/fs"]);
    }

    #[test]
    fn overlay_view_without_upperdir_is_lowers_only() {
        let mounts = [overlay_mount(&["lowerdir=/s/1/fs:/s/2/fs"])];
        let paths = parse_snapshot_paths(&mounts).expect("valid view mount");
        assert_eq!(paths.upper_dir, None);
        assert_eq!(paths.lower_dirs, ["/s/1/fs", "/s/2/fs"]);
    }

    #[test]
    fn writable_bind_mount_is_the_upper_layer() {
        let mounts = [Mount {
            r#type: "bind".to_string(),
            source: "/s/7/fs".to_string(),
            target: String::new(),
            options: vec!["rbind".to_string(), "rw".to_string()],
        }];
        let paths = parse_snapshot_paths(&mounts).expect("valid bind mount");
        assert_eq!(paths.upper_dir.as_deref(), Some("/s/7/fs"));
        assert!(paths.lower_dirs.is_empty());
    }

    #[test]
    fn readonly_bind_mount_is_a_single_lower() {
        let mounts = [Mount {
            r#type: "bind".to_string(),
            source: "/s/7/fs".to_string(),
            target: String::new(),
            options: vec!["rbind".to_string(), "ro".to_string()],
        }];
        let paths = parse_snapshot_paths(&mounts).expect("valid bind mount");
        assert_eq!(paths.upper_dir, None);
        assert_eq!(paths.lower_dirs, ["/s/7/fs"]);
    }

    #[test]
    fn empty_mounts_and_unknown_types_error() {
        assert!(parse_snapshot_paths(&[]).is_err());
        let mounts = [Mount {
            r#type: "erofs".to_string(),
            source: "/dev/loop0".to_string(),
            target: String::new(),
            options: Vec::new(),
        }];
        assert!(parse_snapshot_paths(&mounts).is_err());
        let mounts = [overlay_mount(&["index=off"])];
        assert!(parse_snapshot_paths(&mounts).is_err());
    }
}
