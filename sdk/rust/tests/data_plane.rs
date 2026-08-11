//! Files, ports, snapshots and events against a mock daemon on a real
//! Unix socket.
//!
//! The contracts under test: the write protocol (open + chunks + done,
//! mode defaulted), read collection, path-verb request shapes and stat
//! mapping, watch keepalive filtering and clean end, wait_for_port's
//! timeout naming, expose/list port mapping, the checkpoint echo row,
//! restore's minted id + leak cleanup, snapshot pagination, and event
//! mapping.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use arcbox::{
    ArcBox, CheckpointOptions, ConnectOptions, Connection, ExposeOptions, FileKind, FsEventKind,
    ListSnapshotsOptions, MkdirOptions, Protocol, RemoveOptions, RestoreOptions, SandboxEventKind,
    WatchOptions, WriteOptions,
};
use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{watch_dir_response, watch_events_response, write_file_request};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

type Frames<T> = Vec<Result<T, ConnectError>>;
type BoxStream<T> =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<T, ConnectError>> + Send>>;

fn empty() -> buffa_types::google::protobuf::Empty {
    buffa_types::google::protobuf::Empty::default()
}

#[derive(Default)]
struct MockDaemon {
    // Filesystem.
    write_frames: Mutex<Vec<pb::WriteFileRequest>>,
    read_chunks: Mutex<Vec<pb::FileChunk>>,
    stats: Mutex<Vec<pb::StatFileRequest>>,
    removes: Mutex<Vec<pb::RemoveEntryRequest>>,
    moves: Mutex<Vec<pb::MoveEntryRequest>>,
    mkdirs: Mutex<Vec<pb::MakeDirRequest>>,
    watch_frames: Mutex<Frames<pb::WatchDirResponse>>,
    // Ports.
    wait_ports: Mutex<Vec<pb::WaitForPortRequest>>,
    fail_wait_port: Mutex<Option<ConnectError>>,
    exposes: Mutex<Vec<pb::ExposePortRequest>>,
    // Snapshots.
    checkpoints: Mutex<Vec<pb::CheckpointRequest>>,
    restores: Mutex<Vec<pb::RestoreRequest>>,
    fail_restore: Mutex<Option<ConnectError>>,
    snapshot_removes: Mutex<Vec<pb::RemoveSandboxRequest>>,
    deletes: Mutex<Vec<pb::DeleteSnapshotRequest>>,
    // Events.
    event_frames: Mutex<Frames<pb::WatchEventsResponse>>,
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and this mock is registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxFilesystemService for MockDaemon {
    async fn read_file(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ReadFileRequest>,
    ) -> ServiceResult<BoxStream<pb::FileChunk>> {
        let frames: Frames<pb::FileChunk> = self
            .read_chunks
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(Ok)
            .collect();
        Response::ok(Box::pin(tokio_stream::iter(frames)))
    }

    async fn write_file(
        &self,
        _ctx: RequestContext,
        mut requests: connectrpc::InboundStream<pb::WriteFileRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        use tokio_stream::StreamExt as _;
        while let Some(frame) = requests.next().await {
            self.write_frames
                .lock()
                .unwrap()
                .push(frame?.to_owned_message());
        }
        Response::ok(empty())
    }

    async fn stat(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::StatFileRequest>,
    ) -> ServiceResult<pb::FileStat> {
        self.stats.lock().unwrap().push(request.to_owned_message());
        Response::ok(pb::FileStat {
            name: "hello.txt".into(),
            kind: pb::FileKind::FILE_KIND_FILE.into(),
            size: 5,
            mode: 0o644,
            uid: 1000,
            gid: 1000,
            ..Default::default()
        })
    }

    async fn list_dir(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListDirRequest>,
    ) -> ServiceResult<pb::ListDirResponse> {
        Response::ok(pb::ListDirResponse {
            entries: vec![
                pb::FileStat {
                    name: "a.txt".into(),
                    kind: pb::FileKind::FILE_KIND_FILE.into(),
                    size: 3,
                    ..Default::default()
                },
                pb::FileStat {
                    name: "link".into(),
                    kind: pb::FileKind::FILE_KIND_SYMLINK.into(),
                    symlink_target: "/etc/hosts".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        })
    }

    async fn make_dir(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MakeDirRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.mkdirs.lock().unwrap().push(request.to_owned_message());
        Response::ok(empty())
    }

    async fn remove(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveEntryRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.removes
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(empty())
    }

    async fn r#move(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::MoveEntryRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.moves.lock().unwrap().push(request.to_owned_message());
        Response::ok(empty())
    }

    async fn watch_dir(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WatchDirRequest>,
    ) -> ServiceResult<BoxStream<pb::WatchDirResponse>> {
        let frames = std::mem::take(&mut *self.watch_frames.lock().unwrap());
        Response::ok(Box::pin(tokio_stream::iter(frames)))
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and this mock is registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxSnapshotService for MockDaemon {
    async fn checkpoint(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::CheckpointRequest>,
    ) -> ServiceResult<pb::CheckpointResponse> {
        self.checkpoints
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(pb::CheckpointResponse {
            snapshot_id: "snap-1".into(),
            ..Default::default()
        })
    }

    async fn restore(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::RestoreRequest>,
    ) -> ServiceResult<pb::RestoreResponse> {
        let request = request.to_owned_message();
        self.restores.lock().unwrap().push(request.clone());
        let failure = self.fail_restore.lock().unwrap().take();
        if let Some(error) = failure {
            return Err(error);
        }
        Response::ok(pb::RestoreResponse {
            id: request.id,
            ip_address: "192.168.64.7".into(),
            ..Default::default()
        })
    }

    async fn list_snapshots(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListSnapshotsRequest>,
    ) -> ServiceResult<pb::ListSnapshotsResponse> {
        let token = request.to_owned_message().page_token;
        if token.is_empty() {
            Response::ok(pb::ListSnapshotsResponse {
                snapshots: vec![pb::SnapshotSummary {
                    id: "snap-1".into(),
                    sandbox_id: "sb-1".into(),
                    name: "warm-base".into(),
                    ..Default::default()
                }],
                next_page_token: "page-2".into(),
                ..Default::default()
            })
        } else {
            Response::ok(pb::ListSnapshotsResponse {
                snapshots: vec![pb::SnapshotSummary {
                    id: "snap-2".into(),
                    sandbox_id: "sb-2".into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
        }
    }

    async fn delete_snapshot(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::DeleteSnapshotRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.deletes
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(empty())
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and this mock is registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxProcessService for MockDaemon {
    async fn start_execution(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::StartExecutionRequest>,
    ) -> ServiceResult<pb::Execution> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn attach_execution(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::AttachExecutionRequest>,
    ) -> ServiceResult<BoxStream<pb::ExecutionEvent>> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn write_stdin(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WriteStdinRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn stream_stdin(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<pb::WriteStdinRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn get_stdin_status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetStdinStatusRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn signal_execution(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::SignalExecutionRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn resize_execution_tty(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ResizeExecutionTtyRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn wait_execution(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WaitExecutionRequest>,
    ) -> ServiceResult<pb::Execution> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn list_executions(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListExecutionsRequest>,
    ) -> ServiceResult<pb::ListExecutionsResponse> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn wait_for_port(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::WaitForPortRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.wait_ports
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        let failure = self.fail_wait_port.lock().unwrap().take();
        if let Some(error) = failure {
            return Err(error);
        }
        Response::ok(empty())
    }
}

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and this mock is registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxService for MockDaemon {
    async fn create(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::CreateSandboxRequest>,
    ) -> ServiceResult<pb::CreateSandboxResponse> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn stop(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::StopSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn remove(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.snapshot_removes
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(empty())
    }
    async fn pause(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::PauseSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn resume(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ResumeSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn set_lifecycle(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::SetLifecycleRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn get_capabilities(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetCapabilitiesRequest>,
    ) -> ServiceResult<pb::GetCapabilitiesResponse> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn inspect(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::InspectSandboxRequest>,
    ) -> ServiceResult<pb::SandboxInfo> {
        Response::ok(pb::SandboxInfo {
            id: request.to_owned_message().id,
            state: pb::SandboxState::SANDBOX_STATE_READY.into(),
            ..Default::default()
        })
    }
    async fn list(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListSandboxesRequest>,
    ) -> ServiceResult<pb::ListSandboxesResponse> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn events(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::SandboxEventsRequest>,
    ) -> ServiceResult<BoxStream<pb::WatchEventsResponse>> {
        let frames = std::mem::take(&mut *self.event_frames.lock().unwrap());
        Response::ok(Box::pin(tokio_stream::iter(frames)))
    }
    async fn expose_port(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ExposePortRequest>,
    ) -> ServiceResult<pb::ExposePortResponse> {
        self.exposes
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(pb::ExposePortResponse {
            host_port: 49152,
            guest_port: 61000,
            ..Default::default()
        })
    }
    async fn unexpose_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::UnexposePortRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Response::ok(empty())
    }
    async fn list_exposed_ports(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListExposedPortsRequest>,
    ) -> ServiceResult<pb::ListExposedPortsResponse> {
        Response::ok(pb::ListExposedPortsResponse {
            ports: vec![
                pb::ExposedPort {
                    sandbox_port: 8080,
                    host_port: 49152,
                    protocol: pb::PortProtocol::PORT_PROTOCOL_TCP.into(),
                    ..Default::default()
                },
                // UNSPECIFIED decodes as tcp.
                pb::ExposedPort {
                    sandbox_port: 9000,
                    host_port: 49153,
                    ..Default::default()
                },
            ],
            ..Default::default()
        })
    }
}

async fn serve(mock: Arc<MockDaemon>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let app = connectrpc::Router::new()
        .add_service::<_, pb::SandboxServiceRegisterMarker>(mock.clone())
        .add_service::<_, pb::SandboxProcessServiceRegisterMarker>(mock.clone())
        .add_service::<_, pb::SandboxFilesystemServiceRegisterMarker>(mock.clone())
        .add_service::<_, pb::SandboxSnapshotServiceRegisterMarker>(mock)
        .into_axum_router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, path)
}

async fn sandbox_for(path: &PathBuf) -> arcbox::Sandbox {
    ArcBox::with_connection(&Connection::new().socket_path(path))
        .unwrap()
        .connect("sb-1", ConnectOptions::default())
        .await
        .unwrap()
}

#[tokio::test]
async fn write_streams_open_chunks_done_with_the_default_mode() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;

    sandbox_for(&path)
        .await
        .files()
        .write("/tmp/hello.txt", "hello", WriteOptions::default())
        .await
        .unwrap();

    let frames = mock.write_frames.lock().unwrap();
    let Some(write_file_request::Payload::Open(open)) = &frames[0].payload else {
        panic!("first frame must be the open");
    };
    assert_eq!(open.path, "/tmp/hello.txt");
    assert_eq!(open.mode, 0o644);
    let Some(write_file_request::Payload::Chunk(chunk)) = &frames[1].payload else {
        panic!("second frame must be data");
    };
    assert_eq!(chunk.data, b"hello");
    assert!(!chunk.done);
    let Some(write_file_request::Payload::Chunk(last)) = &frames[2].payload else {
        panic!("last frame must be the done marker");
    };
    assert!(last.done);
}

#[tokio::test]
async fn read_collects_chunks_until_done() {
    let mock = Arc::new(MockDaemon::default());
    *mock.read_chunks.lock().unwrap() = vec![
        pb::FileChunk {
            data: b"hel".to_vec(),
            ..Default::default()
        },
        pb::FileChunk {
            data: b"lo".to_vec(),
            done: true,
            ..Default::default()
        },
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let content = sandbox_for(&path)
        .await
        .files()
        .read("/tmp/hello.txt")
        .await
        .unwrap();

    assert_eq!(content, b"hello");
}

#[tokio::test]
async fn a_read_stream_that_ends_without_done_is_an_error() {
    let mock = Arc::new(MockDaemon::default());
    // A prefix without the done marker: the transfer was cut short.
    *mock.read_chunks.lock().unwrap() = vec![pb::FileChunk {
        data: b"hel".to_vec(),
        ..Default::default()
    }];
    let (_dir, path) = serve(mock.clone()).await;

    let error = sandbox_for(&path)
        .await
        .files()
        .read("/tmp/hello.txt")
        .await
        .unwrap_err();

    assert_eq!(error.kind(), arcbox::ErrorKind::ConnectionLost);
}

#[tokio::test]
async fn path_verbs_carry_their_shapes_and_stat_maps() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;
    let files = sandbox_for(&path).await.files();

    let stat = files.stat("/tmp/hello.txt").await.unwrap();
    assert_eq!(stat.kind, FileKind::File);
    assert_eq!(stat.size, 5);
    assert_eq!(stat.symlink_target, None);

    let entries = files.list("/tmp").await.unwrap();
    assert_eq!(entries[1].kind, FileKind::Symlink);
    assert_eq!(entries[1].symlink_target.as_deref(), Some("/etc/hosts"));

    files
        .mkdir("/tmp/sub", MkdirOptions { mode: Some(0o700) })
        .await
        .unwrap();
    files
        .remove("/tmp/sub", RemoveOptions { recursive: true })
        .await
        .unwrap();
    files.rename("/tmp/a", "/tmp/b").await.unwrap();

    assert_eq!(mock.mkdirs.lock().unwrap()[0].mode, 0o700);
    assert!(mock.removes.lock().unwrap()[0].recursive);
    let moves = mock.moves.lock().unwrap();
    assert_eq!(moves[0].from_path, "/tmp/a");
    assert_eq!(moves[0].to_path, "/tmp/b");
}

#[tokio::test]
async fn watch_filters_keepalives_and_ends_cleanly() {
    let mock = Arc::new(MockDaemon::default());
    *mock.watch_frames.lock().unwrap() = vec![
        Ok(pb::WatchDirResponse {
            payload: Some(watch_dir_response::Payload::from(pb::KeepAlive::default())),
            ..Default::default()
        }),
        Ok(pb::WatchDirResponse {
            payload: Some(watch_dir_response::Payload::from(pb::FsEvent {
                kind: pb::FsEventKind::FS_EVENT_KIND_RENAMED.into(),
                path: "/w/old".into(),
                renamed_to: "/w/new".into(),
                ..Default::default()
            })),
            ..Default::default()
        }),
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let files = sandbox_for(&path).await.files();
    let mut watch = files.watch("/w", WatchOptions { recursive: true });
    let event = watch.next().await.unwrap().unwrap();
    assert_eq!(event.kind, FsEventKind::Renamed);
    assert_eq!(event.path, "/w/old");
    assert_eq!(event.renamed_to.as_deref(), Some("/w/new"));
    // The daemon ending the stream is the clean end (sandbox stopped).
    assert!(watch.next().await.unwrap().is_none());
}

#[tokio::test]
async fn wait_for_port_names_its_own_timeout() {
    let mock = Arc::new(MockDaemon::default());
    *mock.fail_wait_port.lock().unwrap() = Some(ConnectError::deadline_exceeded(
        "no listener on port 8080 within 10s",
    ));
    let (_dir, path) = serve(mock.clone()).await;

    let ports = sandbox_for(&path).await.ports();
    let error = ports
        .wait_for_port(8080, Some(Duration::from_secs(10)))
        .await
        .unwrap_err();

    assert_eq!(error.kind(), arcbox::ErrorKind::Timeout);
    assert!(error.to_string().contains("wait_for_port(timeout)"));
    assert_eq!(mock.wait_ports.lock().unwrap()[0].timeout_seconds, 10);
}

#[tokio::test]
async fn expose_and_list_map_the_port_shapes() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;
    let ports = sandbox_for(&path).await.ports();

    let mapping = ports.expose(8080, ExposeOptions::default()).await.unwrap();
    assert_eq!(mapping.host_port, 49152);
    // The mapping's identity is the caller's sandbox port — the
    // response's guest_port (61000 here) is the DNAT relay, never the
    // sandbox port.
    assert_eq!(mapping.sandbox_port, 8080);
    assert_eq!(mapping.protocol, Protocol::Tcp);
    // The wire never carries UNSPECIFIED outbound.
    assert_eq!(
        mock.exposes.lock().unwrap()[0].protocol.as_known(),
        Some(pb::PortProtocol::PORT_PROTOCOL_TCP)
    );

    let listed = ports.list().await.unwrap();
    assert_eq!(listed.len(), 2);
    // Inbound UNSPECIFIED decodes as tcp.
    assert_eq!(listed[1].protocol, Protocol::Tcp);
    assert_eq!(listed[1].sandbox_port, 9000);
}

#[tokio::test]
async fn checkpoint_returns_the_echoed_catalog_row() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;

    let snapshot = sandbox_for(&path)
        .await
        .checkpoint(CheckpointOptions {
            name: Some("warm-base".into()),
            labels: [("tier".to_owned(), "warm".to_owned())].into(),
        })
        .await
        .unwrap();

    assert_eq!(snapshot.id, "snap-1");
    assert_eq!(snapshot.sandbox_id, "sb-1");
    assert_eq!(snapshot.name, "warm-base");
    assert_eq!(
        snapshot.labels.get("tier").map(String::as_str),
        Some("warm")
    );
    let requests = mock.checkpoints.lock().unwrap();
    assert_eq!(requests[0].name, "warm-base");
}

#[tokio::test]
async fn restore_mints_the_id_and_cleans_up_on_failure() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;
    let client = ArcBox::with_connection(&Connection::new().socket_path(&path)).unwrap();

    let sandbox = client
        .restore(
            "snap-1",
            RestoreOptions {
                ttl: Some(Duration::from_millis(90_500)),
                fresh_network: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    {
        let requests = mock.restores.lock().unwrap();
        assert_eq!(requests[0].snapshot_id, "snap-1");
        assert!(requests[0].network_override);
        // Milliseconds round UP to whole wire seconds.
        assert_eq!(requests[0].ttl_seconds, 91);
        // The handle's identity is the client-minted UUID the wire saw.
        assert_eq!(sandbox.id(), requests[0].id);
        uuid::Uuid::parse_str(sandbox.id()).unwrap();
    }

    // A failed restore force-removes the minted id — the create() rule.
    *mock.fail_restore.lock().unwrap() = Some(ConnectError::not_found("snapshot gone"));
    let error = client
        .restore("snap-9", RestoreOptions::default())
        .await
        .unwrap_err();
    assert_eq!(error.kind(), arcbox::ErrorKind::NotFound);
    let removes = mock.snapshot_removes.lock().unwrap();
    assert_eq!(removes.len(), 1);
    assert!(removes[0].force);
    assert_eq!(removes[0].id, mock.restores.lock().unwrap()[1].id);
}

#[tokio::test]
async fn snapshot_listing_paginates_and_delete_names_the_snapshot() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;
    let client = ArcBox::with_connection(&Connection::new().socket_path(&path)).unwrap();

    let rows = client
        .list_snapshots(ListSnapshotsOptions::default())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "warm-base");
    assert_eq!(rows[1].id, "snap-2");

    client.delete_snapshot("snap-1").await.unwrap();
    assert_eq!(mock.deletes.lock().unwrap()[0].snapshot_id, "snap-1");
}

#[tokio::test]
async fn events_map_kinds_and_filter_keepalives() {
    let mock = Arc::new(MockDaemon::default());
    *mock.event_frames.lock().unwrap() = vec![
        Ok(pb::WatchEventsResponse {
            payload: Some(watch_events_response::Payload::from(
                pb::KeepAlive::default(),
            )),
            ..Default::default()
        }),
        Ok(pb::WatchEventsResponse {
            payload: Some(watch_events_response::Payload::from(pb::SandboxEvent {
                sandbox_id: "sb-1".into(),
                kind: pb::SandboxEventKind::SANDBOX_EVENT_KIND_IDLE.into(),
                attributes: std::iter::once(("exit_code".to_owned(), "0".to_owned())).collect(),
                ..Default::default()
            })),
            ..Default::default()
        }),
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let sandbox = sandbox_for(&path).await;
    let mut events = sandbox.events();
    let event = events.next().await.unwrap().unwrap();
    assert_eq!(event.kind, SandboxEventKind::Idle);
    assert_eq!(
        event.attributes.get("exit_code").map(String::as_str),
        Some("0")
    );
    assert!(events.next().await.unwrap().is_none());
}
