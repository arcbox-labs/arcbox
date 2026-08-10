//! Lifecycle core against a mock daemon served over a real Unix socket.
//!
//! The contracts under test: create arms the readiness watch before
//! Create and cleans up its minted id on failure; connect routes PAUSED
//! through Resume; set_lifecycle's knobs are tri-state on the wire;
//! capabilities are cached per client; errors carry the registry's
//! ErrorInfo detail over the coarse Connect code; list auto-paginates.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use arcbox::{
    ArcBox, ConnectOptions, Connection, CreateOptions, ErrorKind, LifecycleUpdate, SandboxState,
    Update,
};
use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::watch_events_response;
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

/// Answers just enough of the wire to exercise the SDK.
#[derive(Default)]
struct MockDaemon {
    /// What Inspect answers, popped front-first (last entry repeats).
    inspect_states: Mutex<Vec<pb::SandboxState>>,
    /// Frames the Events stream replays.
    event_kinds: Mutex<Vec<pb::SandboxEventKind>>,
    /// Fail Create with this error.
    fail_create: Mutex<Option<ConnectError>>,
    /// Attach this ErrorInfo-carrying error to Inspect.
    fail_inspect: Mutex<Option<ConnectError>>,
    creates: Mutex<Vec<pb::CreateSandboxRequest>>,
    removes: Mutex<Vec<pb::RemoveSandboxRequest>>,
    resumes: Mutex<Vec<String>>,
    lifecycles: Mutex<Vec<pb::SetLifecycleRequest>>,
    capability_calls: Mutex<u32>,
    list_pages: Mutex<Vec<String>>,
}

impl MockDaemon {
    fn next_inspect_state(&self) -> pb::SandboxState {
        let mut states = self.inspect_states.lock().unwrap();
        if states.len() > 1 {
            states.remove(0)
        } else {
            states
                .first()
                .copied()
                .unwrap_or(pb::SandboxState::SANDBOX_STATE_READY)
        }
    }
}

fn unimplemented<T>(name: &str) -> ServiceResult<T> {
    Err(ConnectError::unimplemented(format!(
        "mock does not serve {name}"
    )))
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
        request: ServiceRequest<'_, pb::CreateSandboxRequest>,
    ) -> ServiceResult<pb::CreateSandboxResponse> {
        let request = request.to_owned_message();
        self.creates.lock().unwrap().push(request.clone());
        let failure = self.fail_create.lock().unwrap().take();
        if let Some(error) = failure {
            return Err(error);
        }
        Response::ok(pb::CreateSandboxResponse {
            id: request.id,
            ..Default::default()
        })
    }

    async fn stop(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::StopSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        unimplemented("Stop")
    }

    async fn remove(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::RemoveSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.removes
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(buffa_types::google::protobuf::Empty::default())
    }

    async fn pause(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::PauseSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Response::ok(buffa_types::google::protobuf::Empty::default())
    }

    async fn resume(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ResumeSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.resumes
            .lock()
            .unwrap()
            .push(request.to_owned_message().id);
        Response::ok(buffa_types::google::protobuf::Empty::default())
    }

    async fn set_lifecycle(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::SetLifecycleRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.lifecycles
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(buffa_types::google::protobuf::Empty::default())
    }

    async fn get_capabilities(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetCapabilitiesRequest>,
    ) -> ServiceResult<pb::GetCapabilitiesResponse> {
        *self.capability_calls.lock().unwrap() += 1;
        Response::ok(pb::GetCapabilitiesResponse {
            daemon_version: "0.0.0-mock".into(),
            protocol: 2,
            features: vec!["pause_resume".into()],
            nested_virt: pb::NestedVirtCapability {
                supported: true,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })
    }

    async fn inspect(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::InspectSandboxRequest>,
    ) -> ServiceResult<pb::SandboxInfo> {
        let failure = self.fail_inspect.lock().unwrap().take();
        if let Some(error) = failure {
            return Err(error);
        }
        Response::ok(pb::SandboxInfo {
            id: request.to_owned_message().id,
            state: self.next_inspect_state().into(),
            template: "base".into(),
            ..Default::default()
        })
    }

    async fn list(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::ListSandboxesRequest>,
    ) -> ServiceResult<pb::ListSandboxesResponse> {
        let token = request.to_owned_message().page_token;
        self.list_pages.lock().unwrap().push(token.clone());
        if token.is_empty() {
            Response::ok(pb::ListSandboxesResponse {
                sandboxes: vec![pb::SandboxSummary {
                    id: "sb-1".into(),
                    state: pb::SandboxState::SANDBOX_STATE_READY.into(),
                    ..Default::default()
                }],
                next_page_token: "page-2".into(),
                ..Default::default()
            })
        } else {
            Response::ok(pb::ListSandboxesResponse {
                sandboxes: vec![pb::SandboxSummary {
                    id: "sb-2".into(),
                    state: pb::SandboxState::SANDBOX_STATE_PAUSED.into(),
                    ..Default::default()
                }],
                ..Default::default()
            })
        }
    }

    async fn events(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::SandboxEventsRequest>,
    ) -> ServiceResult<
        std::pin::Pin<
            Box<
                dyn futures_core::Stream<Item = Result<pb::WatchEventsResponse, ConnectError>>
                    + Send,
            >,
        >,
    > {
        let frames: Vec<Result<pb::WatchEventsResponse, ConnectError>> = self
            .event_kinds
            .lock()
            .unwrap()
            .iter()
            .map(|&kind| {
                Ok(pb::WatchEventsResponse {
                    payload: Some(watch_events_response::Payload::from(pb::SandboxEvent {
                        sandbox_id: "any".into(),
                        kind: kind.into(),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
            })
            .collect();
        Response::ok(Box::pin(tokio_stream::iter(frames)))
    }

    async fn expose_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ExposePortRequest>,
    ) -> ServiceResult<pb::ExposePortResponse> {
        unimplemented("ExposePort")
    }

    async fn unexpose_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::UnexposePortRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        unimplemented("UnexposePort")
    }

    async fn list_exposed_ports(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListExposedPortsRequest>,
    ) -> ServiceResult<pb::ListExposedPortsResponse> {
        unimplemented("ListExposedPorts")
    }
}

/// Serve the mock on a temp Unix socket; the guard keeps the dir alive.
async fn serve(mock: Arc<MockDaemon>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let app = connectrpc::Router::new()
        .add_service(mock)
        .into_axum_router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, path)
}

async fn client_for(path: &PathBuf) -> ArcBox {
    ArcBox::with_connection(&Connection::new().socket_path(path)).unwrap()
}

#[tokio::test]
async fn create_sends_the_translated_options_and_waits_for_ready() {
    let mock = Arc::new(MockDaemon::default());
    // Inspect answers STARTING; the READY event is what finishes the wait.
    *mock.inspect_states.lock().unwrap() = vec![pb::SandboxState::SANDBOX_STATE_STARTING];
    *mock.event_kinds.lock().unwrap() = vec![
        pb::SandboxEventKind::SANDBOX_EVENT_KIND_CREATED,
        pb::SandboxEventKind::SANDBOX_EVENT_KIND_READY,
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let sandbox = client_for(&path)
        .await
        .create(
            "base",
            CreateOptions {
                ttl: Some(Duration::from_millis(90_500)),
                labels: [("app".to_owned(), "demo".to_owned())].into(),
                network: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let creates = mock.creates.lock().unwrap();
    let request = &creates[0];
    assert_eq!(request.template, "base");
    // Milliseconds round UP to whole wire seconds.
    assert_eq!(request.ttl_seconds, 91);
    assert_eq!(request.labels.get("app").map(String::as_str), Some("demo"));
    assert_eq!(
        request.network.as_option().map(|network| network.mode),
        Some(pb::NetworkMode::NETWORK_MODE_NONE.into())
    );
    // The handle's identity is the client-minted UUID the wire saw.
    assert_eq!(sandbox.id(), request.id);
    assert_eq!(
        uuid::Uuid::parse_str(sandbox.id())
            .unwrap()
            .get_version_num(),
        4
    );
}

#[tokio::test]
async fn a_failed_create_removes_the_minted_id() {
    let mock = Arc::new(MockDaemon::default());
    *mock.fail_create.lock().unwrap() =
        Some(ConnectError::resource_exhausted("no sandbox slots left"));
    let (_dir, path) = serve(mock.clone()).await;

    let error = client_for(&path)
        .await
        .create("", CreateOptions::default())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::ResourceExhausted);
    // The sandbox may exist even though create() failed, so the minted
    // id gets a best-effort forced removal.
    let removes = mock.removes.lock().unwrap();
    assert_eq!(removes.len(), 1);
    assert!(removes[0].force);
    assert_eq!(removes[0].id, mock.creates.lock().unwrap()[0].id);
}

#[tokio::test]
async fn connect_routes_paused_through_resume() {
    let mock = Arc::new(MockDaemon::default());
    *mock.inspect_states.lock().unwrap() = vec![
        pb::SandboxState::SANDBOX_STATE_PAUSING,
        pb::SandboxState::SANDBOX_STATE_PAUSED,
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let sandbox = client_for(&path)
        .await
        .connect("sb-1", ConnectOptions::default())
        .await
        .unwrap();

    assert_eq!(sandbox.id(), "sb-1");
    assert_eq!(*mock.resumes.lock().unwrap(), vec!["sb-1".to_owned()]);
}

#[tokio::test]
async fn connect_refuses_a_terminal_state() {
    let mock = Arc::new(MockDaemon::default());
    *mock.inspect_states.lock().unwrap() = vec![pb::SandboxState::SANDBOX_STATE_STOPPED];
    let (_dir, path) = serve(mock.clone()).await;

    let error = client_for(&path)
        .await
        .connect("sb-1", ConnectOptions::default())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::SandboxState);
    assert!(mock.resumes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn set_lifecycle_knobs_are_tri_state_on_the_wire() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;
    let client = client_for(&path).await;
    let sandbox = client
        .connect("sb-1", ConnectOptions::default())
        .await
        .unwrap();

    sandbox
        .set_lifecycle(LifecycleUpdate {
            ttl: Update::Set(Duration::from_millis(120_500)),
            idle_timeout: Update::Clear,
            on_idle: Update::Unchanged,
        })
        .await
        .unwrap();

    let updates = mock.lifecycles.lock().unwrap();
    let update = &updates[0];
    assert_eq!(update.id, "sb-1");
    // Set → rounded-up seconds; Clear → explicit 0; Unchanged → absent.
    assert_eq!(update.ttl_seconds, Some(121));
    assert_eq!(update.idle_timeout_seconds, Some(0));
    assert_eq!(update.on_idle, None);
}

#[tokio::test]
async fn capabilities_are_cached_per_client() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;
    let client = client_for(&path).await;

    let first = client.capabilities().await.unwrap();
    let second = client.capabilities().await.unwrap();

    assert_eq!(first.daemon_version, "0.0.0-mock");
    assert_eq!(second.protocol, 2);
    assert!(first.nested_virt.supported);
    assert_eq!(*mock.capability_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn the_registry_detail_beats_the_coarse_code() {
    let mock = Arc::new(MockDaemon::default());
    let info = pb::ErrorInfo {
        code: pb::ErrorCode::ERROR_CODE_SANDBOX_NOT_FOUND.into(),
        suggestion: "list sandboxes with `abctl sandbox list`".into(),
        ..Default::default()
    };
    let mut error = ConnectError::not_found("sandbox sb-9 not found");
    error.details.push(connectrpc::ErrorDetail::from_message(
        "arcbox.sandbox.v1.ErrorInfo",
        &info,
    ));
    *mock.fail_inspect.lock().unwrap() = Some(error);
    let (_dir, path) = serve(mock.clone()).await;

    let error = client_for(&path)
        .await
        .connect("sb-9", ConnectOptions::default())
        .await
        .unwrap_err();

    assert_eq!(error.kind(), ErrorKind::SandboxNotFound);
    assert_eq!(error.code(), Some("SANDBOX_NOT_FOUND"));
    assert_eq!(
        error.suggestion(),
        Some("list sandboxes with `abctl sandbox list`")
    );
    assert_eq!(error.operation(), "sandbox.connect");
}

#[tokio::test]
async fn list_auto_paginates() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;

    let rows = client_for(&path)
        .await
        .list(arcbox::ListOptions::default())
        .await
        .unwrap();

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, "sb-1");
    assert_eq!(rows[0].state, SandboxState::Ready);
    assert_eq!(rows[1].state, SandboxState::Paused);
    assert_eq!(
        *mock.list_pages.lock().unwrap(),
        vec![String::new(), "page-2".to_owned()]
    );
}
