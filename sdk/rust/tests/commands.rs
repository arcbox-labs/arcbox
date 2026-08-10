//! The commands surface against a mock daemon on a real Unix socket.
//!
//! The contracts under test: shell wrapping and option translation on
//! StartExecution; foreground run collecting output and mapping the
//! exit (shell convention for signal deaths); offset-idempotent stdin
//! with a re-read after a failed write; attach-resume re-dialling at
//! the advanced offsets; get() seeding the stdin cursor; list mapping.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use arcbox::{ArcBox, Channel, Cmd, ConnectOptions, Connection, RunOptions, Signal, Stdin};
use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{execution_event, exit_status};
use connectrpc::{ConnectError, RequestContext, Response, ServiceRequest, ServiceResult};

type EventFrames = Vec<Result<pb::ExecutionEvent, ConnectError>>;

/// Answers just enough of the process plane to exercise the SDK.
#[derive(Default)]
struct MockDaemon {
    starts: Mutex<Vec<pb::StartExecutionRequest>>,
    /// One scripted frame batch per Attach call, popped front-first.
    attach_scripts: Mutex<Vec<EventFrames>>,
    attach_requests: Mutex<Vec<pb::AttachExecutionRequest>>,
    stdin_requests: Mutex<Vec<pb::WriteStdinRequest>>,
    /// Fail the next WriteStdin with this error.
    fail_stdin: Mutex<Option<ConnectError>>,
    /// What GetStdinStatus / WaitExecution report as accepted stdin.
    accepted_stdin: Mutex<u64>,
    signals: Mutex<Vec<pb::SignalExecutionRequest>>,
    /// The Execution WaitExecution answers.
    wait_result: Mutex<Option<pb::Execution>>,
    list_result: Mutex<Vec<pb::Execution>>,
}

fn output_frame(channel: pb::StdioChannel, offset: u64, data: &[u8]) -> pb::ExecutionEvent {
    pb::ExecutionEvent {
        event: Some(execution_event::Event::from(pb::ExecutionOutput {
            channel: channel.into(),
            offset,
            data: data.to_vec(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn exited_frame(status: exit_status::Status) -> pb::ExecutionEvent {
    pb::ExecutionEvent {
        event: Some(execution_event::Event::from(pb::ExecutionExited {
            execution: pb::Execution {
                id: "cmd".into(),
                state: pb::ExecutionState::EXECUTION_STATE_EXITED.into(),
                exit_status: pb::ExitStatus {
                    status: Some(status),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        })),
        ..Default::default()
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
        request: ServiceRequest<'_, pb::StartExecutionRequest>,
    ) -> ServiceResult<pb::Execution> {
        let request = request.to_owned_message();
        self.starts.lock().unwrap().push(request.clone());
        Response::ok(pb::Execution {
            id: request.execution_id,
            state: pb::ExecutionState::EXECUTION_STATE_RUNNING.into(),
            ..Default::default()
        })
    }

    async fn attach_execution(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::AttachExecutionRequest>,
    ) -> ServiceResult<
        std::pin::Pin<
            Box<dyn futures_core::Stream<Item = Result<pb::ExecutionEvent, ConnectError>> + Send>,
        >,
    > {
        self.attach_requests
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        let mut scripts = self.attach_scripts.lock().unwrap();
        let frames = if scripts.is_empty() {
            Vec::new()
        } else {
            scripts.remove(0)
        };
        Response::ok(Box::pin(tokio_stream::iter(frames)))
    }

    async fn write_stdin(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::WriteStdinRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        let request = request.to_owned_message();
        self.stdin_requests.lock().unwrap().push(request.clone());
        let failure = self.fail_stdin.lock().unwrap().take();
        if let Some(error) = failure {
            return Err(error);
        }
        let mut accepted = self.accepted_stdin.lock().unwrap();
        // Offset-idempotent: bytes below the accepted count are deduped.
        let end = request.offset + request.data.len() as u64;
        *accepted = (*accepted).max(end);
        Response::ok(pb::StdinStatus {
            bytes_written: *accepted,
            closed: request.eof,
            ..Default::default()
        })
    }

    async fn stream_stdin(
        &self,
        _ctx: RequestContext,
        _requests: connectrpc::InboundStream<pb::WriteStdinRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        Err(ConnectError::unimplemented(
            "mock does not serve StreamStdin",
        ))
    }

    async fn get_stdin_status(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::GetStdinStatusRequest>,
    ) -> ServiceResult<pb::StdinStatus> {
        Response::ok(pb::StdinStatus {
            bytes_written: *self.accepted_stdin.lock().unwrap(),
            ..Default::default()
        })
    }

    async fn signal_execution(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::SignalExecutionRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        self.signals
            .lock()
            .unwrap()
            .push(request.to_owned_message());
        Response::ok(buffa_types::google::protobuf::Empty::default())
    }

    async fn resize_execution_tty(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ResizeExecutionTtyRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Response::ok(buffa_types::google::protobuf::Empty::default())
    }

    async fn wait_execution(
        &self,
        _ctx: RequestContext,
        request: ServiceRequest<'_, pb::WaitExecutionRequest>,
    ) -> ServiceResult<pb::Execution> {
        let request = request.to_owned_message();
        let scripted = self.wait_result.lock().unwrap().clone();
        Response::ok(scripted.unwrap_or_else(|| {
            pb::Execution {
                id: request.execution_id,
                state: pb::ExecutionState::EXECUTION_STATE_EXITED.into(),
                stdin: pb::StdinStatus {
                    bytes_written: *self.accepted_stdin.lock().unwrap(),
                    ..Default::default()
                }
                .into(),
                exit_status: pb::ExitStatus {
                    status: Some(exit_status::Status::Code(0)),
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            }
        }))
    }

    async fn list_executions(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListExecutionsRequest>,
    ) -> ServiceResult<pb::ListExecutionsResponse> {
        Response::ok(pb::ListExecutionsResponse {
            executions: self.list_result.lock().unwrap().clone(),
            ..Default::default()
        })
    }

    async fn wait_for_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::WaitForPortRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented(
            "mock does not serve WaitForPort",
        ))
    }
}

/// Inspect always answers READY so `connect` resolves instantly.
struct ReadySandboxService;

#[allow(
    refining_impl_trait,
    reason = "the trait returns `impl Encodable<M>`; naming the concrete body \
              type is strictly more informative and this mock is registered on a \
              Router rather than named by callers"
)]
impl pb::SandboxService for ReadySandboxService {
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
        _request: ServiceRequest<'_, pb::RemoveSandboxRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
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
    ) -> ServiceResult<
        std::pin::Pin<
            Box<
                dyn futures_core::Stream<Item = Result<pb::WatchEventsResponse, ConnectError>>
                    + Send,
            >,
        >,
    > {
        Response::ok(Box::pin(tokio_stream::iter(Vec::new())))
    }
    async fn expose_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ExposePortRequest>,
    ) -> ServiceResult<pb::ExposePortResponse> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn unexpose_port(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::UnexposePortRequest>,
    ) -> ServiceResult<buffa_types::google::protobuf::Empty> {
        Err(ConnectError::unimplemented("mock"))
    }
    async fn list_exposed_ports(
        &self,
        _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListExposedPortsRequest>,
    ) -> ServiceResult<pb::ListExposedPortsResponse> {
        Err(ConnectError::unimplemented("mock"))
    }
}

async fn serve(mock: Arc<MockDaemon>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("daemon.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let app = connectrpc::Router::new()
        .add_service(mock)
        .add_service(Arc::new(ReadySandboxService))
        .into_axum_router();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (dir, path)
}

async fn commands_for(path: &PathBuf) -> arcbox::Commands {
    let sandbox = ArcBox::with_connection(&Connection::new().socket_path(path))
        .unwrap()
        .connect("sb-1", ConnectOptions::default())
        .await
        .unwrap();
    sandbox.commands()
}

#[tokio::test]
async fn run_wraps_shell_lines_collects_output_and_maps_the_exit() {
    let mock = Arc::new(MockDaemon::default());
    *mock.attach_scripts.lock().unwrap() = vec![vec![
        Ok(output_frame(
            pb::StdioChannel::STDIO_CHANNEL_STDOUT,
            0,
            b"out",
        )),
        Ok(output_frame(
            pb::StdioChannel::STDIO_CHANNEL_STDERR,
            0,
            b"err",
        )),
        Ok(exited_frame(exit_status::Status::Code(3))),
    ]];
    let (_dir, path) = serve(mock.clone()).await;

    let result = commands_for(&path)
        .await
        .run(
            "echo hi",
            RunOptions {
                timeout: Some(Duration::from_millis(1500)),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let starts = mock.starts.lock().unwrap();
    assert_eq!(starts[0].cmd, vec!["/bin/sh", "-lc", "echo hi"]);
    assert_eq!(starts[0].sandbox_id, "sb-1");
    // Milliseconds round UP to whole wire seconds.
    assert_eq!(starts[0].timeout_seconds, 2);
    assert!(!starts[0].stdin);
    assert_eq!(result.exit_code, 3);
    assert!(!result.success());
    assert_eq!(result.stdout, b"out");
    assert_eq!(result.stderr, b"err");
}

#[tokio::test]
async fn signal_deaths_follow_the_shell_convention() {
    let mock = Arc::new(MockDaemon::default());
    *mock.attach_scripts.lock().unwrap() =
        vec![vec![Ok(exited_frame(exit_status::Status::Signal(9)))]];
    let (_dir, path) = serve(mock.clone()).await;

    let result = commands_for(&path)
        .await
        .run(
            Cmd::Argv(vec!["sleep".into(), "60".into()]),
            RunOptions::default(),
        )
        .await
        .unwrap();

    assert_eq!(result.exit_code, 137);
    assert_eq!(result.signal.as_deref(), Some("SIGKILL"));
}

#[tokio::test]
async fn output_reattaches_at_the_advanced_offsets() {
    let mock = Arc::new(MockDaemon::default());
    *mock.attach_scripts.lock().unwrap() = vec![
        // First attach delivers one chunk, then the transport dies.
        vec![
            Ok(output_frame(
                pb::StdioChannel::STDIO_CHANNEL_STDOUT,
                0,
                b"first",
            )),
            Err(ConnectError::unavailable("stream broke")),
        ],
        // The resume must dial in at the advanced stdout offset.
        vec![
            Ok(output_frame(
                pb::StdioChannel::STDIO_CHANNEL_STDOUT,
                5,
                b" second",
            )),
            Ok(exited_frame(exit_status::Status::Code(0))),
        ],
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let handle = commands_for(&path)
        .await
        .spawn("cat", RunOptions::default())
        .await
        .unwrap();
    let mut collected = Vec::new();
    let mut output = handle.output();
    while let Some(chunk) = output.next().await.unwrap() {
        assert_eq!(chunk.channel, Channel::Stdout);
        collected.extend_from_slice(&chunk.data);
    }

    assert_eq!(collected, b"first second");
    let attaches = mock.attach_requests.lock().unwrap();
    assert_eq!(attaches.len(), 2);
    assert_eq!(attaches[0].stdout_offset, 0);
    assert_eq!(attaches[1].stdout_offset, 5);
}

#[tokio::test]
async fn stdin_writes_are_offset_serialized_and_recover_from_failure() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;

    let handle = commands_for(&path)
        .await
        .spawn(
            "cat",
            RunOptions {
                stdin: Stdin::Open,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    handle.write_stdin(b"hello ").await.unwrap();
    handle.write_stdin(b"world").await.unwrap();

    // A failed write forgets the cursor; the next write re-reads the
    // daemon's accepted count instead of guessing.
    *mock.fail_stdin.lock().unwrap() = Some(ConnectError::unavailable("daemon restarting"));
    handle.write_stdin(b"lost").await.unwrap_err();
    handle.write_stdin(b"!").await.unwrap();

    let requests = mock.stdin_requests.lock().unwrap();
    let offsets: Vec<u64> = requests.iter().map(|request| request.offset).collect();
    // 0, 6 (after "hello "), 11 (failed "lost"), then the re-read
    // accepted count 11 again for "!".
    assert_eq!(offsets, vec![0, 6, 11, 11]);
    assert!(mock.starts.lock().unwrap()[0].stdin);
}

#[tokio::test]
async fn get_seeds_the_stdin_cursor_from_the_daemon() {
    let mock = Arc::new(MockDaemon::default());
    *mock.accepted_stdin.lock().unwrap() = 42;
    let (_dir, path) = serve(mock.clone()).await;

    let handle = commands_for(&path).await.get("cmd-7").await.unwrap();
    handle.write_stdin(b"more").await.unwrap();

    let requests = mock.stdin_requests.lock().unwrap();
    assert_eq!(requests[0].offset, 42);
    assert_eq!(requests[0].execution_id, "cmd-7");
}

#[tokio::test]
async fn kill_delivers_the_wire_signal() {
    let mock = Arc::new(MockDaemon::default());
    *mock.attach_scripts.lock().unwrap() =
        vec![vec![Ok(exited_frame(exit_status::Status::Signal(15)))]];
    let (_dir, path) = serve(mock.clone()).await;

    let handle = commands_for(&path)
        .await
        .spawn("sleep 60", RunOptions::default())
        .await
        .unwrap();
    handle.kill(Signal::Term).await.unwrap();

    let signals = mock.signals.lock().unwrap();
    assert_eq!(
        signals[0].signal.as_known(),
        Some(pb::Signal::SIGNAL_SIGTERM)
    );
}

#[tokio::test]
async fn list_maps_running_and_exited_rows() {
    let mock = Arc::new(MockDaemon::default());
    *mock.list_result.lock().unwrap() = vec![
        pb::Execution {
            id: "running".into(),
            state: pb::ExecutionState::EXECUTION_STATE_RUNNING.into(),
            tty: true,
            ..Default::default()
        },
        pb::Execution {
            id: "killed".into(),
            state: pb::ExecutionState::EXECUTION_STATE_EXITED.into(),
            exit_status: pb::ExitStatus {
                status: Some(exit_status::Status::Signal(9)),
                ..Default::default()
            }
            .into(),
            ..Default::default()
        },
    ];
    let (_dir, path) = serve(mock.clone()).await;

    let rows = commands_for(&path).await.list().await.unwrap();

    assert_eq!(rows[0].command_id, "running");
    assert!(rows[0].tty);
    assert_eq!(rows[0].exit_code, None);
    assert_eq!(rows[1].exit_code, Some(137));
    assert_eq!(rows[1].signal.as_deref(), Some("SIGKILL"));
}

#[tokio::test]
async fn open_stdin_is_refused_on_a_foreground_run() {
    let mock = Arc::new(MockDaemon::default());
    let (_dir, path) = serve(mock.clone()).await;

    let error = commands_for(&path)
        .await
        .run(
            "cat",
            RunOptions {
                stdin: Stdin::Open,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();

    assert_eq!(error.kind(), arcbox::ErrorKind::InvalidArgument);
    assert!(mock.starts.lock().unwrap().is_empty());
}
