//! Sandbox handles and the client entry point.
//!
//! A handle holds only the sandbox id and the shared transport — state
//! is never cached; [`Sandbox::info`] always fetches fresh.

use std::collections::BTreeMap;
use std::time::Duration;

use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{
    SandboxServiceClient, SandboxSnapshotServiceClient, watch_events_response,
};
use connectrpc::client::{ClientTransport, ServerStream, SharedHttp2Connection};
use tokio::sync::OnceCell;

use crate::client::ClientContext;
use crate::connection::Connection;
use crate::error::{Error, ErrorKind, Result};
use crate::types::{
    Capabilities, IdlePolicy, LifecycleUpdate, SandboxEvent, SandboxInfo, SandboxState,
    SandboxSummary, Snapshot, Update, capabilities_from_wire, idle_action_to_wire, info_from_wire,
    seconds_to_wire, state_to_wire, summary_from_wire, time_from_wire,
};

/// The one concrete client this SDK drives: the generated Connect
/// client over the shared lazy HTTP/2 Unix-socket transport.
type SandboxClient = SandboxServiceClient<SharedHttp2Connection>;

/// The generated snapshot client over the shared transport.
type SnapshotClient = SandboxSnapshotServiceClient<SharedHttp2Connection>;

/// The server stream [`SandboxClient::events`] returns.
type EventWireStream = ServerStream<
    <SharedHttp2Connection as ClientTransport>::ResponseBody,
    pb::__buffa::view::WatchEventsResponseView<'static>,
>;

/// How often [`ArcBox::connect`] re-inspects a PAUSING sandbox — the
/// settle poll the sibling SDKs use.
const PAUSE_SETTLE_POLL: Duration = Duration::from_millis(500);

/// Default overall deadline for [`ArcBox::connect`] — generous because
/// a checkpoint restore or cold boot legitimately takes a while.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Options for [`ArcBox::create`].
///
/// `Default` waits for readiness with no lifecycle limits; set only the
/// fields you need — struct-update syntax works:
/// `CreateOptions { ttl: Some(...), ..Default::default() }`.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    /// Hard maximum lifetime. On expiry the daemon always destroys the
    /// sandbox — pausing does not apply. Distinct from
    /// [`idle_timeout`](Self::idle_timeout); never conflate the two.
    pub ttl: Option<Duration>,
    /// Apply [`on_idle`](Self::on_idle) after this long without a
    /// running command. Unset = no idle detection.
    pub idle_timeout: Option<Duration>,
    /// What the daemon does when the idle timeout expires (unset =
    /// daemon default: kill).
    pub on_idle: Option<IdlePolicy>,
    /// vCPU count (unset = template, else daemon default).
    pub vcpus: Option<u32>,
    /// Memory in MiB (unset = template, else daemon default).
    pub memory_mib: Option<u64>,
    /// Initial command launched after boot; its exit returns the
    /// sandbox to READY.
    pub cmd: Vec<String>,
    /// Environment for the initial command, merged over the template's.
    pub env: BTreeMap<String, String>,
    /// Labels for filtering in list/events.
    pub labels: BTreeMap<String, String>,
    /// `Some(false)` disables networking entirely (no network device).
    pub network: Option<bool>,
    /// Resolve only once the sandbox is READY (default `true`).
    pub wait_until_ready: bool,
}

impl Default for CreateOptions {
    fn default() -> Self {
        Self {
            ttl: None,
            idle_timeout: None,
            on_idle: None,
            vcpus: None,
            memory_mib: None,
            cmd: Vec::new(),
            env: BTreeMap::new(),
            labels: BTreeMap::new(),
            network: None,
            wait_until_ready: true,
        }
    }
}

/// Options for [`ArcBox::connect`].
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// Overall deadline for the whole connect: the PAUSING settle poll,
    /// a checkpoint resume, and the STARTING readiness wait all share
    /// it (default 60 s; `None` disables the bound). On expiry a
    /// [`ErrorKind::Timeout`] error is returned and the sandbox is left
    /// as it was.
    pub timeout: Option<Duration>,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            timeout: Some(CONNECT_TIMEOUT),
        }
    }
}

/// Options for [`ArcBox::list`].
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    /// Keep only sandboxes in this state.
    pub state: Option<SandboxState>,
    /// Keep only sandboxes carrying all of these labels.
    pub labels: BTreeMap<String, String>,
}

/// Options for [`Sandbox::checkpoint`].
#[derive(Debug, Clone, Default)]
pub struct CheckpointOptions {
    /// Human-readable name recorded on the snapshot.
    pub name: Option<String>,
    /// Labels recorded on the snapshot, filterable in
    /// [`ArcBox::list_snapshots`].
    pub labels: BTreeMap<String, String>,
}

/// Options for [`ArcBox::restore`].
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    /// Hard maximum lifetime of the restored sandbox (unset = no
    /// limit). Same semantics as [`CreateOptions::ttl`].
    pub ttl: Option<Duration>,
    /// Labels for the restored sandbox.
    pub labels: BTreeMap<String, String>,
    /// Assign a fresh TAP interface and IP to the restored sandbox.
    /// Without it the restored sandbox reuses the origin's recorded
    /// NIC — the origin must not be running. Required when running
    /// several sandboxes restored from the same snapshot concurrently.
    pub fresh_network: bool,
}

/// Options for [`ArcBox::list_snapshots`].
#[derive(Debug, Clone, Default)]
pub struct ListSnapshotsOptions {
    /// Keep only snapshots checkpointed from this sandbox.
    pub sandbox_id: Option<String>,
    /// Keep only snapshots carrying all of these labels.
    pub labels: BTreeMap<String, String>,
}

/// Client entry point. Holds one lazily-dialled connection; every
/// handle it creates shares it. Cheap to clone.
#[derive(Clone)]
pub struct ArcBox {
    ctx: ClientContext,
    capabilities: std::sync::Arc<OnceCell<Capabilities>>,
}

impl ArcBox {
    /// An entry point resolved from the environment (see [`Connection`]).
    ///
    /// Nothing is dialled here — the socket is opened on the first call,
    /// so a failure surfaces at the call that needed it.
    ///
    /// # Errors
    ///
    /// Connection resolution errors only (bad environment).
    pub fn new() -> Result<Self> {
        Self::with_connection(&Connection::new())
    }

    /// An entry point for an explicit [`Connection`].
    ///
    /// # Errors
    ///
    /// Connection resolution errors only (bad environment).
    pub fn with_connection(connection: &Connection) -> Result<Self> {
        Ok(Self {
            ctx: ClientContext::new(connection)?,
            capabilities: std::sync::Arc::new(OnceCell::new()),
        })
    }

    fn client(&self) -> SandboxClient {
        SandboxServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    fn snapshots(&self) -> SnapshotClient {
        SandboxSnapshotServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    /// What the daemon can do: version, protocol level, feature flags,
    /// and whether nested virtualization is available. Answered
    /// host-side (works before any sandbox exists) and cached for the
    /// life of this client — a failed fetch is not cached, so the next
    /// call retries.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn capabilities(&self) -> Result<Capabilities> {
        let fetched = self
            .capabilities
            .get_or_try_init(|| async {
                let response = self
                    .client()
                    .get_capabilities(pb::GetCapabilitiesRequest::default())
                    .await
                    .map_err(|error| Error::from_connect(error, "arcbox.capabilities"))?
                    .into_owned();
                Ok::<_, Error>(capabilities_from_wire(response))
            })
            .await?;
        Ok(fetched.clone())
    }

    /// Create a sandbox and (by default) wait until it is READY.
    ///
    /// The sandbox id is minted client-side so the readiness watch can
    /// be armed BEFORE the create call — subscribe-then-act, so no
    /// transition is missed — and so retries stay idempotent.
    ///
    /// # Errors
    ///
    /// Any RPC failure; a sandbox that reaches a terminal state before
    /// READY is [`ErrorKind::SandboxState`]. On failure the minted id
    /// gets a best-effort forced removal so nothing leaks.
    pub async fn create(&self, template: &str, options: CreateOptions) -> Result<Sandbox> {
        let id = uuid::Uuid::new_v4().to_string();
        match self.create_inner(&id, template, &options).await {
            Ok(sandbox) => Ok(sandbox),
            Err(error) => {
                // The sandbox may exist even though create() failed
                // (readiness failed, response lost) and ttl is optional,
                // so a leaked VM could run forever. Best-effort removal;
                // a failure here must not mask the original error.
                let _ = self
                    .client()
                    .remove(pb::RemoveSandboxRequest {
                        id,
                        force: true,
                        ..Default::default()
                    })
                    .await;
                Err(error)
            }
        }
    }

    async fn create_inner(
        &self,
        id: &str,
        template: &str,
        options: &CreateOptions,
    ) -> Result<Sandbox> {
        let client = self.client();
        // Arm the readiness subscription before Create so no transition
        // can be missed between the create and the first watch frame.
        let events = if options.wait_until_ready {
            Some(
                client
                    .events(pb::SandboxEventsRequest {
                        sandbox_id: id.to_owned(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| Error::from_connect(error, "sandbox.create"))?,
            )
        } else {
            None
        };

        let mut request = pb::CreateSandboxRequest {
            id: id.to_owned(),
            template: template.to_owned(),
            labels: options.labels.clone().into_iter().collect(),
            cmd: options.cmd.clone(),
            env: options.env.clone().into_iter().collect(),
            ttl_seconds: seconds_to_wire(options.ttl),
            idle_timeout_seconds: seconds_to_wire(options.idle_timeout),
            on_idle: idle_action_to_wire(options.on_idle).into(),
            ..Default::default()
        };
        if options.vcpus.is_some() || options.memory_mib.is_some() {
            // Setting either sends `limits`, replacing template defaults
            // WHOLESALE (a zero subfield means the daemon default).
            request.limits = pb::ResourceLimits {
                vcpus: options.vcpus.unwrap_or(0),
                memory_mib: options.memory_mib.unwrap_or(0),
                ..Default::default()
            }
            .into();
        }
        if let Some(enabled) = options.network {
            request.network = pb::NetworkSpec {
                mode: if enabled {
                    pb::NetworkMode::NETWORK_MODE_ENABLED.into()
                } else {
                    pb::NetworkMode::NETWORK_MODE_NONE.into()
                },
                ..Default::default()
            }
            .into();
        }

        client
            .create(request)
            .await
            .map_err(|error| Error::from_connect(error, "sandbox.create"))?;

        if let Some(events) = events {
            self.wait_ready(id, events, "sandbox.create").await?;
        }
        Ok(Sandbox::attached(self.ctx.clone(), id.to_owned()))
    }

    /// Attach to an existing sandbox. A PAUSED sandbox is resumed
    /// (resume completes once it is READY again); a PAUSING one settles
    /// to PAUSED first, then resumes; a STARTING one is waited for. A
    /// terminal state is a typed error carrying the observed state.
    /// Connecting never touches the sandbox's lifecycle deadlines.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::Timeout`] when [`ConnectOptions::timeout`] elapses
    /// first; otherwise any RPC failure, mapped onto [`Error`].
    pub async fn connect(&self, id: &str, options: ConnectOptions) -> Result<Sandbox> {
        match options.timeout {
            None => self.connect_inner(id).await,
            Some(deadline) => tokio::time::timeout(deadline, self.connect_inner(id))
                .await
                .map_err(|_| {
                    Error::new(
                        ErrorKind::Timeout,
                        format!("connect(timeout) elapsed before sandbox {id} was ready"),
                        "sandbox.connect",
                    )
                    .with_suggestion("increase the connect timeout option")
                    .with_context("id", id)
                })?,
        }
    }

    async fn connect_inner(&self, id: &str) -> Result<Sandbox> {
        let client = self.client();
        let inspect = |client: SandboxClient| async move {
            client
                .inspect(pb::InspectSandboxRequest {
                    id: id.to_owned(),
                    ..Default::default()
                })
                .await
                .map(|response| info_from_wire(response.into_owned()))
                .map_err(|error| Error::from_connect(error, "sandbox.connect"))
        };
        let mut info = inspect(client.clone()).await?;
        // A pausing sandbox's next stop is PAUSED — never READY — so
        // waiting on readiness events would park forever. Poll the
        // checkpoint out, then route on whatever state it settled in.
        while info.state == SandboxState::Pausing {
            tokio::time::sleep(PAUSE_SETTLE_POLL).await;
            info = inspect(client.clone()).await?;
        }
        match info.state {
            SandboxState::Ready | SandboxState::Running => {
                Ok(Sandbox::attached(self.ctx.clone(), id.to_owned()))
            }
            SandboxState::Paused => {
                // Restoring a checkpoint takes as long as it takes; the
                // overall connect deadline is the only bound.
                client
                    .resume(pb::ResumeSandboxRequest {
                        id: id.to_owned(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| Error::from_connect(error, "sandbox.connect"))?;
                Ok(Sandbox::attached(self.ctx.clone(), id.to_owned()))
            }
            SandboxState::Starting => {
                let events = client
                    .events(pb::SandboxEventsRequest {
                        sandbox_id: id.to_owned(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| Error::from_connect(error, "sandbox.connect"))?;
                self.wait_ready(id, events, "sandbox.connect").await?;
                Ok(Sandbox::attached(self.ctx.clone(), id.to_owned()))
            }
            state => Err(Error::new(
                ErrorKind::SandboxState,
                format!("sandbox {id} is {state:?} and cannot be connected to"),
                "sandbox.connect",
            )
            .with_context("id", id)),
        }
    }

    /// List sandboxes, auto-paginating server-side pages into one
    /// listing.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn list(&self, options: ListOptions) -> Result<Vec<SandboxSummary>> {
        let client = self.client();
        let mut rows = Vec::new();
        let mut page_token = String::new();
        loop {
            let page = client
                .list(pb::ListSandboxesRequest {
                    state: options
                        .state
                        .map_or(pb::SandboxState::SANDBOX_STATE_UNSPECIFIED, state_to_wire)
                        .into(),
                    labels: options.labels.clone().into_iter().collect(),
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(|error| Error::from_connect(error, "sandbox.list"))?
                .into_owned();
            rows.extend(page.sandboxes.into_iter().map(summary_from_wire));
            page_token = page.next_page_token;
            if page_token.is_empty() {
                return Ok(rows);
            }
        }
    }

    /// Restore a new sandbox from a snapshot. The restored sandbox
    /// starts READY — there is no boot to wait for. It gets a fresh id,
    /// minted client-side so retries stay idempotent (the create()
    /// rule). Without [`RestoreOptions::fresh_network`] the restored
    /// sandbox reuses the origin's recorded NIC, so the origin must not
    /// be running — and [`Sandbox::checkpoint`] resumes it, so pause or
    /// kill it first (or set `fresh_network`).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::NotFound`] for a missing snapshot; otherwise any
    /// RPC failure. On failure the minted id gets a best-effort forced
    /// removal so nothing leaks.
    pub async fn restore(&self, snapshot_id: &str, options: RestoreOptions) -> Result<Sandbox> {
        let id = uuid::Uuid::new_v4().to_string();
        // No client-side deadline: restoring takes as long as it takes.
        let restored = self
            .snapshots()
            .restore(pb::RestoreRequest {
                id: id.clone(),
                snapshot_id: snapshot_id.to_owned(),
                labels: options.labels.into_iter().collect(),
                network_override: options.fresh_network,
                ttl_seconds: seconds_to_wire(options.ttl),
                ..Default::default()
            })
            .await;
        if let Err(error) = restored {
            // The sandbox may exist even though restore() failed
            // (response lost) and ttl is optional, so a leaked VM could
            // run forever. Best-effort removal; a failure here must not
            // mask the original error.
            let _ = self
                .client()
                .remove(pb::RemoveSandboxRequest {
                    id,
                    force: true,
                    ..Default::default()
                })
                .await;
            return Err(Error::from_connect(error, "snapshots.restore"));
        }
        Ok(Sandbox::attached(self.ctx.clone(), id))
    }

    /// List the snapshot catalog, auto-paginating server-side pages.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn list_snapshots(&self, options: ListSnapshotsOptions) -> Result<Vec<Snapshot>> {
        let client = self.snapshots();
        let mut rows = Vec::new();
        let mut page_token = String::new();
        loop {
            let page = client
                .list_snapshots(pb::ListSnapshotsRequest {
                    sandbox_id: options.sandbox_id.clone().unwrap_or_default(),
                    labels: options.labels.clone().into_iter().collect(),
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(|error| Error::from_connect(error, "snapshots.list"))?
                .into_owned();
            rows.extend(page.snapshots.into_iter().map(Snapshot::from));
            page_token = page.next_page_token;
            if page_token.is_empty() {
                return Ok(rows);
            }
        }
    }

    /// Delete a snapshot and its on-disk data.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::NotFound`] for a missing snapshot; otherwise any
    /// RPC failure.
    pub async fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.snapshots()
            .delete_snapshot(pb::DeleteSnapshotRequest {
                snapshot_id: snapshot_id.to_owned(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "snapshots.delete"))?;
        Ok(())
    }

    /// Consume lifecycle events until READY/RUNNING, or fail on a
    /// terminal transition. The subscription was armed before Create;
    /// the one residual window — Create processed before the
    /// subscription registered server-side — is covered by an immediate
    /// Inspect and by re-inspecting on every keepalive frame.
    async fn wait_ready(
        &self,
        id: &str,
        mut events: EventWireStream,
        operation: &'static str,
    ) -> Result<()> {
        let check = |state: SandboxState, error: &Option<String>| -> Result<bool> {
            match state {
                SandboxState::Ready | SandboxState::Running => Ok(true),
                SandboxState::Failed => Err(Error::new(
                    ErrorKind::SandboxState,
                    format!(
                        "sandbox {id} failed to start: {}",
                        error.as_deref().unwrap_or("unknown failure")
                    ),
                    operation,
                )
                .with_context("id", id)),
                SandboxState::Stopping | SandboxState::Stopped => Err(Error::new(
                    ErrorKind::SandboxState,
                    format!("sandbox {id} stopped before becoming ready"),
                    operation,
                )
                .with_context("id", id)),
                _ => Ok(false),
            }
        };

        let inspect = || async {
            self.client()
                .inspect(pb::InspectSandboxRequest {
                    id: id.to_owned(),
                    ..Default::default()
                })
                .await
                .map(|response| info_from_wire(response.into_owned()))
                .map_err(|error| Error::from_connect(error, operation))
        };
        let info = inspect().await?;
        if check(info.state, &info.error)? {
            return Ok(());
        }

        loop {
            let frame = events
                .message::<pb::WatchEventsResponse>()
                .await
                .map_err(|error| Error::from_connect(error, operation))?;
            let Some(frame) = frame else {
                return Err(Error::new(
                    ErrorKind::ConnectionLost,
                    format!("the event stream ended before sandbox {id} was ready"),
                    operation,
                )
                .with_context("id", id));
            };
            match frame.to_owned_message().payload {
                Some(watch_events_response::Payload::Event(event)) => {
                    let state = event_state(event.kind.as_known());
                    if let Some(state) = state {
                        let error = event.attributes.get("error").cloned();
                        if check(state, &error)? {
                            return Ok(());
                        }
                    }
                }
                // A keepalive proves the stream is live but carries no
                // transition; re-inspect to cover the subscribe race.
                _ => {
                    let info = inspect().await?;
                    if check(info.state, &info.error)? {
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// A lifecycle event kind mapped onto the state it proves, when it
/// proves one.
fn event_state(kind: Option<pb::SandboxEventKind>) -> Option<SandboxState> {
    use pb::SandboxEventKind as Kind;
    match kind? {
        Kind::SANDBOX_EVENT_KIND_READY | Kind::SANDBOX_EVENT_KIND_IDLE => Some(SandboxState::Ready),
        Kind::SANDBOX_EVENT_KIND_RUNNING => Some(SandboxState::Running),
        Kind::SANDBOX_EVENT_KIND_FAILED => Some(SandboxState::Failed),
        Kind::SANDBOX_EVENT_KIND_STOPPING => Some(SandboxState::Stopping),
        Kind::SANDBOX_EVENT_KIND_STOPPED | Kind::SANDBOX_EVENT_KIND_REMOVED => {
            Some(SandboxState::Stopped)
        }
        _ => None,
    }
}

/// A handle to one sandbox. Holds only the id and the shared transport.
#[derive(Clone)]
pub struct Sandbox {
    ctx: ClientContext,
    id: String,
}

impl Sandbox {
    pub(crate) fn attached(ctx: ClientContext, id: String) -> Self {
        Self { ctx, id }
    }

    fn client(&self) -> SandboxClient {
        SandboxServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
    }

    /// The sandbox id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Run processes inside the sandbox.
    #[must_use]
    pub fn commands(&self) -> crate::Commands {
        crate::Commands::attached(self.ctx.clone(), self.id.clone())
    }

    /// Move bytes in and out of the sandbox.
    #[must_use]
    pub fn files(&self) -> crate::Files {
        crate::Files::attached(self.ctx.clone(), self.id.clone())
    }

    /// Network reachability and readiness of the sandbox.
    #[must_use]
    pub fn ports(&self) -> crate::Ports {
        crate::Ports::attached(self.ctx.clone(), self.id.clone())
    }

    /// Subscribe to this sandbox's lifecycle events (keepalive frames
    /// filtered). The subscription is dialled on the first
    /// [`next`](EventStream::next); the stream ends when the daemon
    /// ends it. Events cannot be replayed, so re-subscribing after an
    /// error is the caller's decision.
    #[must_use]
    pub fn events(&self) -> EventStream {
        EventStream {
            ctx: self.ctx.clone(),
            sandbox_id: self.id.clone(),
            stream: None,
            done: false,
        }
    }

    /// Checkpoint this sandbox into a reusable snapshot: paused,
    /// snapshotted, then resumed, automatically — the sandbox keeps
    /// running under the same id. Requires a quiescent sandbox (READY —
    /// no running command). Restore the returned snapshot into fresh
    /// sandboxes with [`ArcBox::restore`].
    ///
    /// # Errors
    ///
    /// [`ErrorKind::SandboxState`] when the sandbox is not quiescent;
    /// otherwise any RPC failure.
    pub async fn checkpoint(&self, options: CheckpointOptions) -> Result<Snapshot> {
        let name = options.name.unwrap_or_default();
        // No client-side deadline: checkpointing takes as long as it
        // takes.
        let response =
            SandboxSnapshotServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
                .checkpoint(pb::CheckpointRequest {
                    sandbox_id: self.id.clone(),
                    name: name.clone(),
                    labels: options.labels.clone().into_iter().collect(),
                    ..Default::default()
                })
                .await
                .map_err(|error| Error::from_connect(error, "sandbox.checkpoint"))?
                .into_owned();
        // The response carries only id + creation time; name and labels
        // echo the request, which is exactly what the catalog recorded.
        Ok(Snapshot {
            id: response.snapshot_id,
            sandbox_id: self.id.clone(),
            name,
            labels: options.labels,
            created_at: time_from_wire(response.created_at.as_option()),
        })
    }

    /// Fetch the sandbox's current state — always fresh, never cached.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn info(&self) -> Result<SandboxInfo> {
        let response = self
            .client()
            .inspect(pb::InspectSandboxRequest {
                id: self.id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "sandbox.info"))?;
        Ok(info_from_wire(response.into_owned()))
    }

    /// Destroy the sandbox and release all its resources immediately.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn kill(&self) -> Result<()> {
        self.client()
            .remove(pb::RemoveSandboxRequest {
                id: self.id.clone(),
                force: true,
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "sandbox.kill"))?;
        Ok(())
    }

    /// Checkpoint the sandbox to disk under the same id and release its
    /// runtime resources. Resume happens on the next [`ArcBox::connect`]
    /// (or transparently, daemon-side, on the next data-plane call).
    /// Trades RAM for disk: the checkpoint joins the disk overlay in
    /// `storage_bytes` until the sandbox is resumed or removed. Requires
    /// a quiescent sandbox (READY — no running command).
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn pause(&self) -> Result<()> {
        // No client-side deadline: checkpointing takes as long as it
        // takes.
        self.client()
            .pause(pb::PauseSandboxRequest {
                id: self.id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "sandbox.pause"))?;
        Ok(())
    }

    /// Replace lifecycle deadlines. Each knob is tri-state (see
    /// [`Update`]): unchanged, cleared to the daemon default, or set.
    /// `ttl` re-arms the hard cap from NOW; `idle_timeout` re-arms a
    /// live idle timer. Works in any non-terminal state, including
    /// paused.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn set_lifecycle(&self, update: LifecycleUpdate) -> Result<()> {
        let ttl_seconds = match update.ttl {
            Update::Unchanged => None,
            Update::Clear => Some(0),
            Update::Set(duration) => Some(seconds_to_wire(Some(duration))),
        };
        let idle_timeout_seconds = match update.idle_timeout {
            Update::Unchanged => None,
            Update::Clear => Some(0),
            Update::Set(duration) => Some(seconds_to_wire(Some(duration))),
        };
        let on_idle = match update.on_idle {
            Update::Unchanged => None,
            Update::Clear => Some(idle_action_to_wire(None).into()),
            Update::Set(policy) => Some(idle_action_to_wire(Some(policy)).into()),
        };
        self.client()
            .set_lifecycle(pb::SetLifecycleRequest {
                id: self.id.clone(),
                ttl_seconds,
                idle_timeout_seconds,
                on_idle,
                ..Default::default()
            })
            .await
            .map_err(|error| Error::from_connect(error, "sandbox.set_lifecycle"))?;
        Ok(())
    }
}

/// A sandbox's lifecycle events, read one at a time with
/// [`next`](Self::next). The subscription is dialled on the first call.
pub struct EventStream {
    ctx: ClientContext,
    sandbox_id: String,
    stream: Option<EventWireStream>,
    done: bool,
}

impl EventStream {
    /// The next event, or `None` when the daemon ended the stream.
    ///
    /// # Errors
    ///
    /// Any RPC failure, mapped onto [`Error`].
    pub async fn next(&mut self) -> Result<Option<SandboxEvent>> {
        if self.done {
            return Ok(None);
        }
        if self.stream.is_none() {
            let stream =
                SandboxServiceClient::new(self.ctx.transport.clone(), self.ctx.config.clone())
                    .events(pb::SandboxEventsRequest {
                        sandbox_id: self.sandbox_id.clone(),
                        ..Default::default()
                    })
                    .await
                    .map_err(|error| {
                        self.done = true;
                        Error::from_connect(error, "sandbox.events")
                    })?;
            self.stream = Some(stream);
        }
        let stream = self.stream.as_mut().expect("stream attached above");
        loop {
            match stream.message::<pb::WatchEventsResponse>().await {
                Ok(Some(frame)) => {
                    if let Some(watch_events_response::Payload::Event(event)) =
                        frame.to_owned_message().payload
                    {
                        return Ok(Some(SandboxEvent::from(*event)));
                    }
                    // Keepalives prove liveness but carry no event.
                }
                Ok(None) => {
                    self.done = true;
                    return Ok(None);
                }
                Err(error) => {
                    self.done = true;
                    return Err(Error::from_connect(error, "sandbox.events"));
                }
            }
        }
    }
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sandbox")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ArcBox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ArcBox").finish_non_exhaustive()
    }
}
