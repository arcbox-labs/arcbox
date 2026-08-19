//! A scriptable guest agent: the [`GuestAgent`] port with no guest.
//!
//! [`FakeAgentFactory`] declares [`Readiness::Probe`], so a boot over it
//! never waits for an announcement it cannot make. Commands answer from a
//! script, files live in a map, and everything the flows fire and forget —
//! the detached clock sync, the legacy-only network reconfiguration — is
//! recorded so a test can assert it happened.
//!
//! The factory is the handle: clone it, hand one clone to
//! [`NodeEnvironment::agent`](crate::environment::NodeEnvironment::agent),
//! and script and assert through the other. Every agent it builds shares
//! the same state.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arcbox_vm_driver::net::NetworkIdentity;
use arcbox_vm_driver::{PreparedVm, VmHandle};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::agent::{
    ClockSync, DirWatch, ExecInput, ExecInputMsg, ExitStatus, FsEvents, GuestAgent,
    GuestAgentFactory, GuestFiles, OutputChunk, PortWait, ProbeGate, Readiness, ReadyGate,
    StartCommand,
};
use crate::boot_proto::NetReconfigCommand;
use crate::error::{Result, VmmError};
use crate::file_proto::{FileStatDto, FsEventDto, KIND_DIR, KIND_FILE};

/// What the guest does when it is asked to start a command.
#[derive(Debug, Clone)]
pub enum Reply {
    /// Write `stdout`, then exit with `status`.
    Exits { stdout: Vec<u8>, status: ExitStatus },
    /// Never exits, and never writes: the output stream stays open until
    /// the caller's own deadline ends the wait. This is the only way to
    /// reach the ready-probe command budget, which exists because a probe
    /// command that does not terminate parked that await forever.
    NeverExits,
    /// The start itself fails.
    Fails(String),
}

impl Reply {
    /// Exit 0 with no output.
    #[must_use]
    pub const fn ok() -> Self {
        Self::Exits {
            stdout: Vec::new(),
            status: ExitStatus::Code(0),
        }
    }

    /// Exit with `code` and no output.
    #[must_use]
    pub const fn code(code: i32) -> Self {
        Self::Exits {
            stdout: Vec::new(),
            status: ExitStatus::Code(code),
        }
    }

    /// Write `stdout`, then exit 0.
    #[must_use]
    pub fn stdout(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Exits {
            stdout: bytes.into(),
            status: ExitStatus::Code(0),
        }
    }
}

/// One entry of the in-memory filesystem.
#[derive(Debug, Clone)]
enum Entry {
    File { data: Vec<u8>, mode: u32 },
    Dir { mode: u32 },
}

/// Everything a factory and the agents it builds share.
#[derive(Default)]
struct Shared {
    scripted: Mutex<BTreeMap<String, Reply>>,
    fallback: Mutex<Option<Reply>>,
    started: Mutex<Vec<Vec<String>>>,
    clock_syncs: AtomicUsize,
    net_reconfigs: Mutex<Vec<NetReconfigCommand>>,
    listening: Mutex<BTreeSet<u16>>,
    files: Mutex<BTreeMap<String, Entry>>,
    /// Live session ends the fake keeps so a `NeverExits` command's stream
    /// stays open instead of reporting a closed channel, and so an exec's
    /// input sink keeps accepting.
    open: Mutex<Vec<Box<dyn Send>>>,
    watchers: Mutex<Vec<mpsc::UnboundedSender<FsEventDto>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Builds [`FakeAgent`]s that answer from a shared script.
#[derive(Clone, Default)]
pub struct FakeAgentFactory {
    shared: Arc<Shared>,
}

impl FakeAgentFactory {
    /// A factory whose guests exit 0 for every command and start empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One of this factory's guests, without a VM to reach it through —
    /// for the host-side wiring that only needs an agent to talk to.
    #[must_use]
    pub fn agent(&self) -> Arc<dyn GuestAgent> {
        Arc::new(FakeAgent {
            shared: Arc::clone(&self.shared),
        })
    }

    /// Answer `cmd` with `reply`.
    pub fn on(&self, cmd: &[&str], reply: Reply) -> &Self {
        lock(&self.shared.scripted).insert(cmd.join(" "), reply);
        self
    }

    /// Answer every command that has no [`Self::on`] entry with `reply`
    /// (the default is [`Reply::ok`]).
    pub fn on_any(&self, reply: Reply) -> &Self {
        *lock(&self.shared.fallback) = Some(reply);
        self
    }

    /// Make `port` answer [`PortWait::Listening`]; anything else is
    /// [`PortWait::Deadline`].
    pub fn listen(&self, port: u16) -> &Self {
        lock(&self.shared.listening).insert(port);
        self
    }

    /// Seed the in-memory filesystem.
    pub fn put_file(&self, path: &str, data: impl Into<Vec<u8>>) -> &Self {
        lock(&self.shared.files).insert(
            path.to_owned(),
            Entry::File {
                data: data.into(),
                mode: 0o644,
            },
        );
        self
    }

    /// Deliver `event` to every watch opened on this agent.
    ///
    /// The streams are unbounded, so the only reason a send fails is a
    /// dropped watch — which is what makes forgetting one distinguishable
    /// from a full buffer, since a closed stream is how the port spells
    /// "the Computer stopped".
    pub fn emit_fs_event(&self, event: &FsEventDto) -> &Self {
        lock(&self.shared.watchers).retain(|tx| tx.send(event.clone()).is_ok());
        self
    }

    /// Read the in-memory filesystem back.
    #[must_use]
    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        match lock(&self.shared.files).get(path) {
            Some(Entry::File { data, .. }) => Some(data.clone()),
            _ => None,
        }
    }

    /// Every command the guest was asked to start, in order.
    #[must_use]
    pub fn started(&self) -> Vec<Vec<String>> {
        lock(&self.shared.started).clone()
    }

    /// How many clock syncs reached the guest. The flows fire this
    /// detached, so a test polls rather than asserting once.
    #[must_use]
    pub fn clock_syncs(&self) -> usize {
        self.shared.clock_syncs.load(Ordering::SeqCst)
    }

    /// Every network reconfiguration the guest was sent — none at all for
    /// a cold boot or an invariant-addressed restore.
    #[must_use]
    pub fn net_reconfigs(&self) -> Vec<NetReconfigCommand> {
        lock(&self.shared.net_reconfigs).clone()
    }
}

#[async_trait]
impl GuestAgentFactory for FakeAgentFactory {
    fn readiness(&self) -> Readiness {
        Readiness::Probe
    }

    async fn arm_readiness(&self, _prepared: &dyn PreparedVm) -> Result<Box<dyn ReadyGate>> {
        Ok(Box::new(ProbeGate))
    }

    fn connect(
        &self,
        _handle: Arc<dyn VmHandle>,
        _net: Option<&NetworkIdentity>,
    ) -> Result<Arc<dyn GuestAgent>> {
        Ok(Arc::new(FakeAgent {
            shared: Arc::clone(&self.shared),
        }))
    }
}

/// The scripted agent itself.
pub struct FakeAgent {
    shared: Arc<Shared>,
}

impl FakeAgent {
    /// Start a session: record the command, then turn its script entry into
    /// an output stream.
    fn start(&self, start: &StartCommand) -> Result<mpsc::Receiver<Result<OutputChunk>>> {
        lock(&self.shared.started).push(start.cmd.clone());
        let reply = lock(&self.shared.scripted)
            .get(&start.cmd.join(" "))
            .cloned()
            .or_else(|| lock(&self.shared.fallback).clone())
            .unwrap_or_else(Reply::ok);
        let (tx, rx) = mpsc::channel(16);
        match reply {
            Reply::Fails(message) => return Err(VmmError::Vsock(message)),
            Reply::NeverExits => lock(&self.shared.open).push(Box::new(tx)),
            Reply::Exits { stdout, status } => {
                tokio::spawn(async move {
                    if !stdout.is_empty() {
                        let _ = tx.send(Ok(OutputChunk::Stdout(stdout))).await;
                    }
                    let _ = tx.send(Ok(OutputChunk::Exit(status))).await;
                });
            }
        }
        Ok(rx)
    }
}

#[async_trait]
impl GuestAgent for FakeAgent {
    async fn run(&self, start: StartCommand) -> Result<mpsc::Receiver<Result<OutputChunk>>> {
        self.start(&start)
    }

    async fn exec(
        &self,
        start: StartCommand,
    ) -> Result<(ExecInput, mpsc::Receiver<Result<OutputChunk>>)> {
        let rx = self.start(&start)?;
        let (input_tx, input_rx) = mpsc::channel::<ExecInputMsg>(8);
        // The guest side of the input channel: kept so a caller's stdin,
        // resize and EOF frames are accepted rather than failing on a
        // closed receiver, as they would against a real agent.
        lock(&self.shared.open).push(Box::new(input_rx));
        Ok((input_tx, rx))
    }

    async fn sync_clock(&self) -> Result<ClockSync> {
        self.shared.clock_syncs.fetch_add(1, Ordering::SeqCst);
        Ok(ClockSync::Synced)
    }

    async fn reconfigure_network(&self, cmd: &NetReconfigCommand) -> Result<()> {
        lock(&self.shared.net_reconfigs).push(cmd.clone());
        Ok(())
    }

    async fn wait_for_port(&self, port: u16, _timeout: Duration) -> Result<PortWait> {
        Ok(if lock(&self.shared.listening).contains(&port) {
            PortWait::Listening
        } else {
            PortWait::Deadline
        })
    }

    fn files(&self) -> &dyn GuestFiles {
        self
    }
}

/// Direct children of `dir` in a flat path map.
fn children<'a>(files: &'a BTreeMap<String, Entry>, dir: &str) -> Vec<(&'a String, &'a Entry)> {
    let prefix = if dir.ends_with('/') {
        dir.to_owned()
    } else {
        format!("{dir}/")
    };
    files
        .iter()
        .filter(|(path, _)| {
            path.strip_prefix(&prefix)
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        })
        .collect()
}

fn stat_of(path: &str, entry: &Entry) -> FileStatDto {
    let (kind, size, mode) = match entry {
        Entry::File { data, mode } => (KIND_FILE, data.len() as u64, *mode),
        Entry::Dir { mode } => (KIND_DIR, 0, *mode),
    };
    FileStatDto {
        name: path.rsplit('/').next().unwrap_or(path).to_owned(),
        kind: kind.to_owned(),
        size,
        mode,
        mtime_secs: 0,
        mtime_nanos: 0,
        uid: 0,
        gid: 0,
        symlink_target: String::new(),
    }
}

#[async_trait]
impl GuestFiles for FakeAgent {
    async fn read(&self, path: &str) -> Result<Vec<u8>> {
        match lock(&self.shared.files).get(path) {
            Some(Entry::File { data, .. }) => Ok(data.clone()),
            Some(Entry::Dir { .. }) => Err(VmmError::Vsock(format!("{path} is a directory"))),
            None => Err(VmmError::PathNotFound(path.to_owned())),
        }
    }

    async fn write(&self, path: &str, mode: u32, data: &[u8]) -> Result<()> {
        lock(&self.shared.files).insert(
            path.to_owned(),
            Entry::File {
                data: data.to_vec(),
                mode,
            },
        );
        Ok(())
    }

    async fn stat(&self, path: &str) -> Result<FileStatDto> {
        lock(&self.shared.files)
            .get(path)
            .map(|entry| stat_of(path, entry))
            .ok_or_else(|| VmmError::PathNotFound(path.to_owned()))
    }

    async fn list(&self, path: &str) -> Result<Vec<FileStatDto>> {
        let files = lock(&self.shared.files);
        match files.get(path) {
            Some(Entry::Dir { .. }) => Ok(children(&files, path)
                .into_iter()
                .map(|(child, entry)| stat_of(child, entry))
                .collect()),
            Some(Entry::File { .. }) => Err(VmmError::NotADirectory(path.to_owned())),
            None => Err(VmmError::PathNotFound(path.to_owned())),
        }
    }

    async fn make_dir(&self, path: &str, mode: u32) -> Result<()> {
        let mut files = lock(&self.shared.files);
        for (index, _) in path.match_indices('/').skip(1) {
            files
                .entry(path[..index].to_owned())
                .or_insert(Entry::Dir { mode });
        }
        files.entry(path.to_owned()).or_insert(Entry::Dir { mode });
        Ok(())
    }

    async fn remove(&self, path: &str, recursive: bool) -> Result<()> {
        let mut files = lock(&self.shared.files);
        if !files.contains_key(path) {
            return Err(VmmError::PathNotFound(path.to_owned()));
        }
        let descendants: Vec<String> = files
            .keys()
            .filter(|key| key.starts_with(&format!("{path}/")))
            .cloned()
            .collect();
        if !descendants.is_empty() && !recursive {
            return Err(VmmError::DirectoryNotEmpty(path.to_owned()));
        }
        for key in descendants {
            files.remove(&key);
        }
        files.remove(path);
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let mut files = lock(&self.shared.files);
        let entry = files
            .remove(from)
            .ok_or_else(|| VmmError::PathNotFound(from.to_owned()))?;
        let moved: Vec<String> = files
            .keys()
            .filter(|key| key.starts_with(&format!("{from}/")))
            .cloned()
            .collect();
        for key in moved {
            let entry = files.remove(&key).expect("key just listed");
            files.insert(format!("{to}{}", &key[from.len()..]), entry);
        }
        files.insert(to.to_owned(), entry);
        Ok(())
    }

    async fn watch(&self, path: &str, _recursive: bool) -> Result<DirWatch> {
        if !lock(&self.shared.files).contains_key(path) {
            return Err(VmmError::PathNotFound(path.to_owned()));
        }
        let (tx, events) = mpsc::unbounded_channel();
        lock(&self.shared.watchers).push(tx);
        Ok(DirWatch::new(Box::new(FakeWatch { events })))
    }
}

/// The fake's watch stream: whatever [`FakeAgentFactory::emit_fs_event`]
/// pushes, ending cleanly once the factory that owns it goes away.
struct FakeWatch {
    events: mpsc::UnboundedReceiver<FsEventDto>,
}

#[async_trait]
impl FsEvents for FakeWatch {
    async fn next_event(&mut self) -> Result<Option<FsEventDto>> {
        Ok(self.events.recv().await)
    }
}
