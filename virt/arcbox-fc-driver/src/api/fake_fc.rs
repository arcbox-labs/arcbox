//! A Firecracker API socket the tests can script.
//!
//! The interesting paths are the ones a real Firecracker cannot be made to
//! take — a capture that fails and a resume that fails on top of it, a
//! guest the handle believes is frozen and is not, an adopt that finds the
//! VMM answering. This answers the API instead: one closure decides every
//! reply from the request's method, path and body, and every request is
//! recorded in order.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

/// One request the driver made: `"{METHOD} {path} {body}"`, body trimmed to
/// nothing when empty.
pub type Call = String;

/// What to answer: an HTTP status and a JSON body (ignored for 204).
pub type Reply = (u16, String);

/// A scripted Firecracker API on a Unix socket.
pub struct FakeFc {
    socket: PathBuf,
    calls: Arc<Mutex<Vec<Call>>>,
    server: tokio::task::JoinHandle<()>,
}

impl FakeFc {
    /// Serve `reply` on a fresh socket under `dir` until dropped.
    pub fn start<R>(dir: &Path, reply: R) -> Self
    where
        R: Fn(&str, &str) -> Reply + Send + Sync + 'static,
    {
        let socket = dir.join("fake-firecracker.sock");
        let listener = UnixListener::bind(&socket).expect("bind the fake api socket");
        let calls = Arc::new(Mutex::new(Vec::new()));
        let server = tokio::spawn(serve(listener, Arc::new(reply), Arc::clone(&calls)));
        Self {
            socket,
            calls,
            server,
        }
    }

    /// A client that talks to this socket.
    pub fn client(&self) -> fc_sdk::Client {
        fc_sdk::connection::connect(&self.socket)
    }

    /// Every request so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Drop for FakeFc {
    fn drop(&mut self) {
        self.server.abort();
        let _ = std::fs::remove_file(&self.socket);
    }
}

async fn serve<R>(listener: UnixListener, reply: Arc<R>, calls: Arc<Mutex<Vec<Call>>>)
where
    R: Fn(&str, &str) -> Reply + Send + Sync + 'static,
{
    while let Ok((stream, _)) = listener.accept().await {
        let reply = Arc::clone(&reply);
        let calls = Arc::clone(&calls);
        tokio::spawn(async move {
            let _ = answer(stream, &*reply, &calls).await;
        });
    }
}

/// Answer every request on one connection until the peer goes away.
async fn answer<R>(
    mut stream: UnixStream,
    reply: &R,
    calls: &Mutex<Vec<Call>>,
) -> std::io::Result<()>
where
    R: Fn(&str, &str) -> Reply + Sync,
{
    let mut buffered = Vec::new();
    loop {
        let Some((head, body)) = read_request(&mut stream, &mut buffered).await? else {
            return Ok(());
        };
        let mut parts = head.split_whitespace();
        let (method, path) = match (parts.next(), parts.next()) {
            (Some(method), Some(path)) => (method, path),
            _ => return Ok(()),
        };
        let route = format!("{method} {path}");
        calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(format!("{route} {body}").trim_end().to_owned());
        let (status, payload) = reply(&route, &body);
        let response = if status == 204 {
            "HTTP/1.1 204 No Content\r\n\r\n".to_owned()
        } else {
            format!(
                "HTTP/1.1 {status} \r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{payload}",
                payload.len()
            )
        };
        stream.write_all(response.as_bytes()).await?;
    }
}

/// The request line and body of the next request, or `None` at EOF.
async fn read_request(
    stream: &mut UnixStream,
    buffered: &mut Vec<u8>,
) -> std::io::Result<Option<(String, String)>> {
    let head_end = loop {
        if let Some(at) = find(buffered, b"\r\n\r\n") {
            break at + 4;
        }
        if !fill(stream, buffered).await? {
            return Ok(None);
        }
    };
    let head = String::from_utf8_lossy(&buffered[..head_end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let line = line.to_ascii_lowercase();
            let value = line.strip_prefix("content-length:")?;
            value.trim().parse::<usize>().ok()
        })
        .unwrap_or(0);
    while buffered.len() < head_end + length {
        if !fill(stream, buffered).await? {
            return Ok(None);
        }
    }
    let body = String::from_utf8_lossy(&buffered[head_end..head_end + length]).into_owned();
    buffered.drain(..head_end + length);
    let request_line = head.lines().next().unwrap_or_default().to_owned();
    Ok(Some((request_line, body)))
}

/// Read more bytes; `false` at EOF.
async fn fill(stream: &mut UnixStream, buffered: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut chunk = [0u8; 1024];
    let read = stream.read(&mut chunk).await?;
    if read == 0 {
        return Ok(false);
    }
    buffered.extend_from_slice(&chunk[..read]);
    Ok(true)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
