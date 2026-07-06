//! Chunked restore of a published macOS system disk.
//!
//! A manifest splits the disk into fixed-size, independently decompressible
//! zstd frames (`disk.NNN.zst`). [`fetch_disk`] downloads them with bounded
//! parallelism, verifies each stored object against its manifest hash,
//! decompresses each frame, and sparse-writes it at its fixed offset — the
//! compressed bytes are streamed through decompression and never staged on
//! disk. Per-chunk integrity (compressed hash + exact decompressed length,
//! plus zstd's own per-frame content checksum) combined with deterministic
//! offset placement makes the assembled image correct without an end-to-end
//! re-read of the multi-gigabyte result.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::remote::{DiskChunk, DiskManifest, RemoteLocation};
use crate::error::{CoreError, Result};

/// Concurrent chunk downloads: enough to keep a fast link busy and overlap
/// decompression across cores without flooding the CDN or the runtime.
const DOWNLOAD_CONCURRENCY: usize = 4;

/// Per-chunk transient-failure budget. A chunk is small enough (≤ ~480 MiB
/// compressed) that a failed attempt simply re-downloads it from the start —
/// no byte-range resume, which keeps the streaming decoder state trivial.
const DOWNLOAD_RETRIES: u32 = 4;
const DOWNLOAD_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Block granularity for zero detection; a multiple of the APFS block size.
const SPARSE_BLOCK: usize = 64 * 1024;
static ZERO_BLOCK: [u8; SPARSE_BLOCK] = [0u8; SPARSE_BLOCK];

/// Zero-skipping positioned block writer: writes decompressed bytes at
/// `base + offset` into a pre-sized file, never writing all-zero blocks (so
/// skipped ranges stay holes). One writer per chunk; `base` is the chunk's
/// absolute disk offset. Both `base` (a multiple of `chunk_size`) and the
/// block size are aligned to the block grid, so chunks written in parallel
/// never share a block and their positioned writes never overlap.
///
/// Alignment comes from buffering to fixed-size blocks; the `Write::flush`
/// impl deliberately does not drain a partial block (the decompressor flushes
/// mid-stream), the tail is written by [`SparseWriter::finish`].
struct SparseWriter {
    file: Arc<std::fs::File>,
    base: u64,
    offset: u64,
    buf: Vec<u8>,
}

impl SparseWriter {
    fn new(file: Arc<std::fs::File>, base: u64) -> Self {
        Self {
            file,
            base,
            offset: 0,
            buf: Vec::with_capacity(SPARSE_BLOCK),
        }
    }

    fn flush_block(&mut self) -> std::io::Result<()> {
        use std::os::unix::fs::FileExt;
        // Slice equality is a memcmp — much faster than a per-byte scan.
        if self.buf.as_slice() != &ZERO_BLOCK[..self.buf.len()] {
            self.file.write_all_at(&self.buf, self.base + self.offset)?;
        }
        self.offset += self.buf.len() as u64;
        self.buf.clear();
        Ok(())
    }

    /// Drains the partial tail block and returns the bytes this chunk covered.
    fn finish(mut self) -> std::io::Result<u64> {
        if !self.buf.is_empty() {
            self.flush_block()?;
        }
        Ok(self.offset)
    }
}

impl Write for SparseWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let take = (SPARSE_BLOCK - self.buf.len()).min(data.len());
        self.buf.extend_from_slice(&data[..take]);
        if self.buf.len() == SPARSE_BLOCK {
            self.flush_block()?;
        }
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Hex-encodes bytes (lowercase).
pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Verifies a hex SHA-256 against an expected manifest value.
pub(super) fn verify_sha256(what: &str, actual: &[u8], expected: &str) -> Result<()> {
    let actual = hex(actual);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(CoreError::macos(format!(
            "{what}: checksum mismatch (expected {expected}, got {actual})"
        )));
    }
    Ok(())
}

/// Hash + decompress + sparse-write sink for one chunk's compressed stream.
struct ChunkSink {
    decoder: zstd::stream::write::Decoder<'static, SparseWriter>,
    hasher: Sha256,
    received: u64,
}

impl ChunkSink {
    fn new(file: Arc<std::fs::File>, base: u64) -> Result<Self> {
        Ok(Self {
            decoder: zstd::stream::write::Decoder::new(SparseWriter::new(file, base))
                .map_err(|e| CoreError::macos(format!("zstd init: {e}")))?,
            hasher: Sha256::new(),
            received: 0,
        })
    }

    fn consume(&mut self, bytes: &[u8], path: &str) -> Result<()> {
        self.hasher.update(bytes);
        self.decoder
            .write_all(bytes)
            .map_err(|e| CoreError::macos(format!("decompress {path}: {e}")))?;
        self.received += bytes.len() as u64;
        Ok(())
    }

    /// Finalizes decompression and verifies the chunk: exact compressed size,
    /// compressed SHA-256, and exact decompressed length.
    fn finish(mut self, chunk: &DiskChunk, expected_len: u64) -> Result<()> {
        self.decoder
            .flush()
            .map_err(|e| CoreError::macos(format!("decompress {}: {e}", chunk.path)))?;
        let written = self
            .decoder
            .into_inner()
            .finish()
            .map_err(|e| CoreError::macos(format!("write {}: {e}", chunk.path)))?;
        if self.received != chunk.size {
            return Err(CoreError::macos(format!(
                "{}: truncated download (expected {} compressed bytes, got {})",
                chunk.path, chunk.size, self.received
            )));
        }
        verify_sha256(&chunk.path, &self.hasher.finalize(), &chunk.sha256)?;
        if written != expected_len {
            return Err(CoreError::macos(format!(
                "{}: decompressed to {written} bytes, expected {expected_len}",
                chunk.path
            )));
        }
        Ok(())
    }
}

/// Downloads, verifies, and sparse-writes every disk chunk into `dst`.
///
/// `location` is the manifest's own location; chunk paths resolve relative to
/// it. Chunks download with bounded parallelism; `on_progress` receives the
/// downloaded fraction (weighted by compressed bytes) as each chunk completes.
///
/// # Errors
/// Returns an error on any download, integrity, or write failure. The whole
/// operation is cancellable: dropping the returned future aborts every
/// in-flight chunk at its next await point.
pub(super) async fn fetch_disk(
    location: &RemoteLocation,
    disk: &DiskManifest,
    dst: &Path,
    mut on_progress: impl FnMut(f64),
) -> Result<()> {
    let file = Arc::new(std::fs::File::create(dst)?);
    file.set_len(disk.uncompressed_size)?;
    let total_compressed: u64 = disk.chunks.iter().map(|c| c.size).sum();

    let client = reqwest::Client::new();
    let semaphore = Arc::new(Semaphore::new(DOWNLOAD_CONCURRENCY));
    let mut tasks = JoinSet::new();
    for (index, chunk) in disk.chunks.iter().enumerate() {
        let base = index as u64 * disk.chunk_size;
        let expected_len = (disk.uncompressed_size - base).min(disk.chunk_size);
        let chunk_location = location.join(&chunk.path)?;
        let client = client.clone();
        let file = Arc::clone(&file);
        let chunk = chunk.clone();
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            // The permit bounds concurrent downloads; the remaining tasks park
            // here cheaply until a slot frees.
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|_| CoreError::macos("disk download canceled"))?;
            fetch_chunk(&client, &chunk_location, &chunk, base, expected_len, file).await?;
            Ok::<u64, CoreError>(chunk.size)
        });
    }

    on_progress(0.0);
    let mut downloaded = 0u64;
    while let Some(joined) = tasks.join_next().await {
        downloaded += joined.map_err(|e| CoreError::macos(format!("disk chunk task: {e}")))??;
        if total_compressed > 0 {
            on_progress((downloaded as f64 / total_compressed as f64).min(1.0));
        }
    }
    Ok(())
}

/// Fetches one chunk from its resolved location into the shared disk file.
async fn fetch_chunk(
    client: &reqwest::Client,
    location: &RemoteLocation,
    chunk: &DiskChunk,
    base: u64,
    expected_len: u64,
    file: Arc<std::fs::File>,
) -> Result<()> {
    match location {
        RemoteLocation::Http(url) => {
            let mut attempt = 0u32;
            loop {
                match download_chunk_http(client, url, chunk, base, expected_len, Arc::clone(&file))
                    .await
                {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        attempt += 1;
                        if attempt > DOWNLOAD_RETRIES {
                            return Err(CoreError::macos(format!(
                                "{}: giving up after {DOWNLOAD_RETRIES} attempts: {e}",
                                chunk.path
                            )));
                        }
                        tracing::warn!(
                            "chunk {}: {e}; retrying ({attempt}/{DOWNLOAD_RETRIES})",
                            chunk.path
                        );
                        tokio::time::sleep(DOWNLOAD_RETRY_DELAY).await;
                    }
                }
            }
        }
        RemoteLocation::File(path) => {
            download_chunk_file(path, chunk, base, expected_len, file).await
        }
    }
}

/// Streams a chunk over HTTP through decompression into the sparse file.
async fn download_chunk_http(
    client: &reqwest::Client,
    url: &reqwest::Url,
    chunk: &DiskChunk,
    base: u64,
    expected_len: u64,
    file: Arc<std::fs::File>,
) -> Result<()> {
    let mut sink = ChunkSink::new(file, base)?;
    let mut resp = client
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| CoreError::macos(format!("download {url}: {e}")))?;
    while let Some(bytes) = resp
        .chunk()
        .await
        .map_err(|e| CoreError::macos(format!("download {url}: {e}")))?
    {
        sink.consume(&bytes, &chunk.path)?;
    }
    sink.finish(chunk, expected_len)
}

/// Reads a chunk from a local file through decompression into the sparse file.
///
/// Uses `tokio::fs` (not `std`): every read is an await point, which keeps the
/// decompression cancellable rather than running to completion inside a single
/// poll and pinning a runtime worker.
async fn download_chunk_file(
    path: &Path,
    chunk: &DiskChunk,
    base: u64,
    expected_len: u64,
    file: Arc<std::fs::File>,
) -> Result<()> {
    let mut sink = ChunkSink::new(file, base)?;
    let mut src = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        sink.consume(&buf[..n], &chunk.path)?;
    }
    sink.finish(chunk, expected_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Splits `raw` into `chunk_size` slices, zstd-compresses each into `dir`
    /// as `disk.NNN.zst`, and returns the matching manifest.
    fn publish_disk(dir: &Path, raw: &[u8], chunk_size: usize) -> DiskManifest {
        let mut chunks = Vec::new();
        for (i, slice) in raw.chunks(chunk_size).enumerate() {
            let compressed = zstd::encode_all(slice, 3).unwrap();
            let path = format!("disk.{i:03}.zst");
            std::fs::write(dir.join(&path), &compressed).unwrap();
            chunks.push(DiskChunk {
                path,
                size: compressed.len() as u64,
                sha256: hex(&Sha256::digest(&compressed)),
            });
        }
        DiskManifest {
            disk_format: "raw".into(),
            uncompressed_size: raw.len() as u64,
            chunk_size: chunk_size as u64,
            chunks,
        }
    }

    #[test]
    fn sparse_writer_skips_zero_blocks() {
        // APFS only keeps holes in files above a size threshold (verified
        // empirically: fully materialized at 16 MiB, sparse at 256 MiB), so
        // this test must run at realistic scale. Data is streamed block-wise
        // to keep the test memory-light.
        const TOTAL: u64 = 256 * 1024 * 1024;
        let dir = tempdir().unwrap();
        let path = dir.path().join("sparse.bin");

        let file = std::fs::File::create(&path).unwrap();
        file.set_len(TOTAL).unwrap();
        let mut w = SparseWriter::new(Arc::new(file), 0);
        let data = vec![7u8; SPARSE_BLOCK];
        let zeros = vec![0u8; SPARSE_BLOCK];
        let blocks = TOTAL / SPARSE_BLOCK as u64;
        for i in 0..blocks {
            // Non-zero first and last blocks, zeros everywhere between.
            if i == 0 || i == blocks - 1 {
                w.write_all(&data).unwrap();
            } else {
                w.write_all(&zeros).unwrap();
            }
        }
        assert_eq!(w.finish().unwrap(), TOTAL);

        // Content: first/last blocks hold data, an interior block reads zero.
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(&path).unwrap();
        let mut buf = vec![0u8; SPARSE_BLOCK];
        f.read_exact_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
        f.read_exact_at(&mut buf, TOTAL - SPARSE_BLOCK as u64)
            .unwrap();
        assert_eq!(buf, data);
        f.read_exact_at(&mut buf, TOTAL / 2).unwrap();
        assert_eq!(buf, zeros);

        // Allocation: the zero interior must be holes, not written blocks.
        let allocated = std::fs::metadata(&path)
            .map(|m| std::os::unix::fs::MetadataExt::blocks(&m) * 512)
            .unwrap();
        assert!(
            allocated < 8 * 1024 * 1024,
            "expected sparse file, got {allocated} bytes allocated for {TOTAL}"
        );
    }

    #[tokio::test]
    async fn assembles_chunks_from_local_files() {
        let dir = tempdir().unwrap();
        let publish = dir.path().join("publish");
        std::fs::create_dir_all(&publish).unwrap();

        // Three full chunks (data, zero gap, data) plus a partial last chunk,
        // exercising the remainder and the hole-skipping path.
        let mut raw = vec![0u8; 5 * SPARSE_BLOCK + SPARSE_BLOCK / 2];
        raw[0..SPARSE_BLOCK].fill(0xAB);
        raw[4 * SPARSE_BLOCK..5 * SPARSE_BLOCK].fill(0xCD);
        raw[5 * SPARSE_BLOCK..].fill(0xEE);
        let disk = publish_disk(&publish, &raw, 2 * SPARSE_BLOCK);
        assert_eq!(disk.chunks.len(), 3);

        let location = RemoteLocation::File(publish.join("manifest.json"));
        let dst = dir.path().join("disk.img");
        fetch_disk(&location, &disk, &dst, |_| {}).await.unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), raw);
    }

    #[tokio::test]
    async fn rejects_chunk_with_wrong_hash() {
        let dir = tempdir().unwrap();
        let publish = dir.path().join("publish");
        std::fs::create_dir_all(&publish).unwrap();

        let raw = vec![0xABu8; SPARSE_BLOCK];
        let mut disk = publish_disk(&publish, &raw, SPARSE_BLOCK);
        disk.chunks[0].sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".into();

        let location = RemoteLocation::File(publish.join("manifest.json"));
        let dst = dir.path().join("disk.img");
        let err = fetch_disk(&location, &disk, &dst, |_| {})
            .await
            .unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
    }

    /// First GET on a connection sends only half the body then hangs up; every
    /// later GET serves the whole body. Drives the chunk retry path.
    async fn serve_flaky(listener: tokio::net::TcpListener, body: Vec<u8>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let first = Arc::new(AtomicBool::new(true));
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            let first = Arc::clone(&first);
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                if first.swap(false, Ordering::SeqCst) {
                    // Truncate mid-body then drop: a broken connection.
                    let _ = sock.write_all(&body[..body.len() / 2]).await;
                } else {
                    let _ = sock.write_all(&body).await;
                }
            });
        }
    }

    #[tokio::test]
    async fn http_chunk_retries_after_connection_drop() {
        let mut raw = vec![0xABu8; SPARSE_BLOCK];
        raw.extend_from_slice(&vec![0u8; SPARSE_BLOCK]);
        raw.extend_from_slice(&vec![0xCDu8; SPARSE_BLOCK]);
        let body = zstd::encode_all(&raw[..], 3).unwrap();
        let disk = DiskManifest {
            disk_format: "raw".into(),
            uncompressed_size: raw.len() as u64,
            chunk_size: raw.len() as u64,
            chunks: vec![DiskChunk {
                path: "disk.000.zst".into(),
                size: body.len() as u64,
                sha256: hex(&Sha256::digest(&body)),
            }],
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_flaky(listener, body));

        let location = RemoteLocation::parse(&format!("http://{addr}/manifest.json"));
        let dir = tempdir().unwrap();
        let dst = dir.path().join("disk.img");
        fetch_disk(&location, &disk, &dst, |_| {}).await.unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), raw);
    }
}
