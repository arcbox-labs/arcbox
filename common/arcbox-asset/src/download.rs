//! Streaming download with SHA-256 verification and atomic writes.

use crate::error::{AssetError, Result};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

/// HTTP request timeout in seconds.
const HTTP_TIMEOUT_SECS: u64 = 300;

/// User-Agent header sent with all requests.
const USER_AGENT: &str = "arcbox-asset/0.1";

/// Compute the SHA-256 hex digest of a file.
pub async fn sha256_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path).await?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// Returns a sibling temp path unique per process and per call.
///
/// A fixed shared temp name (`dest.tmp`) lets two concurrent downloads of
/// the same destination truncate and interleave into one file — each
/// writer's *stream* hash still verifies, so a corrupt file gets renamed
/// into place as "verified". Uniqueness makes every writer's temp private;
/// the final `rename` stays atomic, so concurrent installs degrade to
/// last-writer-wins with a genuinely verified file.
fn unique_temp_path(dest: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let file_name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    dest.with_file_name(format!("{file_name}.{}.{seq}.tmp", std::process::id()))
}

/// Download `url` to `dest`, verifying that the content matches
/// `expected_sha256`. The hash is computed incrementally while streaming.
///
/// The file is first written to a `.tmp` sibling and atomically renamed on
/// success. On checksum failure the temp file is removed.
///
/// `on_progress` is called after every chunk with (bytes_downloaded, total_bytes).
pub async fn download_and_verify(
    url: &str,
    dest: &Path,
    expected_sha256: &str,
    name: &str,
    on_progress: impl Fn(u64, Option<u64>) + Send + Sync,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| AssetError::Download(format!("failed to create HTTP client: {e}")))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AssetError::Download(format!("request failed for {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(AssetError::Download(format!(
            "HTTP {} for {url}",
            response.status()
        )));
    }

    let total = response.content_length();
    let mut downloaded: u64 = 0;

    // Write to a private temp file, then rename atomically.
    let temp_path = unique_temp_path(dest);
    let outcome: Result<()> = async {
        let mut file = tokio::fs::File::create(&temp_path).await?;
        let mut stream = response.bytes_stream();
        let mut hasher = Sha256::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| AssetError::Download(format!("stream error: {e}")))?;
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            on_progress(downloaded, total);
        }

        file.flush().await?;
        drop(file);

        let actual_sha = format!("{:x}", hasher.finalize());
        if actual_sha != expected_sha256 {
            return Err(AssetError::ChecksumMismatch {
                name: name.to_string(),
                expected: expected_sha256.to_string(),
                actual: actual_sha,
            });
        }

        tokio::fs::rename(&temp_path, dest).await?;
        Ok(())
    }
    .await;

    // Unique temp names would otherwise accumulate on failure.
    if outcome.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }
    outcome
}

/// Download `url` to `dest` without checksum verification.
///
/// Useful for fetching manifests or metadata files whose checksums are
/// validated after parsing.
pub async fn download_raw(url: &str, dest: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(HTTP_TIMEOUT_SECS))
        .user_agent(USER_AGENT)
        .build()
        .map_err(|e| AssetError::Download(format!("failed to create HTTP client: {e}")))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| AssetError::Download(format!("request failed for {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(AssetError::Download(format!(
            "HTTP {} for {url}",
            response.status()
        )));
    }

    let temp_path = unique_temp_path(dest);
    let outcome: Result<()> = async {
        let mut file = tokio::fs::File::create(&temp_path).await?;
        let mut stream = response.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| AssetError::Download(format!("stream error: {e}")))?;
            file.write_all(&chunk).await?;
        }

        file.flush().await?;
        drop(file);

        tokio::fs::rename(&temp_path, dest).await?;
        Ok(())
    }
    .await;

    if outcome.is_err() {
        let _ = tokio::fs::remove_file(&temp_path).await;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Serves `body` over HTTP to every incoming connection until dropped.
    async fn serve_fixture(body: &'static [u8]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture listener");
        let addr = listener.local_addr().expect("fixture addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(header.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                });
            }
        });
        format!("http://{addr}/asset")
    }

    fn leftover_temp_files(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .expect("read dir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "tmp"))
            .collect()
    }

    #[tokio::test]
    async fn checksum_mismatch_removes_temp_file() {
        const BODY: &[u8] = b"asset-bytes";
        let url = serve_fixture(BODY).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("asset.bin");

        let err = download_and_verify(&url, &dest, "deadbeef", "asset", |_, _| {})
            .await
            .expect_err("wrong sha must fail");
        assert!(matches!(err, AssetError::ChecksumMismatch { .. }));
        assert!(!dest.exists(), "dest must not be created on failure");
        assert!(
            leftover_temp_files(dir.path()).is_empty(),
            "failed download must not leak temp files"
        );
    }

    #[tokio::test]
    async fn concurrent_downloads_of_same_dest_yield_verified_file() {
        // Regression: a fixed `dest.tmp` let two concurrent writers truncate
        // and interleave the same temp file, then rename a corrupt file that
        // each writer's own stream hash had "verified".
        const BODY: &[u8] = b"shared-destination-bytes";
        let url = serve_fixture(BODY).await;
        let sha = format!("{:x}", Sha256::digest(BODY));
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("tool");

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let url = url.clone();
                let sha = sha.clone();
                let dest = dest.clone();
                tokio::spawn(async move {
                    download_and_verify(&url, &dest, &sha, "tool", |_, _| {}).await
                })
            })
            .collect();
        for t in tasks {
            t.await.expect("task").expect("download");
        }

        let on_disk = tokio::fs::read(&dest).await.expect("read dest");
        assert_eq!(on_disk, BODY, "installed file must match the payload");
        assert!(
            leftover_temp_files(dir.path()).is_empty(),
            "successful downloads must not leak temp files"
        );
    }
}
