//! Streaming download with SHA-256 verification and atomic writes.

use crate::error::{AssetError, Result};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::Path;
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
    on_progress: impl Fn(u64, Option<u64>),
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

    // Write to temp file, then rename atomically.
    let temp_path = dest.with_extension("tmp");
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
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(AssetError::ChecksumMismatch {
            name: name.to_string(),
            expected: expected_sha256.to_string(),
            actual: actual_sha,
        });
    }

    tokio::fs::rename(&temp_path, dest).await?;
    Ok(())
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

    let temp_path = dest.with_extension("tmp");
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
