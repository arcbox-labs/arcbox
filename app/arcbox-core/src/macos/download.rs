//! Downloading macOS restore images (IPSWs) to a local cache.
//!
//! Apple's API yields a remote IPSW URL but not the bytes; the installer needs a
//! local file. This streams the URL into a cache directory: the download is written
//! to a sibling `.part` file and atomically renamed on success, so an interrupted
//! download never looks like a valid cache entry. SHA-256 is computed for integrity
//! and verified against `expected` when known (version resolution will supply one;
//! `latest` has no published digest, so the size check + atomic rename guard it).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// Streams `url` into `cache_dir`, returning the path to the cached IPSW.
///
/// The cache file name is the URL's last path segment. A complete cache hit is
/// reused (re-verified against `expected_sha256` when provided, otherwise trusted).
/// `on_progress` receives the downloaded fraction in `0.0..=1.0`, best-effort — only
/// when the server reports a content length.
pub(super) async fn download_ipsw(
    url: &str,
    cache_dir: &Path,
    expected_sha256: Option<&str>,
    mut on_progress: impl FnMut(f64),
) -> Result<PathBuf> {
    let file_name = url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CoreError::macos(format!("cannot derive a file name from URL: {url}")))?;
    if file_name.contains("..") || file_name.contains('/') {
        return Err(CoreError::macos(format!(
            "unsafe IPSW file name: {file_name}"
        )));
    }

    std::fs::create_dir_all(cache_dir)?;
    let dest = cache_dir.join(file_name);

    if dest.exists() {
        match expected_sha256 {
            Some(expected) if !sha256_file(&dest)?.eq_ignore_ascii_case(expected) => {
                tracing::warn!(
                    "cached IPSW {} failed checksum, re-downloading",
                    dest.display()
                );
                std::fs::remove_file(&dest)?;
            }
            _ => return Ok(dest),
        }
    }

    let part = dest.with_extension("part");
    let _ = std::fs::remove_file(&part);

    let mut resp = reqwest::get(url)
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| CoreError::macos(format!("download {url}: {e}")))?;

    let total = resp.content_length();
    let mut file = std::fs::File::create(&part)?;
    let mut hasher = Sha256::new();
    let mut downloaded: u64 = 0;
    let mut last_msg = String::new();

    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| CoreError::macos(format!("download {url}: {e}")))?
    {
        let bytes = chunk.as_ref();
        file.write_all(bytes)?;
        hasher.update(bytes);
        downloaded += bytes.len() as u64;
        if let Some(total) = total.filter(|t| *t > 0) {
            let frac = (downloaded as f64 / total as f64).min(1.0);
            let msg = format!("{:.0}", frac * 100.0);
            if msg != last_msg {
                last_msg = msg;
                on_progress(frac);
            }
        }
    }
    file.flush()?;
    drop(file);

    if let Some(total) = total {
        if downloaded != total {
            let _ = std::fs::remove_file(&part);
            return Err(CoreError::macos(format!(
                "download {url}: truncated (expected {total} bytes, got {downloaded})"
            )));
        }
    }

    let actual = format!("{:x}", hasher.finalize());
    if let Some(expected) = expected_sha256 {
        if !actual.eq_ignore_ascii_case(expected) {
            let _ = std::fs::remove_file(&part);
            return Err(CoreError::macos(format!(
                "download {url}: checksum mismatch (expected {expected}, got {actual})"
            )));
        }
    }

    std::fs::rename(&part, &dest)?;
    Ok(dest)
}

/// Computes the hex SHA-256 of a file, reading it in chunks.
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
