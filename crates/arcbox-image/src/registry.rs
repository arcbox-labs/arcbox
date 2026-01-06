//! Docker Registry v2 API client.
//!
//! Supports Docker Hub and OCI-compliant registries with token authentication.

use futures::StreamExt;
use reqwest::{header, Client, StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, instrument, trace};

use crate::error::{ImageError, Result};
use crate::manifest::{ImageManifest, ManifestList};
use crate::ImageRef;

/// Docker Hub registry URL.
const DOCKER_REGISTRY_URL: &str = "https://registry-1.docker.io";

/// Accept header value for manifest requests.
const ACCEPT_MANIFEST: &str = concat!(
    "application/vnd.docker.distribution.manifest.v2+json, ",
    "application/vnd.docker.distribution.manifest.list.v2+json, ",
    "application/vnd.oci.image.manifest.v1+json, ",
    "application/vnd.oci.image.index.v1+json"
);

/// Registry authentication credentials.
#[derive(Debug, Clone)]
pub struct RegistryAuth {
    /// Username.
    pub username: String,
    /// Password or token.
    pub password: String,
}

/// Token response from Docker Hub auth service.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

/// WWW-Authenticate challenge parsed from 401 response.
#[derive(Debug, Default)]
struct AuthChallenge {
    realm: String,
    service: String,
    scope: String,
}

/// Manifest fetch result - can be either a manifest or manifest list.
#[derive(Debug, Clone)]
pub enum ManifestResponse {
    /// Single-platform manifest.
    Manifest(ImageManifest),
    /// Multi-platform manifest list.
    ManifestList(ManifestList),
}

/// Registry client for Docker Registry v2 API.
pub struct RegistryClient {
    /// HTTP client.
    client: Client,
    /// Registry base URL.
    registry_url: String,
    /// Optional basic auth credentials.
    auth: Option<RegistryAuth>,
    /// Cached bearer token (per-repository).
    tokens: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

/// Default request timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default connect timeout in seconds.
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

impl RegistryClient {
    /// Creates a new registry client for the specified registry.
    ///
    /// # Arguments
    ///
    /// * `registry` - Registry hostname (e.g., "docker.io", "ghcr.io")
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be created (should not happen in practice).
    #[must_use]
    pub fn new(registry: impl Into<String>) -> Self {
        let registry = registry.into();
        let registry_url = Self::registry_to_url(&registry);

        let client = Client::builder()
            .user_agent("arcbox/0.1")
            .timeout(std::time::Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(std::time::Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS))
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to create HTTP client");

        Self {
            client,
            registry_url,
            auth: None,
            tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Sets authentication credentials.
    #[must_use]
    pub fn with_auth(mut self, auth: RegistryAuth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Gets the registry URL.
    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry_url
    }

    /// Converts registry hostname to base URL.
    fn registry_to_url(registry: &str) -> String {
        match registry {
            "docker.io" => DOCKER_REGISTRY_URL.to_string(),
            r if r.starts_with("http://") || r.starts_with("https://") => r.to_string(),
            r => format!("https://{r}"),
        }
    }

    /// Checks if an image exists in the registry.
    ///
    /// # Errors
    ///
    /// Returns an error if the check fails due to network or auth issues.
    #[instrument(skip(self))]
    pub async fn exists(&self, reference: &ImageRef) -> Result<bool> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            self.registry_url, reference.repository, reference.reference
        );

        let response = self
            .request_with_auth(reqwest::Method::HEAD, &url, &reference.repository)
            .await?;

        Ok(response.status().is_success())
    }

    /// Gets an image manifest from the registry.
    ///
    /// Returns either a single manifest or a manifest list for multi-arch images.
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be fetched or parsed.
    #[instrument(skip(self))]
    pub async fn get_manifest(&self, reference: &ImageRef) -> Result<ManifestResponse> {
        let url = format!(
            "{}/v2/{}/manifests/{}",
            self.registry_url, reference.repository, reference.reference
        );

        debug!(url = %url, "fetching manifest");

        let response = self
            .request_with_auth(reqwest::Method::GET, &url, &reference.repository)
            .await?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(ImageError::NotFound(reference.full_name()));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ImageError::Registry(format!(
                "failed to fetch manifest: {status} - {body}"
            )));
        }

        // Check content type to determine manifest type.
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let body = response.bytes().await.map_err(|e| {
            ImageError::Registry(format!("failed to read manifest body: {e}"))
        })?;

        trace!(content_type = %content_type, body_len = body.len(), "received manifest");

        // Parse based on content type.
        if content_type.contains("manifest.list") || content_type.contains("image.index") {
            let list: ManifestList = serde_json::from_slice(&body)?;
            Ok(ManifestResponse::ManifestList(list))
        } else {
            let manifest: ImageManifest = serde_json::from_slice(&body)?;
            Ok(ManifestResponse::Manifest(manifest))
        }
    }

    /// Gets a manifest by digest (used after resolving from manifest list).
    ///
    /// # Errors
    ///
    /// Returns an error if the manifest cannot be fetched.
    #[instrument(skip(self))]
    pub async fn get_manifest_by_digest(
        &self,
        repository: &str,
        digest: &str,
    ) -> Result<ImageManifest> {
        let url = format!("{}/v2/{}/manifests/{}", self.registry_url, repository, digest);

        debug!(url = %url, "fetching manifest by digest");

        let response = self
            .request_with_auth(reqwest::Method::GET, &url, repository)
            .await?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ImageError::Registry(format!(
                "failed to fetch manifest: {status} - {body}"
            )));
        }

        let body = response.bytes().await.map_err(|e| {
            ImageError::Registry(format!("failed to read manifest body: {e}"))
        })?;

        let manifest: ImageManifest = serde_json::from_slice(&body)?;
        Ok(manifest)
    }

    /// Gets a blob from the registry.
    ///
    /// Returns the raw blob data. For layers, this is typically gzipped tar.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be fetched.
    #[instrument(skip(self))]
    pub async fn get_blob(&self, reference: &ImageRef, digest: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            self.registry_url, reference.repository, digest
        );

        debug!(url = %url, "fetching blob");

        let response = self
            .request_with_auth(reqwest::Method::GET, &url, &reference.repository)
            .await?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(ImageError::NotFound(format!("blob {digest}")));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ImageError::Registry(format!(
                "failed to fetch blob: {status} - {body}"
            )));
        }

        let bytes = response.bytes().await.map_err(|e| {
            ImageError::Registry(format!("failed to read blob body: {e}"))
        })?;

        Ok(bytes.to_vec())
    }

    /// Gets a blob with progress callback.
    ///
    /// Streams the blob and calls the callback with progress updates.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be fetched.
    #[instrument(skip(self, progress))]
    pub async fn get_blob_with_progress<F>(
        &self,
        reference: &ImageRef,
        digest: &str,
        expected_size: u64,
        mut progress: F,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(u64, u64),
    {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            self.registry_url, reference.repository, digest
        );

        debug!(url = %url, expected_size = expected_size, "fetching blob with progress");

        let response = self
            .request_with_auth(reqwest::Method::GET, &url, &reference.repository)
            .await?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(ImageError::NotFound(format!("blob {digest}")));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ImageError::Registry(format!(
                "failed to fetch blob: {status} - {body}"
            )));
        }

        // Stream the response and track progress.
        let mut stream = response.bytes_stream();
        // Pre-allocate based on expected size, capped at reasonable limit for safety.
        let capacity = usize::try_from(expected_size).unwrap_or(usize::MAX).min(256 * 1024 * 1024);
        let mut data = Vec::with_capacity(capacity);
        let mut downloaded: u64 = 0;

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                ImageError::Registry(format!("failed to read blob chunk: {e}"))
            })?;
            downloaded += chunk.len() as u64;
            data.extend_from_slice(&chunk);
            progress(downloaded, expected_size);
        }

        Ok(data)
    }

    /// Gets a blob by repository name with optional progress callback.
    ///
    /// This variant takes owned strings to work better with async closures.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be fetched.
    #[instrument(skip(self, progress))]
    pub async fn get_blob_by_repo<F>(
        &self,
        repository: &str,
        digest: &str,
        expected_size: u64,
        progress: Option<F>,
    ) -> Result<Vec<u8>>
    where
        F: FnMut(u64, u64),
    {
        let url = format!(
            "{}/v2/{}/blobs/{}",
            self.registry_url, repository, digest
        );

        debug!(url = %url, expected_size = expected_size, "fetching blob by repo");

        let response = self
            .request_with_auth(reqwest::Method::GET, &url, repository)
            .await?;

        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Err(ImageError::NotFound(format!("blob {digest}")));
        }
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ImageError::Registry(format!(
                "failed to fetch blob: {status} - {body}"
            )));
        }

        // Stream the response and track progress.
        let mut stream = response.bytes_stream();
        let capacity = usize::try_from(expected_size).unwrap_or(usize::MAX).min(256 * 1024 * 1024);
        let mut data = Vec::with_capacity(capacity);
        let mut downloaded: u64 = 0;

        if let Some(mut progress_fn) = progress {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    ImageError::Registry(format!("failed to read blob chunk: {e}"))
                })?;
                downloaded += chunk.len() as u64;
                data.extend_from_slice(&chunk);
                progress_fn(downloaded, expected_size);
            }
        } else {
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    ImageError::Registry(format!("failed to read blob chunk: {e}"))
                })?;
                data.extend_from_slice(&chunk);
            }
        }

        Ok(data)
    }

    /// Makes an authenticated request to the registry.
    ///
    /// Handles token authentication (401 challenge) automatically.
    async fn request_with_auth(
        &self,
        method: reqwest::Method,
        url: &str,
        repository: &str,
    ) -> Result<reqwest::Response> {
        // First, try with cached token if available.
        let cached_token = {
            let tokens = self.tokens.read().await;
            tokens.get(repository).cloned()
        };

        if let Some(token) = cached_token {
            let response = self
                .client
                .request(method.clone(), url)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ACCEPT, ACCEPT_MANIFEST)
                .send()
                .await
                .map_err(|e| ImageError::Registry(format!("request failed: {e}")))?;

            if response.status() != StatusCode::UNAUTHORIZED {
                return Ok(response);
            }
            // Token expired, clear it and retry.
            let mut tokens = self.tokens.write().await;
            tokens.remove(repository);
        }

        // Make initial request without auth.
        let response = self
            .client
            .request(method.clone(), url)
            .header(header::ACCEPT, ACCEPT_MANIFEST)
            .send()
            .await
            .map_err(|e| ImageError::Registry(format!("request failed: {e}")))?;

        // If 401, parse challenge and get token.
        if response.status() == StatusCode::UNAUTHORIZED {
            let challenge = Self::parse_www_authenticate(&response)?;
            let token = self.get_token(&challenge).await?;

            // Cache the token.
            {
                let mut tokens = self.tokens.write().await;
                tokens.insert(repository.to_string(), token.clone());
            }

            // Retry with token.
            let response = self
                .client
                .request(method, url)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::ACCEPT, ACCEPT_MANIFEST)
                .send()
                .await
                .map_err(|e| ImageError::Registry(format!("request failed: {e}")))?;

            return Ok(response);
        }

        Ok(response)
    }

    /// Parses WWW-Authenticate header from 401 response.
    fn parse_www_authenticate(response: &reqwest::Response) -> Result<AuthChallenge> {
        let header = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ImageError::Auth("missing WWW-Authenticate header".to_string())
            })?;

        trace!(header = %header, "parsing WWW-Authenticate");

        let mut challenge = AuthChallenge::default();

        // Parse Bearer realm="...",service="...",scope="..."
        for part in header.trim_start_matches("Bearer ").split(',') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("realm=") {
                challenge.realm = value.trim_matches('"').to_string();
            } else if let Some(value) = part.strip_prefix("service=") {
                challenge.service = value.trim_matches('"').to_string();
            } else if let Some(value) = part.strip_prefix("scope=") {
                challenge.scope = value.trim_matches('"').to_string();
            }
        }

        if challenge.realm.is_empty() {
            return Err(ImageError::Auth("invalid WWW-Authenticate header".to_string()));
        }

        Ok(challenge)
    }

    /// Gets a bearer token from the auth service.
    async fn get_token(&self, challenge: &AuthChallenge) -> Result<String> {
        use std::fmt::Write;

        let mut url = format!(
            "{}?service={}&scope={}",
            challenge.realm, challenge.service, challenge.scope
        );

        // Add basic auth if provided.
        if let Some(auth) = &self.auth {
            let _ = write!(url, "&account={}", urlencoding::encode(&auth.username));
        }

        debug!(url = %url, "requesting token");

        let mut request = self.client.get(&url);

        // Add basic auth header if credentials provided.
        if let Some(auth) = &self.auth {
            request = request.basic_auth(&auth.username, Some(&auth.password));
        }

        let response = request
            .send()
            .await
            .map_err(|e| ImageError::Auth(format!("token request failed: {e}")))?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ImageError::Auth(format!("token request failed: {body}")));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| ImageError::Auth(format!("failed to parse token response: {e}")))?;

        Ok(token_response.token)
    }
}

/// Selects the appropriate manifest from a manifest list for the current platform.
///
/// Note: Container images are always for Linux, so we select "linux" as the OS
/// regardless of the host OS.
#[must_use]
pub fn select_platform_manifest(list: &ManifestList) -> Option<&crate::manifest::PlatformManifest> {
    let arch = current_arch();

    // Container images are always for Linux.
    list.manifests.iter().find(|m| {
        m.platform.os == "linux" && m.platform.architecture == arch
    })
}

/// Returns the current architecture in Docker/OCI format.
fn current_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        a => a,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_to_url() {
        assert_eq!(
            RegistryClient::registry_to_url("docker.io"),
            "https://registry-1.docker.io"
        );
        assert_eq!(
            RegistryClient::registry_to_url("ghcr.io"),
            "https://ghcr.io"
        );
        assert_eq!(
            RegistryClient::registry_to_url("http://localhost:5000"),
            "http://localhost:5000"
        );
    }

    #[test]
    fn test_current_arch() {
        let arch = current_arch();
        assert!(!arch.is_empty());
        // Should return amd64 or arm64 on common platforms.
        assert!(["amd64", "arm64", "x86_64", "aarch64"].contains(&arch));
    }

    #[test]
    fn test_image_ref_parse() {
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");

        let r = ImageRef::parse("nginx:1.25").unwrap();
        assert_eq!(r.registry, "docker.io");
        assert_eq!(r.repository, "library/nginx");
        assert_eq!(r.reference, "1.25");

        let r = ImageRef::parse("ghcr.io/owner/repo:v1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/repo");
        assert_eq!(r.reference, "v1");
    }
}
