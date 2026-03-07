//! Progress reporting types for asset downloads.

/// Progress information for a single asset being prepared.
#[derive(Debug, Clone)]
pub struct PrepareProgress {
    /// Name of the asset currently being processed.
    pub name: String,
    /// 1-based index of the current asset.
    pub current: usize,
    /// Total number of assets.
    pub total: usize,
    /// Current phase.
    pub phase: PreparePhase,
}

/// Phase within a single asset's lifecycle.
#[derive(Debug, Clone)]
pub enum PreparePhase {
    /// Checking whether the asset is already cached and valid.
    Checking,
    /// Downloading the asset.
    Downloading { downloaded: u64, total: Option<u64> },
    /// Verifying checksum after download.
    Verifying,
    /// Asset is ready (freshly downloaded and verified).
    Ready,
    /// Asset was already cached with a valid checksum.
    Cached,
}

/// Boxed progress callback.
pub type ProgressCallback = Box<dyn Fn(PrepareProgress) + Send + Sync>;
