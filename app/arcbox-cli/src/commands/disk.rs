//! Disk management commands.
//!
//! Inspect and manage the Docker data disk image.

use anyhow::{Context, Result};
use arcbox_protocol::v1::MachineAgentRequest;
use clap::Subcommand;

/// Disk management commands.
#[derive(Subcommand)]
pub enum DiskCommands {
    /// Show disk usage for the Docker data image.
    Usage,
    /// Compact the Docker data image by trimming free blocks.
    Compact,
}

pub async fn execute(cmd: DiskCommands) -> Result<()> {
    match cmd {
        DiskCommands::Usage => execute_usage().await,
        DiskCommands::Compact => execute_compact().await,
    }
}

const BYTES_PER_GIB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Disk usage figures derived from `stat` on the sparse data image.
#[derive(Debug, Clone, Copy, PartialEq)]
struct DiskUsage {
    /// Apparent file size (`st_size`).
    logical_bytes: u64,
    /// Bytes actually backed on host storage (`st_blocks * 512`).
    physical_bytes: u64,
}

impl DiskUsage {
    fn logical_gib(self) -> f64 {
        self.logical_bytes as f64 / BYTES_PER_GIB
    }

    fn physical_gib(self) -> f64 {
        self.physical_bytes as f64 / BYTES_PER_GIB
    }

    /// Sparse holes — bytes that the host has not yet allocated (or has
    /// reclaimed via fstrim). This is *not* filesystem free space; it is
    /// the gap between apparent and physical size on the host.
    fn reclaimable_gib(self) -> f64 {
        self.logical_bytes.saturating_sub(self.physical_bytes) as f64 / BYTES_PER_GIB
    }

    /// Percentage of the apparent size that is physically allocated.
    /// Clamped to ≤100% since `st_blocks` rounding can yield a
    /// physical figure marginally above `st_size`.
    fn usage_pct(self) -> f64 {
        if self.logical_bytes == 0 {
            return 0.0;
        }
        let used = self.physical_bytes.min(self.logical_bytes) as f64;
        (used / self.logical_bytes as f64) * 100.0
    }
}

fn read_disk_usage(path: &std::path::Path) -> Result<DiskUsage> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;

    let logical_bytes = metadata.len();

    #[cfg(unix)]
    let physical_bytes = {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks() * 512
    };
    #[cfg(not(unix))]
    let physical_bytes = logical_bytes;

    Ok(DiskUsage {
        logical_bytes,
        physical_bytes,
    })
}

async fn execute_usage() -> Result<()> {
    let config = arcbox_core::Config::load().unwrap_or_default();
    let img_path = config.docker_img_path();

    if !img_path.exists() {
        println!("Docker data disk not found at {}", img_path.display());
        println!("The disk will be created when a machine is first started.");
        return Ok(());
    }

    let usage = read_disk_usage(&img_path)?;

    println!("Docker data disk:");
    println!("  Path:        {}", img_path.display());
    println!("  Logical:     {:.1} GiB", usage.logical_gib());
    println!(
        "  Physical:    {:.1} GiB   ({:.1}%)",
        usage.physical_gib(),
        usage.usage_pct()
    );
    println!("  Reclaimable: {:.1} GiB", usage.reclaimable_gib());

    // The metadata image is small but part of the data set; report it so
    // "what is on disk" is complete.
    let meta_path = config.docker_meta_img_path();
    if meta_path.exists() {
        let meta = read_disk_usage(&meta_path)?;
        println!();
        println!("Docker metadata disk:");
        println!("  Path:        {}", meta_path.display());
        println!("  Logical:     {:.1} GiB", meta.logical_gib());
        println!(
            "  Physical:    {:.1} GiB   ({:.1}%)",
            meta.physical_gib(),
            meta.usage_pct()
        );
    }

    Ok(())
}

/// Machine whose data disk `disk compact` targets. The Docker data image
/// belongs to the default native machine — the same one `disk usage` inspects.
const DEFAULT_MACHINE: &str = "default";

async fn execute_compact() -> Result<()> {
    let config = arcbox_core::Config::load().unwrap_or_default();
    let img_path = config.docker_img_path();

    if !img_path.exists() {
        println!("Docker data disk not found at {}", img_path.display());
        return Ok(());
    }

    let before = read_disk_usage(&img_path)?;

    // Ask the daemon to run fstrim in the guest. The resulting discards flow
    // through virtio-blk, which punches holes in this sparse image, so the
    // physical footprint we re-stat below shrinks by the freed amount.
    println!("Compacting Docker data disk (running fstrim in the guest)...");
    let client = super::machine::machine_client();
    client
        .compact_disk(crate::connect::request::<
            arcbox_connect::v1::MachineAgentRequest,
            _,
        >(&MachineAgentRequest {
            id: DEFAULT_MACHINE.to_string(),
        })?)
        .await
        .context("Failed to compact data disk via the daemon")?;

    let after = read_disk_usage(&img_path)?;
    let reclaimed = before.physical_bytes.saturating_sub(after.physical_bytes);

    println!(
        "  Physical: {:.1} GiB -> {:.1} GiB",
        before.physical_gib(),
        after.physical_gib(),
    );
    println!("  Reclaimed: {:.1} GiB", reclaimed as f64 / BYTES_PER_GIB);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DiskUsage;

    #[test]
    fn usage_pct_clamped_when_physical_exceeds_logical() {
        let usage = DiskUsage {
            logical_bytes: 100,
            physical_bytes: 200,
        };
        assert!((usage.usage_pct() - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn usage_pct_zero_when_logical_zero() {
        let usage = DiskUsage {
            logical_bytes: 0,
            physical_bytes: 0,
        };
        assert!(usage.usage_pct().abs() < f64::EPSILON);
    }

    #[test]
    fn reclaimable_gib_saturates_to_zero_when_physical_exceeds_logical() {
        let usage = DiskUsage {
            logical_bytes: 100,
            physical_bytes: 200,
        };
        assert!(usage.reclaimable_gib().abs() < f64::EPSILON);
    }

    #[test]
    fn usage_pct_typical_sparse_image() {
        let usage = DiskUsage {
            logical_bytes: 10 * 1024 * 1024 * 1024,
            physical_bytes: 5 * 1024 * 1024 * 1024,
        };
        assert!((usage.usage_pct() - 50.0).abs() < f64::EPSILON);
    }
}
