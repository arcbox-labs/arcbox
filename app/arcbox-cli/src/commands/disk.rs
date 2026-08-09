//! Disk management commands.
//!
//! Inspect and manage the Docker data disk image.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use serde::Serialize;

use super::OutputFormat;

/// Disk management commands.
#[derive(Subcommand)]
pub enum DiskCommands {
    /// Show disk usage for the Docker data image.
    Usage,
    /// Compact the Docker data image by trimming free blocks.
    Compact,
}

pub async fn execute(cmd: DiskCommands, format: OutputFormat) -> Result<()> {
    match cmd {
        DiskCommands::Usage => execute_usage(format).await,
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

    /// Sparse holes — bytes that the host has not allocated.
    fn unallocated_sparse_bytes(self) -> u64 {
        self.logical_bytes.saturating_sub(self.physical_bytes)
    }

    fn unallocated_sparse_gib(self) -> f64 {
        self.unallocated_sparse_bytes() as f64 / BYTES_PER_GIB
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

#[derive(Debug, Serialize)]
struct DiskImageReport {
    path: std::path::PathBuf,
    logical_capacity_bytes: u64,
    physical_allocation_bytes: u64,
    unallocated_sparse_bytes: u64,
}

impl DiskImageReport {
    fn new(path: std::path::PathBuf, usage: DiskUsage) -> Self {
        Self {
            path,
            logical_capacity_bytes: usage.logical_bytes,
            physical_allocation_bytes: usage.physical_bytes,
            unallocated_sparse_bytes: usage.unallocated_sparse_bytes(),
        }
    }
}

#[derive(Debug, Serialize)]
struct DiskUsageReport {
    docker_data_disk: Option<DiskImageReport>,
    docker_metadata_disk: Option<DiskImageReport>,
    docker_reclaimable: Option<arcbox_docker::DockerReclaimableSpace>,
    reclaimable_bytes: u64,
}

impl DiskUsageReport {
    fn new(
        docker_data_disk: DiskImageReport,
        docker_metadata_disk: Option<DiskImageReport>,
        docker_reclaimable: arcbox_docker::DockerReclaimableSpace,
    ) -> Self {
        let reclaimable_bytes = docker_reclaimable
            .total_bytes
            .min(docker_data_disk.physical_allocation_bytes);
        Self {
            docker_data_disk: Some(docker_data_disk),
            docker_metadata_disk,
            docker_reclaimable: Some(docker_reclaimable),
            reclaimable_bytes,
        }
    }

    fn empty() -> Self {
        Self {
            docker_data_disk: None,
            docker_metadata_disk: None,
            docker_reclaimable: None,
            reclaimable_bytes: 0,
        }
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

fn print_disk_usage(label: &str, path: &std::path::Path, usage: DiskUsage) {
    println!("{label}:");
    println!("  Path:                 {}", path.display());
    println!("  Logical capacity:     {:.1} GiB", usage.logical_gib());
    println!(
        "  Physical allocation:  {:.1} GiB   ({:.1}%)",
        usage.physical_gib(),
        usage.usage_pct()
    );
    println!(
        "  Sparse/unallocated:    {:.1} GiB",
        usage.unallocated_sparse_gib()
    );
}

async fn execute_usage(format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Quiet) {
        bail!("disk usage does not support quiet output");
    }

    let config = arcbox_core::Config::load()?;
    let img_path = config.docker_img_path();

    if !img_path.exists() {
        match format {
            OutputFormat::Json => println!("{}", serde_json::to_string(&DiskUsageReport::empty())?),
            OutputFormat::Table => {
                println!("Docker data disk not found at {}", img_path.display());
                println!("The disk will be created when a machine is first started.");
            }
            OutputFormat::Quiet => unreachable!(),
        }
        return Ok(());
    }

    let usage = read_disk_usage(&img_path)?;
    let meta_path = config.docker_meta_img_path();
    let metadata_usage = meta_path
        .exists()
        .then(|| read_disk_usage(&meta_path))
        .transpose()?;
    let socket_path = std::env::var_os("ARCBOX_SOCKET").map_or_else(
        || config.docker.socket_path.clone(),
        std::path::PathBuf::from,
    );
    let docker_reclaimable = arcbox_docker::query_reclaimable_space(&socket_path)
        .await
        .with_context(|| {
            format!(
                "failed to query Docker disk usage through {}",
                socket_path.display()
            )
        })?;
    let report = DiskUsageReport::new(
        DiskImageReport::new(img_path.clone(), usage),
        metadata_usage.map(|meta| DiskImageReport::new(meta_path.clone(), meta)),
        docker_reclaimable,
    );

    match format {
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
        OutputFormat::Table => {
            print_disk_usage("Docker data disk", &img_path, usage);

            if let Some(meta) = metadata_usage {
                println!();
                print_disk_usage("Docker metadata disk", &meta_path, meta);
            }

            println!();
            println!("Docker reclaimable:");
            println!(
                "  Images:                {:.1} GiB",
                docker_reclaimable.images_bytes as f64 / BYTES_PER_GIB
            );
            println!(
                "  Containers:            {:.1} GiB",
                docker_reclaimable.containers_bytes as f64 / BYTES_PER_GIB
            );
            println!(
                "  Volumes:               {:.1} GiB",
                docker_reclaimable.volumes_bytes as f64 / BYTES_PER_GIB
            );
            println!(
                "  Build cache:           {:.1} GiB",
                docker_reclaimable.build_cache_bytes as f64 / BYTES_PER_GIB
            );
            println!(
                "  Runtime total:         {:.1} GiB",
                docker_reclaimable.total_bytes as f64 / BYTES_PER_GIB
            );
            println!(
                "  Reclaimable (capped):  {:.1} GiB",
                report.reclaimable_bytes as f64 / BYTES_PER_GIB
            );
        }
        OutputFormat::Quiet => unreachable!(),
    }

    Ok(())
}

/// Machine whose data disk `disk compact` targets. The Docker data image
/// belongs to the default native machine — the same one `disk usage` inspects.
const DEFAULT_MACHINE: &str = "default";

async fn execute_compact() -> Result<()> {
    let config = arcbox_core::Config::load()?;
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
        .compact_disk(arcbox_connect::v1::MachineAgentRequest {
            id: DEFAULT_MACHINE.to_string(),
            ..Default::default()
        })
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
    use std::io::Write as _;

    use serde_json::json;

    use super::{DiskImageReport, DiskUsage, DiskUsageReport, read_disk_usage};

    fn docker_reclaimable(total_bytes: u64) -> arcbox_docker::DockerReclaimableSpace {
        arcbox_docker::DockerReclaimableSpace {
            images_bytes: total_bytes,
            containers_bytes: 0,
            volumes_bytes: 0,
            build_cache_bytes: 0,
            total_bytes,
        }
    }

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
    fn unallocated_sparse_bytes_saturate_when_physical_exceeds_logical() {
        let usage = DiskUsage {
            logical_bytes: 100,
            physical_bytes: 200,
        };
        assert_eq!(usage.unallocated_sparse_bytes(), 0);
    }

    #[test]
    fn usage_pct_typical_sparse_image() {
        let usage = DiskUsage {
            logical_bytes: 10 * 1024 * 1024 * 1024,
            physical_bytes: 5 * 1024 * 1024 * 1024,
        };
        assert!((usage.usage_pct() - 50.0).abs() < f64::EPSILON);
    }

    #[cfg(unix)]
    #[test]
    fn large_sparse_file_keeps_capacity_separate_from_physical_allocation() {
        const EIGHT_TIB: u64 = 8 * 1024 * 1024 * 1024 * 1024;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.as_file_mut().set_len(EIGHT_TIB).unwrap();
        file.write_all(&[1; 4096]).unwrap();
        file.as_file().sync_all().unwrap();

        let usage = read_disk_usage(file.path()).unwrap();
        assert_eq!(usage.logical_bytes, EIGHT_TIB);
        assert!(usage.physical_bytes < 1024 * 1024);
        assert_eq!(
            usage.unallocated_sparse_bytes(),
            EIGHT_TIB - usage.physical_bytes
        );
    }

    #[test]
    fn reclaimable_bytes_are_capped_by_physical_allocation() {
        let report = DiskUsageReport::new(
            DiskImageReport::new(
                "/data/docker.img".into(),
                DiskUsage {
                    logical_bytes: 8 * 1024,
                    physical_bytes: 55,
                },
            ),
            None,
            docker_reclaimable(6000),
        );

        assert_eq!(report.reclaimable_bytes, 55);
    }

    #[test]
    fn json_contract_uses_raw_bytes_and_separate_sparse_capacity() {
        let report = DiskUsageReport::new(
            DiskImageReport::new(
                "/data/docker.img".into(),
                DiskUsage {
                    logical_bytes: 8192,
                    physical_bytes: 55,
                },
            ),
            None,
            arcbox_docker::DockerReclaimableSpace {
                images_bytes: 11,
                containers_bytes: 12,
                volumes_bytes: 13,
                build_cache_bytes: 14,
                total_bytes: 50,
            },
        );

        assert_eq!(
            serde_json::to_value(report).unwrap(),
            json!({
                "docker_data_disk": {
                    "path": "/data/docker.img",
                    "logical_capacity_bytes": 8192,
                    "physical_allocation_bytes": 55,
                    "unallocated_sparse_bytes": 8137,
                },
                "docker_metadata_disk": null,
                "docker_reclaimable": {
                    "images_bytes": 11,
                    "containers_bytes": 12,
                    "volumes_bytes": 13,
                    "build_cache_bytes": 14,
                    "total_bytes": 50,
                },
                "reclaimable_bytes": 50,
            })
        );
    }
}
