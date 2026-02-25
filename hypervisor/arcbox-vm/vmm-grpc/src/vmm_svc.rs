use std::sync::Arc;

use tonic::{Request, Response, Status};

use vmm_core::VmmManager;
use vmm_core::config::{
    BalloonSpec, CacheType, CpuTemplateSpec, DriveSpec, HugePagesSpec, IoEngine, MemoryHotplugSpec,
    MmdsSpec, MmdsVersionSpec, RateLimitSpec, RestoreSpec, SnapshotRequest, SnapshotType,
    TokenBucketSpec, VmSpec, VsockSpec,
};

use crate::proto::vmm::{
    BalloonConfig, CreateSnapshotRequest, CreateSnapshotResponse, CreateVmRequest,
    CreateVmResponse, DeleteSnapshotRequest, DriveConfig, Empty, FlushMetricsRequest,
    GetMetricsRequest, ListSnapshotsRequest, ListSnapshotsResponse, MemHotplugConfig, MmdsConfig,
    PauseVmRequest, RateLimiter, RestoreSnapshotRequest, RestoreSnapshotResponse, ResumeVmRequest,
    SnapshotSummary, TokenBucket, UpdateBalloonRequest, UpdateBalloonStatsIntervalRequest,
    UpdateDriveRequest, UpdateMemoryRequest, UpdateNetworkInterfaceRequest, VmMetrics, VsockConfig,
    vmm_service_server::VmmService,
};

/// Implementation of `vmm.v1.VmmService`.
pub struct VmmServiceImpl {
    manager: Arc<VmmManager>,
}

impl VmmServiceImpl {
    pub fn new(manager: Arc<VmmManager>) -> Self {
        Self { manager }
    }
}

// =============================================================================
// Conversion helpers: proto types → vmm-core config types
// =============================================================================

fn proto_token_bucket(tb: TokenBucket) -> TokenBucketSpec {
    TokenBucketSpec {
        size: tb.size,
        refill_time_ms: tb.refill_time_ms,
        one_time_burst: tb.one_time_burst,
    }
}

fn proto_rate_limiter(rl: RateLimiter) -> RateLimitSpec {
    RateLimitSpec {
        bandwidth: rl.bandwidth.map(proto_token_bucket),
        ops: rl.ops.map(proto_token_bucket),
    }
}

fn proto_drive_config(d: DriveConfig) -> DriveSpec {
    let io_engine = match d.io_engine.to_lowercase().as_str() {
        "async" => IoEngine::Async,
        _ => IoEngine::Sync,
    };
    let cache_type = match d.cache_type.to_lowercase().as_str() {
        "writeback" => CacheType::Writeback,
        _ => CacheType::Unsafe,
    };
    DriveSpec {
        drive_id: d.drive_id,
        path: d.path,
        readonly: d.readonly,
        io_engine,
        cache_type,
        partuuid: d.partuuid,
        rate_limit: d.rate_limit.map(proto_rate_limiter),
    }
}

fn proto_balloon(b: BalloonConfig) -> BalloonSpec {
    BalloonSpec {
        amount_mib: b.amount_mib,
        deflate_on_oom: b.deflate_on_oom,
        stats_polling_interval_s: b.stats_polling_interval_s,
        free_page_hinting: b.free_page_hinting,
        free_page_reporting: b.free_page_reporting,
    }
}

fn proto_vsock(v: VsockConfig) -> VsockSpec {
    VsockSpec {
        guest_cid: v.guest_cid,
    }
}

fn proto_mem_hotplug(m: MemHotplugConfig) -> MemoryHotplugSpec {
    MemoryHotplugSpec {
        total_size_mib: m.total_size_mib,
        slot_size_mib: m.slot_size_mib,
        block_size_mib: m.block_size_mib,
    }
}

fn proto_mmds(m: MmdsConfig) -> MmdsSpec {
    let version = match m.version.to_lowercase().as_str() {
        "v2" => MmdsVersionSpec::V2,
        _ => MmdsVersionSpec::V1,
    };
    MmdsSpec {
        network_interfaces: m.network_interfaces,
        version,
        ipv4_address: m.ipv4_address,
        imds_compat: m.imds_compat,
        initial_data: None,
    }
}

fn proto_cpu_template(s: &str) -> Option<CpuTemplateSpec> {
    match s.to_uppercase().as_str() {
        "C3" => Some(CpuTemplateSpec::C3),
        "T2" => Some(CpuTemplateSpec::T2),
        "T2S" => Some(CpuTemplateSpec::T2S),
        "T2CL" => Some(CpuTemplateSpec::T2CL),
        "T2A" => Some(CpuTemplateSpec::T2A),
        "V1N1" => Some(CpuTemplateSpec::V1N1),
        _ => None,
    }
}

fn proto_huge_pages(s: &str) -> Option<HugePagesSpec> {
    match s {
        "2M" | "2m" => Some(HugePagesSpec::TwoMB),
        _ => None,
    }
}

// =============================================================================
// VmmService implementation
// =============================================================================

#[tonic::async_trait]
impl VmmService for VmmServiceImpl {
    /// Create a VM with the full Firecracker parameter set.
    async fn create_vm(
        &self,
        request: Request<CreateVmRequest>,
    ) -> Result<Response<CreateVmResponse>, Status> {
        let req = request.into_inner();

        let root_io_engine = match req.root_io_engine.to_lowercase().as_str() {
            "async" => IoEngine::Async,
            _ => IoEngine::Sync,
        };
        let root_cache_type = match req.root_cache_type.to_lowercase().as_str() {
            "writeback" => CacheType::Writeback,
            _ => CacheType::Unsafe,
        };

        let spec = VmSpec {
            name: req.name,
            vcpus: req.vcpus as u64,
            memory_mib: req.memory_mib,
            kernel: req.kernel,
            boot_args: req.boot_args,
            initrd: req.initrd,
            smt: req.smt,
            track_dirty_pages: req.track_dirty_pages,
            huge_pages: proto_huge_pages(&req.huge_pages),
            cpu_template: proto_cpu_template(&req.cpu_template),
            rootfs: req.rootfs,
            root_readonly: req.root_readonly,
            root_io_engine,
            root_cache_type,
            root_partuuid: req.root_partuuid,
            root_rate_limit: req.root_rate_limit.map(proto_rate_limiter),
            extra_drives: req
                .extra_drives
                .into_iter()
                .map(proto_drive_config)
                .collect(),
            net_rx_rate_limit: req.net_rx_rate_limit.map(proto_rate_limiter),
            net_tx_rate_limit: req.net_tx_rate_limit.map(proto_rate_limiter),
            balloon: req.balloon.map(proto_balloon),
            vsock: req.vsock.map(proto_vsock),
            entropy_device: req.entropy_device,
            serial_out: req.serial_out,
            memory_hotplug: req.memory_hotplug.map(proto_mem_hotplug),
            mmds: req.mmds.map(proto_mmds),
            ssh_public_key: req.ssh_public_key,
            disk_size: None,
        };

        let id = self
            .manager
            .create_vm(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateVmResponse { id }))
    }

    /// Pause a running VM.
    async fn pause(&self, request: Request<PauseVmRequest>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .pause_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Resume a paused VM.
    async fn resume(&self, request: Request<ResumeVmRequest>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .resume_vm(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Create a snapshot.
    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let req = request.into_inner();
        let snapshot_type = match req.snapshot_type.as_str() {
            "diff" => SnapshotType::Diff,
            _ => SnapshotType::Full,
        };
        let snap_req = SnapshotRequest {
            name: if req.name.is_empty() {
                None
            } else {
                Some(req.name)
            },
            snapshot_type,
        };

        let info = self
            .manager
            .snapshot_vm(&req.id, snap_req)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateSnapshotResponse {
            snapshot_id: info.id,
            snapshot_dir: info
                .vmstate_path
                .parent()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            created_at: info.created_at.to_rfc3339(),
        }))
    }

    /// List snapshots for a VM.
    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let req = request.into_inner();
        let snaps = self
            .manager
            .list_snapshots(&req.id)
            .map_err(|e| Status::internal(e.to_string()))?;

        let snapshots = snaps
            .into_iter()
            .map(|s| SnapshotSummary {
                id: s.id,
                vm_id: s.vm_id,
                name: s.name.unwrap_or_default(),
                snapshot_type: format!("{:?}", s.snapshot_type).to_lowercase(),
                vmstate_path: s.vmstate_path.to_string_lossy().into_owned(),
                mem_path: s
                    .mem_path
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                created_at: s.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Response::new(ListSnapshotsResponse { snapshots }))
    }

    /// Restore a VM from a snapshot.
    async fn restore_snapshot(
        &self,
        request: Request<RestoreSnapshotRequest>,
    ) -> Result<Response<RestoreSnapshotResponse>, Status> {
        let req = request.into_inner();
        let spec = RestoreSpec {
            name: req.name,
            snapshot_dir: req.snapshot_dir,
            network_override: req.network_override,
        };

        let id = self
            .manager
            .restore_vm(spec)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RestoreSnapshotResponse { id }))
    }

    /// Delete a snapshot.
    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .delete_snapshot(&req.vm_id, &req.snapshot_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Get VM metrics.
    async fn get_metrics(
        &self,
        request: Request<GetMetricsRequest>,
    ) -> Result<Response<VmMetrics>, Status> {
        let req = request.into_inner();
        let m = self
            .manager
            .get_metrics(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(VmMetrics {
            vm_id: m.vm_id,
            balloon_target_mib: m.balloon_target_mib.unwrap_or(-1),
            balloon_actual_mib: m.balloon_actual_mib.unwrap_or(-1),
        }))
    }

    /// Update balloon target.
    async fn update_balloon(
        &self,
        request: Request<UpdateBalloonRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_balloon(&req.id, req.amount_mib)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Update balloon statistics polling interval.
    async fn update_balloon_stats_interval(
        &self,
        request: Request<UpdateBalloonStatsIntervalRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_balloon_stats_interval(&req.id, req.stats_polling_interval_s)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Update hotplug memory size.
    async fn update_memory(
        &self,
        request: Request<UpdateMemoryRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_memory(&req.id, req.size_mib)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Hot-swap a drive or update its rate limiter.
    async fn update_drive(
        &self,
        request: Request<UpdateDriveRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_drive(
                &req.id,
                &req.drive_id,
                req.path_on_host,
                req.rate_limit.map(proto_rate_limiter),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Update rate limiters on a network interface.
    async fn update_network_interface(
        &self,
        request: Request<UpdateNetworkInterfaceRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .update_network_interface(
                &req.id,
                &req.iface_id,
                req.rx_rate_limit.map(proto_rate_limiter),
                req.tx_rate_limit.map(proto_rate_limiter),
            )
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }

    /// Flush metrics to disk immediately.
    async fn flush_metrics(
        &self,
        request: Request<FlushMetricsRequest>,
    ) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        self.manager
            .flush_metrics(&req.id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(Empty {}))
    }
}
