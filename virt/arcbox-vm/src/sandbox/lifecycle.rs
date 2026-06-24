use super::boot::boot_sandbox;
use super::cleanup::{inst_to_info, remove_sandbox_impl};
use super::*;

impl SandboxManager {
    pub async fn create_sandbox(&self, mut spec: SandboxSpec) -> Result<(SandboxId, String)> {
        // Apply daemon defaults for fields not supplied by the caller.
        let defaults = &self.config.defaults;
        if spec.kernel.is_empty() {
            spec.kernel.clone_from(&defaults.kernel);
        }
        if spec.rootfs.is_empty() {
            spec.rootfs.clone_from(&defaults.rootfs);
        }
        if spec.boot_args.is_empty() {
            spec.boot_args.clone_from(&defaults.boot_args);
        }
        if spec.vcpus == 0 {
            spec.vcpus = defaults.vcpus as u32;
        }
        if spec.memory_mib == 0 {
            spec.memory_mib = defaults.memory_mib;
        }
        if spec.network.mode.is_empty() {
            spec.network.mode = "tap".into();
        }

        let id = spec
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Sanitize caller-supplied IDs: reject path separators and other
        // dangerous characters to prevent directory traversal.
        if id.contains('/') || id.contains('\\') || id.contains('\0') || id == "." || id == ".." {
            return Err(VmmError::Config(format!(
                "invalid sandbox ID: {id:?} (must not contain path separators)"
            )));
        }

        // Uniqueness check.
        {
            let instances = self.instances.read().unwrap();
            if instances.contains_key(&id) {
                return Err(VmmError::AlreadyExists(id));
            }
        }

        // Allocate network resources (point-to-point TAP).
        let net_alloc = if spec.network.mode == "none" {
            None
        } else {
            Some(self.network.allocate(&id)?)
        };

        let ip_address = net_alloc
            .as_ref()
            .map(|n| n.ip_address.to_string())
            .unwrap_or_default();

        // Create the VM working directory.
        let vm_dir = PathBuf::from(&self.config.firecracker.data_dir)
            .join("sandboxes")
            .join(&id);
        std::fs::create_dir_all(&vm_dir).map_err(VmmError::Io)?;

        // Insert instance in Starting state.
        let instance =
            SandboxInstance::new(id.clone(), spec.clone(), net_alloc.clone(), vm_dir.clone());
        {
            let mut instances = self.instances.write().unwrap();
            instances.insert(id.clone(), Arc::new(Mutex::new(instance)));
        }

        // Broadcast "created" event.
        let _ = self.events_tx.send(SandboxEvent::new(&id, "created"));

        // Spawn background boot task.
        {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let config = Arc::clone(&self.config);
            let events_tx = self.events_tx.clone();
            let cow_manager = Arc::clone(&self.cow_manager);
            let id_clone = id.clone();
            let spec_clone = spec.clone();
            let net_alloc_clone = net_alloc;
            tokio::spawn(async move {
                boot_sandbox(
                    id_clone,
                    spec_clone,
                    net_alloc_clone,
                    vm_dir,
                    instances,
                    network,
                    config,
                    events_tx,
                    cow_manager,
                )
                .await;
            });
        }

        // Spawn TTL expiry task if requested.
        if spec.ttl_seconds > 0 {
            let instances = Arc::clone(&self.instances);
            let network = Arc::clone(&self.network);
            let events_tx = self.events_tx.clone();
            let config2 = Arc::clone(&self.config);
            let cow2 = Arc::clone(&self.cow_manager);
            let id2 = id.clone();
            let ttl = spec.ttl_seconds;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl as u64)).await;
                remove_sandbox_impl(
                    &id2, true, &instances, &network, &events_tx, &config2, &cow2,
                )
                .await;
            });
        }

        info!(sandbox_id = %id, "sandbox create requested (async boot started)");
        Ok((id, ip_address))
    }

    /// Stop a sandbox gracefully.
    ///
    /// Sends Ctrl+Alt+Del to the guest and waits up to `timeout_seconds`
    /// (default 30 s) for the VM to shut down.
    pub async fn stop_sandbox(&self, id: &SandboxId, timeout_seconds: u32) -> Result<()> {
        let vm_handle = {
            let instance = self.get_instance(id)?;
            let mut inst = instance.lock().unwrap();
            match inst.state {
                SandboxState::Ready | SandboxState::Running => {}
                s => {
                    return Err(VmmError::WrongState {
                        id: id.clone(),
                        expected: "Ready or Running".into(),
                        actual: s.to_string(),
                    });
                }
            }
            inst.state = SandboxState::Stopping;
            inst.vm.as_ref().map(Arc::clone)
        };

        let _ = self.events_tx.send(SandboxEvent::new(id, "stopping"));

        if let Some(vm) = vm_handle {
            let timeout = if timeout_seconds > 0 {
                timeout_seconds
            } else {
                30
            };
            // Ignore errors — VM may have already exited.
            let _ =
                tokio::time::timeout(Duration::from_secs(timeout as u64), vm.send_ctrl_alt_del())
                    .await;
        }

        // Force-kill the Firecracker process if it is still alive.
        {
            let instance = self.get_instance(id)?;
            let mut inst = instance.lock().unwrap();
            if let Some(ref mut proc) = inst.process
                && let Some(pid) = proc.pid()
                && pid > 0
            {
                let _ = nix::sys::signal::kill(
                    #[allow(
                        clippy::cast_possible_wrap,
                        reason = "Firecracker pid fits platform pid_t"
                    )]
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            inst.state = SandboxState::Stopped;
        }

        let _ = self.events_tx.send(SandboxEvent::new(id, "stopped"));
        info!(sandbox_id = %id, "sandbox stopped");
        Ok(())
    }

    /// Forcibly destroy a sandbox and release all resources immediately.
    pub async fn remove_sandbox(&self, id: &SandboxId, force: bool) -> Result<()> {
        // Verify the sandbox exists.
        let state = {
            let instance = self.get_instance(id)?;
            instance.lock().unwrap().state
        };

        if !force && state == SandboxState::Running {
            return Err(VmmError::WrongState {
                id: id.clone(),
                expected: "non-running (pass force=true to override)".into(),
                actual: state.to_string(),
            });
        }

        remove_sandbox_impl(
            id,
            force,
            &self.instances,
            &self.network,
            &self.events_tx,
            &self.config,
            &self.cow_manager,
        )
        .await;
        info!(sandbox_id = %id, "sandbox removed");
        Ok(())
    }

    /// Return the current state and metadata of a sandbox.
    pub fn inspect_sandbox(&self, id: &SandboxId) -> Result<SandboxInfo> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        Ok(inst_to_info(&inst))
    }

    /// List sandboxes, optionally filtered by state string and/or labels.
    pub fn list_sandboxes(
        &self,
        state_filter: Option<&str>,
        label_filter: &HashMap<String, String>,
    ) -> Vec<SandboxSummary> {
        self.instances
            .read()
            .unwrap()
            .values()
            .filter_map(|arc| {
                let inst = arc.lock().unwrap();
                // State filter.
                if let Some(sf) = state_filter
                    && !sf.is_empty()
                    && inst.state.to_string() != sf
                {
                    return None;
                }
                // Label filter: all supplied key-value pairs must match.
                for (k, v) in label_filter {
                    if inst.labels.get(k).map(String::as_str) != Some(v.as_str()) {
                        return None;
                    }
                }
                Some(SandboxSummary {
                    id: inst.id.clone(),
                    state: inst.state,
                    labels: inst.labels.clone(),
                    ip_address: inst
                        .network
                        .as_ref()
                        .map(|n| n.ip_address.to_string())
                        .unwrap_or_default(),
                    created_at: inst.created_at,
                })
            })
            .collect()
    }

    /// Subscribe to sandbox lifecycle events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SandboxEvent> {
        self.events_tx.subscribe()
    }

    pub(super) fn get_instance(&self, id: &SandboxId) -> Result<Arc<Mutex<SandboxInstance>>> {
        self.instances
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| VmmError::NotFound(id.clone()))
    }

    /// Verify the sandbox is `Ready` and return its vsock UDS path.
    pub(super) fn require_ready_vsock(&self, id: &SandboxId) -> Result<PathBuf> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        match inst.state {
            SandboxState::Ready => {}
            s => {
                return Err(VmmError::WrongState {
                    id: id.clone(),
                    expected: "Ready".into(),
                    actual: s.to_string(),
                });
            }
        }
        inst.vsock_uds_path
            .clone()
            .ok_or_else(|| VmmError::Vsock(format!("sandbox {id} has no vsock configured")))
    }

    pub(super) fn get_vm_handle(&self, id: &SandboxId) -> Result<Arc<fc_sdk::Vm>> {
        let instance = self.get_instance(id)?;
        let inst = instance.lock().unwrap();
        inst.vm
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| VmmError::WrongState {
                id: id.clone(),
                expected: "Ready or Running (VM handle not yet available)".into(),
                actual: inst.state.to_string(),
            })
    }
}
