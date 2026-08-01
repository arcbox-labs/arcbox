//! Migration execution.

use crate::error::{MigrationError, Result};
use crate::model::{
    ContainerMount, ContainerPlan, ContainerSpec, MigrationPlan, PortPublish, SourceConfig,
};
use crate::progress::{MigrationProgress, MigrationStage};
use crate::runner::{CreateNetworkOptions, DockerCliRunner};

/// Execution options approved by the caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrationExecutorOptions {
    /// Whether destructive replace actions are approved.
    pub confirm_replace: bool,
    /// Whether stopping blocked source containers is approved.
    pub confirm_stop_source_containers: bool,
}

/// Executes migration plans against a source and target Docker daemon.
#[derive(Debug, Clone)]
pub struct MigrationExecutor {
    target: DockerCliRunner,
}

impl MigrationExecutor {
    /// Creates an executor for the provided ArcBox target socket.
    #[must_use]
    pub fn new(target: DockerCliRunner) -> Self {
        Self { target }
    }

    /// Executes a migration plan.
    pub async fn execute<F>(
        &self,
        source: SourceConfig,
        plan: &MigrationPlan,
        options: MigrationExecutorOptions,
        mut progress: F,
    ) -> Result<()>
    where
        F: FnMut(MigrationProgress),
    {
        if !plan.unsupported_resources.is_empty() {
            return Err(MigrationError::Blocked(format!(
                "unsupported resources: {}",
                plan.unsupported_resources.join(", ")
            )));
        }
        if !plan.replacements.is_empty() && !options.confirm_replace {
            return Err(MigrationError::Blocked(
                "replace confirmation is required".to_string(),
            ));
        }
        if !plan.blockers.is_empty() && !options.confirm_stop_source_containers {
            return Err(MigrationError::Blocked(
                "stopping source containers is required".to_string(),
            ));
        }

        let source_runner = DockerCliRunner::new(source.socket_path)?;

        stop_source_blockers(&source_runner, plan, &mut progress).await?;
        remove_target_conflicts(&self.target, plan, &mut progress).await?;

        source_runner.ensure_helper_image().await?;
        self.target.ensure_helper_image().await?;

        import_images(&source_runner, &self.target, plan, &mut progress).await?;
        import_volumes(&source_runner, &self.target, plan, &mut progress).await?;
        recreate_networks(&self.target, plan, &mut progress).await?;
        recreate_containers(&self.target, plan, &mut progress).await?;

        progress(MigrationProgress {
            stage: MigrationStage::Complete,
            detail: "migration completed".to_string(),
            resource_type: None,
            resource_name: None,
            current: None,
            total: None,
        });
        Ok(())
    }
}

async fn stop_source_blockers<F>(
    source: &DockerCliRunner,
    plan: &MigrationPlan,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    let mut containers = plan
        .blockers
        .iter()
        .flat_map(|blocker| blocker.containers.clone())
        .collect::<Vec<_>>();
    containers.sort();
    containers.dedup();

    let total = u32::try_from(containers.len()).unwrap_or(0);
    for (index, container) in containers.into_iter().enumerate() {
        progress(MigrationProgress {
            stage: MigrationStage::StopSourceContainers,
            detail: format!("stopping source container '{container}'"),
            resource_type: Some("container".to_string()),
            resource_name: Some(container.clone()),
            current: Some(u32::try_from(index + 1).unwrap_or(total)),
            total: Some(total),
        });
        source.stop_container(&container).await?;
    }
    Ok(())
}

async fn remove_target_conflicts<F>(
    target: &DockerCliRunner,
    plan: &MigrationPlan,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    for container in &plan.replacements.containers {
        progress(MigrationProgress {
            stage: MigrationStage::Cleanup,
            detail: format!("removing target container '{container}'"),
            resource_type: Some("container".to_string()),
            resource_name: Some(container.clone()),
            current: None,
            total: None,
        });
        target.remove_container(container).await?;
    }
    for network in &plan.replacements.networks {
        progress(MigrationProgress {
            stage: MigrationStage::Cleanup,
            detail: format!("removing target network '{network}'"),
            resource_type: Some("network".to_string()),
            resource_name: Some(network.clone()),
            current: None,
            total: None,
        });
        target.remove_network(network).await?;
    }
    for volume in &plan.replacements.volumes {
        progress(MigrationProgress {
            stage: MigrationStage::Cleanup,
            detail: format!("removing target volume '{volume}'"),
            resource_type: Some("volume".to_string()),
            resource_name: Some(volume.clone()),
            current: None,
            total: None,
        });
        target.remove_volume(volume).await?;
    }
    Ok(())
}

async fn import_images<F>(
    source: &DockerCliRunner,
    target: &DockerCliRunner,
    plan: &MigrationPlan,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    let total = u32::try_from(plan.images.len()).unwrap_or(0);
    for (index, image) in plan.images.iter().enumerate() {
        progress(MigrationProgress {
            stage: MigrationStage::ImportImages,
            detail: format!("importing image '{}'", image.primary_reference()),
            resource_type: Some("image".to_string()),
            resource_name: Some(image.primary_reference().to_string()),
            current: Some(u32::try_from(index + 1).unwrap_or(total)),
            total: Some(total),
        });
        source
            .pipe_save_into(target, &image.export_references)
            .await?;
    }
    Ok(())
}

async fn import_volumes<F>(
    source: &DockerCliRunner,
    target: &DockerCliRunner,
    plan: &MigrationPlan,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    let total = u32::try_from(plan.volumes.len()).unwrap_or(0);
    for (index, volume) in plan.volumes.iter().enumerate() {
        progress(MigrationProgress {
            stage: MigrationStage::ImportVolumes,
            detail: format!("importing volume '{}'", volume.name),
            resource_type: Some("volume".to_string()),
            resource_name: Some(volume.name.clone()),
            current: Some(u32::try_from(index + 1).unwrap_or(total)),
            total: Some(total),
        });

        target
            .create_volume(
                &volume.name,
                &volume
                    .labels
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
                &volume
                    .options
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Vec<_>>(),
            )
            .await?;

        let source_helper_name = format!("arcbox-migration-src-{}", sanitize_name(&volume.name));
        let target_helper_name = format!("arcbox-migration-dst-{}", sanitize_name(&volume.name));

        let source_helper = source
            .create_helper_container(&source_helper_name, &volume.name)
            .await?;
        let target_helper = target
            .create_helper_container(&target_helper_name, &volume.name)
            .await?;

        let archive_result = source.copy_from_container(&source_helper, "/volume").await;
        let copy_result = match archive_result {
            Ok(archive) => {
                target
                    .copy_to_container(archive.path(), &target_helper, "/")
                    .await
            }
            Err(err) => Err(err),
        };

        let cleanup_source = source.remove_container(&source_helper).await;
        let cleanup_target = target.remove_container(&target_helper).await;

        copy_result?;
        cleanup_source?;
        cleanup_target?;
    }
    Ok(())
}

async fn recreate_networks<F>(
    target: &DockerCliRunner,
    plan: &MigrationPlan,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    let total = u32::try_from(plan.networks.len()).unwrap_or(0);
    for (index, network) in plan.networks.iter().enumerate() {
        progress(MigrationProgress {
            stage: MigrationStage::RecreateNetworks,
            detail: format!("recreating network '{}'", network.name),
            resource_type: Some("network".to_string()),
            resource_name: Some(network.name.clone()),
            current: Some(u32::try_from(index + 1).unwrap_or(total)),
            total: Some(total),
        });
        let ipam = network
            .ipam
            .iter()
            .map(|entry| {
                (
                    entry.subnet.clone(),
                    entry.gateway.clone(),
                    entry.ip_range.clone(),
                )
            })
            .collect::<Vec<_>>();
        let create_options = CreateNetworkOptions {
            internal: network.internal,
            enable_ipv6: network.enable_ipv6,
            attachable: network.attachable,
            labels: network
                .labels
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            options: network
                .options
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
            ipam,
        };
        target
            .create_network(&network.name, &create_options)
            .await?;
    }
    Ok(())
}

async fn recreate_containers<F>(
    target: &DockerCliRunner,
    plan: &MigrationPlan,
    progress: &mut F,
) -> Result<()>
where
    F: FnMut(MigrationProgress),
{
    let total = u32::try_from(plan.containers.len()).unwrap_or(0);
    for (index, container) in plan.containers.iter().enumerate() {
        progress(MigrationProgress {
            stage: MigrationStage::RecreateContainers,
            detail: format!("recreating container '{}'", container.name),
            resource_type: Some("container".to_string()),
            resource_name: Some(container.name.clone()),
            current: Some(u32::try_from(index + 1).unwrap_or(total)),
            total: Some(total),
        });
        let create_args = build_create_args(container);
        let container_id = target.create_container(create_args).await?;
        for attachment in &container.extra_networks {
            target
                .connect_network(&attachment.network, &container_id, &attachment.aliases)
                .await?;
        }
    }
    Ok(())
}

fn build_create_args(plan: &ContainerPlan) -> Vec<String> {
    let mut args = vec!["--name".to_string(), plan.name.clone()];
    append_container_spec_args(&mut args, &plan.spec);
    args.push(plan.image_reference.clone());
    args.extend(final_command(&plan.spec));
    args
}

fn append_container_spec_args(args: &mut Vec<String>, spec: &ContainerSpec) {
    if let Some(hostname) = &spec.hostname {
        args.push("--hostname".to_string());
        args.push(hostname.clone());
    }
    if let Some(domainname) = &spec.domainname {
        args.push("--domainname".to_string());
        args.push(domainname.clone());
    }
    if let Some(user) = &spec.user {
        args.push("--user".to_string());
        args.push(user.clone());
    }
    for env in &spec.env {
        args.push("--env".to_string());
        args.push(env.clone());
    }
    for (key, value) in &spec.labels {
        args.push("--label".to_string());
        args.push(format!("{key}={value}"));
    }
    for port in &spec.exposed_ports {
        args.push("--expose".to_string());
        args.push(port.clone());
    }
    if spec.tty {
        args.push("--tty".to_string());
    }
    if spec.open_stdin {
        args.push("--interactive".to_string());
    }
    if let Some(working_dir) = &spec.working_dir {
        args.push("--workdir".to_string());
        args.push(working_dir.clone());
    }
    if let Some(entrypoint) = spec.entrypoint.first() {
        args.push("--entrypoint".to_string());
        args.push(entrypoint.clone());
    }
    for mount in &spec.mounts {
        match mount {
            ContainerMount::Volume { source, target, rw } => {
                args.push("--mount".to_string());
                args.push(format!(
                    "type=volume,src={source},dst={target}{}",
                    if *rw { "" } else { ",readonly" }
                ));
            }
            ContainerMount::Bind { source, target, rw } => {
                args.push("--mount".to_string());
                args.push(format!(
                    "type=bind,src={source},dst={target}{}",
                    if *rw { "" } else { ",readonly" }
                ));
            }
            ContainerMount::Tmpfs { target, options } => {
                args.push("--tmpfs".to_string());
                args.push(if let Some(options) = options {
                    format!("{target}:{options}")
                } else {
                    target.clone()
                });
            }
        }
    }
    for publish in &spec.publishes {
        args.push("--publish".to_string());
        args.push(format_publish(publish));
    }
    if let Some(restart_policy) = &spec.restart_policy {
        args.push("--restart".to_string());
        let mut value = restart_policy.name.clone();
        if let Some(count) = restart_policy.maximum_retry_count {
            if restart_policy.name == "on-failure" {
                value.push(':');
                value.push_str(&count.to_string());
            }
        }
        args.push(value);
    }
    if spec.privileged {
        args.push("--privileged".to_string());
    }
    if spec.read_only_rootfs {
        args.push("--read-only".to_string());
    }
    for host in &spec.extra_hosts {
        args.push("--add-host".to_string());
        args.push(host.clone());
    }
    if spec.auto_remove {
        args.push("--rm".to_string());
    }
    if let Some(primary_network) = &spec.primary_network {
        args.push("--network".to_string());
        args.push(primary_network.network.clone());
        for alias in &primary_network.aliases {
            args.push("--network-alias".to_string());
            args.push(alias.clone());
        }
    }
}

fn final_command(spec: &ContainerSpec) -> Vec<String> {
    let mut command = Vec::new();
    if spec.entrypoint.len() > 1 {
        command.extend(spec.entrypoint.iter().skip(1).cloned());
    }
    command.extend(spec.cmd.clone());
    command
}

fn format_publish(publish: &PortPublish) -> String {
    let mut out = String::new();
    if let Some(host_ip) = &publish.host_ip {
        if !host_ip.is_empty() {
            out.push_str(host_ip);
            out.push(':');
        }
    }
    if let Some(host_port) = &publish.host_port {
        if !host_port.is_empty() {
            out.push_str(host_port);
            out.push(':');
        }
    }
    out.push_str(&publish.container_port);
    out
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RestartPolicySpec;
    use std::collections::HashMap;

    #[test]
    fn final_command_merges_entrypoint_tail_and_cmd() {
        let spec = ContainerSpec {
            hostname: None,
            domainname: None,
            user: None,
            env: Vec::new(),
            labels: HashMap::new(),
            exposed_ports: Vec::new(),
            tty: false,
            open_stdin: false,
            working_dir: None,
            entrypoint: vec!["/bin/sh".into(), "-c".into()],
            cmd: vec!["echo hi".into()],
            mounts: Vec::new(),
            publishes: Vec::new(),
            restart_policy: None,
            privileged: false,
            read_only_rootfs: false,
            extra_hosts: Vec::new(),
            auto_remove: false,
            primary_network: None,
        };
        assert_eq!(
            final_command(&spec),
            vec!["-c".to_string(), "echo hi".to_string()]
        );
    }

    #[test]
    fn publish_format_handles_host_ip_and_port() {
        let publish = PortPublish {
            container_port: "5432/tcp".into(),
            host_ip: Some("127.0.0.1".into()),
            host_port: Some("15432".into()),
        };
        assert_eq!(format_publish(&publish), "127.0.0.1:15432:5432/tcp");
    }

    #[test]
    fn restart_policy_on_failure_keeps_retry_count() {
        let spec = ContainerSpec {
            hostname: None,
            domainname: None,
            user: None,
            env: Vec::new(),
            labels: HashMap::new(),
            exposed_ports: Vec::new(),
            tty: false,
            open_stdin: false,
            working_dir: None,
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            mounts: Vec::new(),
            publishes: Vec::new(),
            restart_policy: Some(RestartPolicySpec {
                name: "on-failure".into(),
                maximum_retry_count: Some(5),
            }),
            privileged: false,
            read_only_rootfs: false,
            extra_hosts: Vec::new(),
            auto_remove: false,
            primary_network: None,
        };
        let mut args = Vec::new();
        append_container_spec_args(&mut args, &spec);
        assert!(
            args.windows(2)
                .any(|window| window == ["--restart", "on-failure:5"])
        );
    }
}
