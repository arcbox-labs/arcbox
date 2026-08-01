//! Migration plan construction.

use crate::docker_types::{
    ContainerInspect, DockerInfo, ImageInspect, MountPoint, NetworkInspect, RestartPolicy,
    VolumeInspect,
};
use crate::error::Result;
use crate::helper_image::{helper_image_reference, is_helper_object};
use crate::model::{
    ContainerMount, ContainerNetworkAttachment, ContainerPlan, ContainerSpec, ImagePlan,
    MigrationPlan, NetworkModeSpec, NetworkPlan, PortPublish, ReplacementSummary,
    RestartPolicySpec, RunningVolumeBlocker, SourceConfig, SourceInfo, VolumePlan,
};
use crate::runner::DockerCliRunner;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Builds migration plans from source and target Docker daemons.
#[derive(Debug, Clone)]
pub struct MigrationPlanner {
    target: DockerCliRunner,
}

impl MigrationPlanner {
    /// Creates a planner for the provided ArcBox target socket.
    #[must_use]
    pub fn new(target: DockerCliRunner) -> Self {
        Self { target }
    }

    /// Plans a migration from the provided source into the configured target.
    pub async fn plan(&self, source: SourceConfig) -> Result<MigrationPlan> {
        let source_runner = DockerCliRunner::new(source.socket_path.clone())?;

        let source_info = source_runner.info().await?;
        let target_images = self.target.list_images().await?;
        let target_image_tags = collect_target_tags(&target_images);
        let target_volumes =
            collect_names(self.target.list_volumes().await?, |volume| &volume.name);
        let target_networks =
            collect_names(self.target.list_networks().await?, |network| &network.name);
        let target_containers = collect_names(self.target.list_containers().await?, |container| {
            trimmed_name(container)
        });

        let source_images = source_runner.list_images().await?;
        let source_volumes = source_runner.list_volumes().await?;
        let source_networks = source_runner.list_networks().await?;
        // Drop migration's own scaffolding before anything derives from it, so
        // it cannot leak into volume usage, blockers, or the container plan.
        // `ensure_helper_image` leaves its image behind on both daemons, and a
        // crashed run can strand helper containers.
        let source_containers: Vec<_> = source_runner
            .list_containers()
            .await?
            .into_iter()
            .filter(|container| !is_helper_object(trimmed_name(container)))
            .collect();

        let mut unsupported_resources = Vec::new();

        let mut volume_usage: HashMap<String, Vec<(String, bool)>> = HashMap::new();
        for container in &source_containers {
            let container_name = trimmed_name(container).to_string();
            for mount in &container.mounts {
                if mount.mount_type == "volume" && !mount.name.is_empty() {
                    volume_usage
                        .entry(mount.name.clone())
                        .or_default()
                        .push((container_name.clone(), container.state.running));
                } else if mount.mount_type != "volume"
                    && mount.mount_type != "bind"
                    && mount.mount_type != "tmpfs"
                {
                    unsupported_resources.push(format!(
                        "container '{}' uses unsupported mount type '{}'",
                        container_name, mount.mount_type
                    ));
                }
            }
        }

        let volume_plans: Vec<_> = source_volumes
            .into_iter()
            .map(|volume| normalize_volume(volume, &target_volumes, &volume_usage))
            .inspect(|plan| {
                if plan.driver != "local" {
                    unsupported_resources.push(format!(
                        "volume '{}' uses unsupported driver '{}'",
                        plan.name, plan.driver
                    ));
                }
            })
            .collect();

        let blockers = volume_plans
            .iter()
            .filter_map(|volume| {
                let running: Vec<_> = volume_usage
                    .get(&volume.name)?
                    .iter()
                    .filter(|(_, running)| *running)
                    .map(|(name, _)| name.clone())
                    .collect();
                if running.is_empty() {
                    None
                } else {
                    Some(RunningVolumeBlocker {
                        volume_name: volume.name.clone(),
                        containers: running,
                    })
                }
            })
            .collect();

        let network_plans: Vec<_> = source_networks
            .into_iter()
            .map(|network| normalize_network(network, &target_networks))
            .inspect(|plan| {
                if plan.driver != "bridge" {
                    unsupported_resources.push(format!(
                        "network '{}' uses unsupported driver '{}'",
                        plan.name, plan.driver
                    ));
                }
            })
            .collect();
        let migrated_network_names: BTreeSet<_> = network_plans
            .iter()
            .map(|network| network.name.clone())
            .collect();

        let image_plan_data =
            normalize_images(&source_images, &source_containers, &target_image_tags);
        let image_refs_by_id: HashMap<_, _> = image_plan_data
            .iter()
            .map(|image| (image.image_id.clone(), image.export_references.clone()))
            .collect();

        let mut warnings = Vec::new();
        let mut container_plans: Vec<_> = source_containers
            .into_iter()
            .map(|container| {
                normalize_container(
                    container,
                    &target_containers,
                    &image_refs_by_id,
                    &migrated_network_names,
                    &mut warnings,
                    &mut unsupported_resources,
                )
            })
            .collect();
        // Recreate and start in source creation order: for a compose project
        // that is the order the services were brought up in.
        //
        // Sort on the parsed instant, not the string. Docker formats `Created`
        // with Go's RFC3339Nano, which strips trailing zeros from the fraction,
        // so the field is variable-width and byte order can invert real order.
        container_plans.sort_by_key(|plan| created_at(&plan.created));

        let replacements = build_replacements(
            &image_plan_data,
            &volume_plans,
            &network_plans,
            &container_plans,
        );
        warnings.extend(collect_missing_bind_sources(&container_plans));

        Ok(MigrationPlan {
            source: normalize_source_info(source, source_info),
            helper_image: helper_image_reference().to_string(),
            images: image_plan_data,
            volumes: volume_plans,
            networks: network_plans,
            containers: container_plans,
            unsupported_resources,
            warnings,
            replacements,
            blockers,
        })
    }
}

fn normalize_source_info(source: SourceConfig, info: DockerInfo) -> SourceInfo {
    SourceInfo {
        kind: source.kind,
        socket_path: source.socket_path,
        daemon_name: info.name,
        server_version: info.server_version,
        operating_system: info.operating_system,
        architecture: info.architecture,
    }
}

fn normalize_images(
    images: &[ImageInspect],
    containers: &[ContainerInspect],
    target_tags: &BTreeSet<String>,
) -> Vec<ImagePlan> {
    let mut ordered = BTreeMap::new();

    for image in images {
        let tags = meaningful_tags(&image.repo_tags);
        if tags.iter().any(|tag| is_helper_object(tag)) {
            continue;
        }
        if !tags.is_empty() {
            ordered.insert(
                image.id.clone(),
                ImagePlan {
                    image_id: image.id.clone(),
                    export_references: tags.clone(),
                    replace_tags: tags
                        .iter()
                        .filter(|tag| target_tags.contains(*tag))
                        .cloned()
                        .collect(),
                    repo_tags: tags,
                },
            );
        }
    }

    // Untagged images are only worth carrying when a container references them;
    // they export by ID and land untagged on the target. The plan records the
    // *source* ID here, which the target reassigns on load — the executor
    // rewrites the container's reference to the assigned ID after import.
    for container in containers {
        ordered
            .entry(container.image.clone())
            .or_insert_with(|| ImagePlan {
                image_id: container.image.clone(),
                export_references: vec![container.image.clone()],
                repo_tags: Vec::new(),
                replace_tags: Vec::new(),
            });
    }

    ordered.into_values().collect()
}

fn normalize_volume(
    volume: VolumeInspect,
    target_volumes: &BTreeSet<String>,
    usage: &HashMap<String, Vec<(String, bool)>>,
) -> VolumePlan {
    let attached_containers = usage
        .get(&volume.name)
        .map(|items| items.iter().map(|(name, _)| name.clone()).collect())
        .unwrap_or_default();

    VolumePlan {
        name: volume.name.clone(),
        driver: volume.driver,
        labels: volume.labels.unwrap_or_default(),
        options: volume.options.unwrap_or_default(),
        replace_existing: target_volumes.contains(&volume.name),
        attached_containers,
    }
}

fn normalize_network(network: NetworkInspect, target_networks: &BTreeSet<String>) -> NetworkPlan {
    NetworkPlan {
        name: network.name.clone(),
        id: network.id,
        driver: network.driver,
        internal: network.internal,
        enable_ipv6: network.enable_ipv6,
        attachable: network.attachable,
        labels: network.labels.unwrap_or_default(),
        options: network.options.unwrap_or_default(),
        ipam: network.ipam.config,
        replace_existing: target_networks.contains(&network.name),
    }
}

/// Outcome of reading `HostConfig.NetworkMode`.
enum NetworkModeOutcome {
    Resolved(NetworkModeSpec),
    /// The mode cannot be reproduced; carries the blocking explanation.
    Unsupported(String),
}

/// Classifies `HostConfig.NetworkMode` against the networks being migrated.
///
/// Docker's contract: `bridge`, `host`, `none` and `container:<name|id>` are
/// the standard values, and any other value names a user-defined network.
fn classify_network_mode(
    mode: &str,
    container_name: &str,
    attachments: &[ContainerNetworkAttachment],
    warnings: &mut Vec<String>,
) -> NetworkModeOutcome {
    match mode {
        "" | "default" | "bridge" => NetworkModeOutcome::Resolved(NetworkModeSpec::Default),
        "host" => NetworkModeOutcome::Resolved(NetworkModeSpec::Host),
        "none" => NetworkModeOutcome::Resolved(NetworkModeSpec::None),
        other if other.starts_with("container:") => NetworkModeOutcome::Unsupported(format!(
            "container '{container_name}' shares another container's network namespace ('{other}'), which migration cannot reproduce"
        )),
        named => attachments
            .iter()
            .find(|attachment| attachment.network == named)
            .cloned()
            .map_or_else(
                || {
                    // The named network was filtered out of the migration (for
                    // example a non-bridge driver). Falling back to the default
                    // bridge keeps the container creatable.
                    warnings.push(format!(
                        "container '{container_name}' was on network '{named}', which is not part of this migration; it will join the default bridge instead"
                    ));
                    NetworkModeOutcome::Resolved(NetworkModeSpec::Default)
                },
                |attachment| NetworkModeOutcome::Resolved(NetworkModeSpec::Named(attachment)),
            ),
    }
}

/// Picks which of an image's references to recreate a container against.
///
/// Prefers the name the container was originally created under, so a container
/// built from `myapp:dev` does not come back reporting a sibling tag that
/// happens to sort first. Falls back to the plan's primary reference when the
/// original name is not one the image still carries.
fn preferred_reference(references: &[String], requested: &str) -> Option<String> {
    references
        .iter()
        .find(|reference| reference.as_str() == requested)
        .or_else(|| references.first())
        .cloned()
}

fn normalize_container(
    container: ContainerInspect,
    target_containers: &BTreeSet<String>,
    image_refs_by_id: &HashMap<String, Vec<String>>,
    migrated_network_names: &BTreeSet<String>,
    warnings: &mut Vec<String>,
    unsupported: &mut Vec<String>,
) -> ContainerPlan {
    let name = trimmed_name(&container).to_string();
    let image_reference = image_refs_by_id
        .get(&container.image)
        .and_then(|references| preferred_reference(references, &container.config.image))
        .unwrap_or_else(|| {
            if container.config.image.is_empty() {
                container.image.clone()
            } else {
                container.config.image.clone()
            }
        });

    let mut attachments = normalized_network_attachments(&container, migrated_network_names);
    // The primary network comes from NetworkMode, not from an arbitrary pick
    // out of the (alphabetically sorted) attachment list.
    let network_mode = match classify_network_mode(
        &container.host_config.network_mode,
        &name,
        &attachments,
        warnings,
    ) {
        NetworkModeOutcome::Resolved(mode) => mode,
        NetworkModeOutcome::Unsupported(reason) => {
            unsupported.push(reason);
            NetworkModeSpec::Default
        }
    };
    if let NetworkModeSpec::Named(primary) = &network_mode {
        attachments.retain(|attachment| attachment.network != primary.network);
    }

    ContainerPlan {
        name: name.clone(),
        id: container.id,
        image_reference,
        spec: ContainerSpec {
            hostname: non_empty(&container.config.hostname),
            domainname: non_empty(&container.config.domainname),
            user: non_empty(&container.config.user),
            env: container.config.env.unwrap_or_default(),
            labels: container.config.labels.unwrap_or_default(),
            exposed_ports: sorted(
                container
                    .config
                    .exposed_ports
                    .unwrap_or_default()
                    .into_keys()
                    .collect(),
            ),
            tty: container.config.tty,
            open_stdin: container.config.open_stdin,
            working_dir: non_empty(&container.config.working_dir),
            entrypoint: container.config.entrypoint.unwrap_or_default(),
            cmd: container.config.cmd.unwrap_or_default(),
            mounts: container.mounts.iter().map(normalize_mount).collect(),
            publishes: normalized_publishes(container.host_config.port_bindings),
            restart_policy: normalize_restart_policy(container.host_config.restart_policy),
            privileged: container.host_config.privileged,
            read_only_rootfs: container.host_config.readonly_rootfs,
            extra_hosts: container.host_config.extra_hosts.unwrap_or_default(),
            auto_remove: container.host_config.auto_remove,
            memory: positive(container.host_config.memory),
            nano_cpus: positive(container.host_config.nano_cpus),
            cap_add: sorted(container.host_config.cap_add.unwrap_or_default()),
            network_mode,
        },
        extra_networks: attachments,
        replace_existing: target_containers.contains(&name),
        was_running: container.state.running,
        created: container.created,
    }
}

fn normalize_mount(mount: &MountPoint) -> ContainerMount {
    match mount.mount_type.as_str() {
        "bind" => ContainerMount::Bind {
            source: mount.source.clone(),
            target: mount.destination.clone(),
            rw: mount.rw,
        },
        "tmpfs" => ContainerMount::Tmpfs {
            target: mount.destination.clone(),
            options: non_empty(&mount.mode),
        },
        _ => ContainerMount::Volume {
            source: if mount.name.is_empty() {
                mount.source.clone()
            } else {
                mount.name.clone()
            },
            target: mount.destination.clone(),
            rw: mount.rw,
        },
    }
}

fn normalized_publishes(
    port_bindings: Option<HashMap<String, Option<Vec<crate::docker_types::PortBinding>>>>,
) -> Vec<PortPublish> {
    let Some(port_bindings) = port_bindings else {
        return Vec::new();
    };

    let mut publishes = Vec::new();
    let mut ports: Vec<_> = port_bindings.into_iter().collect();
    ports.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (container_port, bindings) in ports {
        match bindings {
            Some(bindings) if !bindings.is_empty() => {
                for binding in bindings {
                    publishes.push(PortPublish {
                        container_port: container_port.clone(),
                        host_ip: non_empty(&binding.host_ip),
                        host_port: non_empty(&binding.host_port),
                    });
                }
            }
            _ => publishes.push(PortPublish {
                container_port,
                host_ip: None,
                host_port: None,
            }),
        }
    }
    publishes
}

fn normalize_restart_policy(policy: Option<RestartPolicy>) -> Option<RestartPolicySpec> {
    let policy = policy?;
    if policy.name.is_empty() || policy.name == "no" {
        None
    } else {
        Some(RestartPolicySpec {
            name: policy.name,
            maximum_retry_count: if policy.maximum_retry_count > 0 {
                Some(policy.maximum_retry_count)
            } else {
                None
            },
        })
    }
}

fn normalized_network_attachments(
    container: &ContainerInspect,
    migrated_network_names: &BTreeSet<String>,
) -> Vec<ContainerNetworkAttachment> {
    let name = trimmed_name(container);
    let mut attachments: Vec<_> = container
        .network_settings
        .networks
        .iter()
        .filter(|(network, _)| migrated_network_names.contains(*network))
        .map(|(network, endpoint)| ContainerNetworkAttachment {
            network: network.clone(),
            aliases: endpoint
                .aliases
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter(|alias| alias != name)
                .collect(),
        })
        .collect();
    attachments.sort_by(|left, right| left.network.cmp(&right.network));
    attachments
}

/// Flags bind mounts whose source path is absent on this host.
///
/// Source and target run on the same machine, so a bind mount that resolved
/// under the old runtime normally still resolves. When it does not the
/// container starts against an empty directory instead of failing, which is
/// hard to attribute afterwards — surface it before the migration runs.
fn collect_missing_bind_sources(containers: &[ContainerPlan]) -> Vec<String> {
    let mut warnings = Vec::new();
    for container in containers {
        for mount in &container.spec.mounts {
            if let ContainerMount::Bind { source, target, .. } = mount {
                if !std::path::Path::new(source).exists() {
                    warnings.push(format!(
                        "container '{}' binds '{source}' to '{target}', but that path does not exist on this host",
                        container.name
                    ));
                }
            }
        }
    }
    warnings
}

fn build_replacements(
    images: &[ImagePlan],
    volumes: &[VolumePlan],
    networks: &[NetworkPlan],
    containers: &[ContainerPlan],
) -> ReplacementSummary {
    ReplacementSummary {
        image_tags: images
            .iter()
            .flat_map(|image| image.replace_tags.clone())
            .collect(),
        volumes: volumes
            .iter()
            .filter(|volume| volume.replace_existing)
            .map(|volume| volume.name.clone())
            .collect(),
        networks: networks
            .iter()
            .filter(|network| network.replace_existing)
            .map(|network| network.name.clone())
            .collect(),
        containers: containers
            .iter()
            .filter(|container| container.replace_existing)
            .map(|container| container.name.clone())
            .collect(),
    }
}

fn meaningful_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter(|tag| *tag != "<none>:<none>")
        .cloned()
        .collect()
}

fn collect_names<T, F>(items: Vec<T>, name_fn: F) -> BTreeSet<String>
where
    F: Fn(&T) -> &str,
{
    items
        .into_iter()
        .map(|item| name_fn(&item).to_string())
        .collect()
}

fn collect_target_tags(images: &[ImageInspect]) -> BTreeSet<String> {
    images
        .iter()
        .flat_map(|image| meaningful_tags(&image.repo_tags))
        .collect()
}

fn trimmed_name(container: &ContainerInspect) -> &str {
    container.name.trim_start_matches('/')
}

/// Parses a Docker `Created` timestamp into a sortable instant.
///
/// Unparseable stamps sort first, which keeps them out of the way of the
/// containers whose order actually matters.
fn created_at(created: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(created)
        .ok()
        .and_then(|stamp| stamp.timestamp_nanos_opt())
        .unwrap_or(i64::MIN)
}

/// Treats Docker's "unset" sentinel of zero (or a negative) as absent.
fn positive(value: i64) -> Option<i64> {
    (value > 0).then_some(value)
}

/// Sorts a list so generated argument order does not depend on Docker's
/// response ordering, which keeps generated commands reproducible.
fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker_types::{EndpointSettings, NetworkSettings};
    use std::collections::HashMap;

    #[test]
    fn meaningful_tags_filters_none_entries() {
        let tags = meaningful_tags(&["<none>:<none>".into(), "nginx:latest".into()]);
        assert_eq!(tags, vec!["nginx:latest"]);
    }

    fn image_inspect(id: &str, tags: &[&str]) -> ImageInspect {
        ImageInspect {
            id: id.into(),
            repo_tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            repo_digests: Vec::new(),
        }
    }

    #[test]
    fn a_container_keeps_the_tag_it_was_created_under() {
        // One image, three tags: the container must come back as the tag it
        // was created from, not whichever one Docker happens to list first.
        let references = vec![
            "alpine:3.21".to_string(),
            "smoke-app:dev".to_string(),
            "smoke-app:latest".to_string(),
        ];
        assert_eq!(
            preferred_reference(&references, "smoke-app:dev").as_deref(),
            Some("smoke-app:dev")
        );
    }

    #[test]
    fn an_unknown_original_name_falls_back_to_the_primary_reference() {
        let references = vec!["alpine:3.21".to_string(), "smoke-app:dev".to_string()];
        // The tag it was created under is gone from the image.
        assert_eq!(
            preferred_reference(&references, "smoke-app:gone").as_deref(),
            Some("alpine:3.21")
        );
        // An untagged image exports by ID, which is also the fallback, so the
        // executor's rewrite key still matches.
        assert_eq!(
            preferred_reference(&["sha256:abc".to_string()], "abc").as_deref(),
            Some("sha256:abc")
        );
        assert_eq!(preferred_reference(&[], "anything"), None);
    }

    #[test]
    fn the_helper_image_is_never_planned() {
        // ensure_helper_image leaves it behind on both daemons, so without
        // this every run after the first would offer it as user data.
        let images = [
            image_inspect(
                "sha256:helper",
                &[crate::helper_image::helper_image_reference()],
            ),
            image_inspect("sha256:real", &["postgres:16"]),
        ];
        let plans = normalize_images(&images, &[], &BTreeSet::new());

        let refs: Vec<_> = plans
            .iter()
            .flat_map(|plan| plan.export_references.clone())
            .collect();
        assert_eq!(refs, vec!["postgres:16".to_string()]);
    }

    #[test]
    fn every_tag_of_an_image_is_exported() {
        let images = [image_inspect(
            "sha256:abc",
            &["myapp:dev", "myapp:latest", "<none>:<none>"],
        )];
        let plans = normalize_images(&images, &[], &BTreeSet::new());

        assert_eq!(plans.len(), 1);
        // All tags must reach `docker save`, otherwise the others are dropped.
        assert_eq!(
            plans[0].export_references,
            vec!["myapp:dev".to_string(), "myapp:latest".to_string()]
        );
        assert_eq!(plans[0].primary_reference(), "myapp:dev");
    }

    fn classify(mode: &str, attachments: &[ContainerNetworkAttachment]) -> NetworkModeOutcome {
        let mut warnings = Vec::new();
        classify_network_mode(mode, "demo", attachments, &mut warnings)
    }

    fn resolved(mode: &str, attachments: &[ContainerNetworkAttachment]) -> NetworkModeSpec {
        match classify(mode, attachments) {
            NetworkModeOutcome::Resolved(spec) => spec,
            NetworkModeOutcome::Unsupported(reason) => panic!("unexpectedly unsupported: {reason}"),
        }
    }

    #[test]
    fn standard_network_modes_are_classified() {
        for mode in ["", "default", "bridge"] {
            assert_eq!(resolved(mode, &[]), NetworkModeSpec::Default);
        }
        assert_eq!(resolved("host", &[]), NetworkModeSpec::Host);
        assert_eq!(resolved("none", &[]), NetworkModeSpec::None);
    }

    #[test]
    fn named_network_mode_selects_its_attachment() {
        let attachments = [
            ContainerNetworkAttachment {
                network: "aaa-first-alphabetically".into(),
                aliases: Vec::new(),
            },
            ContainerNetworkAttachment {
                network: "usernet".into(),
                aliases: vec!["api".into()],
            },
        ];
        // The primary must come from NetworkMode, not from sort order.
        assert_eq!(
            resolved("usernet", &attachments),
            NetworkModeSpec::Named(attachments[1].clone())
        );
    }

    #[test]
    fn container_network_mode_is_unsupported() {
        let outcome = classify("container:abc123", &[]);
        let NetworkModeOutcome::Unsupported(reason) = outcome else {
            panic!("container mode must be rejected");
        };
        assert!(reason.contains("container:abc123"));
    }

    #[test]
    fn unmigrated_named_network_falls_back_with_a_warning() {
        let mut warnings = Vec::new();
        let outcome = classify_network_mode("macvlan0", "demo", &[], &mut warnings);
        assert!(matches!(
            outcome,
            NetworkModeOutcome::Resolved(NetworkModeSpec::Default)
        ));
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("macvlan0"));
    }

    fn plan_with_bind(name: &str, source: &str) -> ContainerPlan {
        ContainerPlan {
            name: name.into(),
            id: "id".into(),
            image_reference: "img".into(),
            spec: ContainerSpec {
                mounts: vec![ContainerMount::Bind {
                    source: source.into(),
                    target: "/app".into(),
                    rw: true,
                }],
                ..ContainerSpec::default()
            },
            extra_networks: Vec::new(),
            replace_existing: false,
            was_running: false,
            created: String::new(),
        }
    }

    #[test]
    fn creation_order_survives_stripped_trailing_zeros() {
        // Docker uses Go's RFC3339Nano, which elides trailing zeros, so the
        // earlier stamp can be a byte-wise *prefix* of the later one and sort
        // after it. Whole-second fixtures never expose this.
        let earlier = "2026-08-01T08:09:16.84759688Z"; // .847596880, zero stripped
        let later = "2026-08-01T08:09:16.847596885Z";
        assert!(earlier > later, "precondition: byte order is inverted here");
        assert!(
            created_at(earlier) < created_at(later),
            "parsed order must be chronological"
        );
    }

    #[test]
    fn unparseable_creation_stamps_sort_first() {
        assert_eq!(created_at(""), i64::MIN);
        assert!(created_at("") < created_at("2026-08-01T08:09:16Z"));
    }

    #[test]
    fn zero_resource_limits_are_treated_as_unset() {
        assert_eq!(positive(0), None);
        assert_eq!(positive(-1), None);
        assert_eq!(positive(512), Some(512));
    }

    #[test]
    fn running_state_and_creation_order_are_carried_into_the_plan() {
        let mut warnings = Vec::new();
        let mut unsupported = Vec::new();
        let plan = normalize_container(
            ContainerInspect {
                id: "cid".into(),
                name: "/db".into(),
                image: "postgres".into(),
                created: "2024-05-02T10:00:00Z".into(),
                state: crate::docker_types::ContainerState {
                    status: "running".into(),
                    running: true,
                },
                config: crate::docker_types::ContainerConfig::default(),
                host_config: crate::docker_types::HostConfig::default(),
                network_settings: NetworkSettings::default(),
                mounts: Vec::new(),
            },
            &BTreeSet::new(),
            &HashMap::new(),
            &BTreeSet::new(),
            &mut warnings,
            &mut unsupported,
        );

        assert!(plan.was_running);
        assert_eq!(plan.created, "2024-05-02T10:00:00Z");
    }

    #[test]
    fn missing_bind_source_is_warned_about() {
        let present = tempfile::tempdir().unwrap();
        let plans = [
            plan_with_bind("ok", &present.path().to_string_lossy()),
            plan_with_bind("broken", "/definitely/not/a/real/path"),
        ];

        let warnings = collect_missing_bind_sources(&plans);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("broken"));
        assert!(warnings[0].contains("/definitely/not/a/real/path"));
    }

    #[test]
    fn untagged_image_referenced_by_container_exports_by_id() {
        let container = ContainerInspect {
            id: "cid".into(),
            name: "/demo".into(),
            image: "sha256:dangling".into(),
            created: "2024-01-01T00:00:00Z".into(),
            state: crate::docker_types::ContainerState {
                status: "exited".into(),
                running: false,
            },
            config: crate::docker_types::ContainerConfig::default(),
            host_config: crate::docker_types::HostConfig::default(),
            network_settings: NetworkSettings::default(),
            mounts: Vec::new(),
        };
        let plans = normalize_images(&[], std::slice::from_ref(&container), &BTreeSet::new());

        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].export_references, vec!["sha256:dangling"]);
        assert!(plans[0].repo_tags.is_empty());
    }

    #[test]
    fn network_aliases_filter_container_name() {
        let mut networks = HashMap::new();
        networks.insert(
            "usernet".to_string(),
            EndpointSettings {
                aliases: Some(vec!["demo".into(), "api".into()]),
            },
        );
        let container = ContainerInspect {
            id: "id".into(),
            name: "/demo".into(),
            image: "img".into(),
            created: "2024-01-01T00:00:00Z".into(),
            state: crate::docker_types::ContainerState {
                status: "running".into(),
                running: true,
            },
            config: crate::docker_types::ContainerConfig::default(),
            host_config: crate::docker_types::HostConfig::default(),
            network_settings: NetworkSettings { networks },
            mounts: Vec::new(),
        };
        let migrated_network_names = BTreeSet::from(["usernet".to_string()]);
        let attachments = normalized_network_attachments(&container, &migrated_network_names);
        assert_eq!(attachments[0].aliases, vec!["api".to_string()]);
    }
}
