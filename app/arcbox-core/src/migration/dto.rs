//! Projection of the internal migration plan onto its wire DTO.
//!
//! The two representations are deliberately not the same type. `arcbox_migration`
//! parses source inspect output into a model where invalid states are
//! unrepresentable — a mount is exactly one of three shapes, a container always
//! has a spec, a network mode either names a network or does not. Protobuf can
//! express none of that: every message field arrives as an `Option`, every enum
//! admits an unknown value, and a `oneof` still decodes to `None`. Letting the
//! generated types serve as the internal model would push that permissiveness
//! into the planner and executor, which is precisely what parsing at the
//! boundary is meant to prevent.
//!
//! So the flow is one-way. The planner produces the parsed model; this module
//! projects it outward for callers to read. Nothing converts a DTO back into the
//! model — `RunMigration` names a plan the daemon already holds by ID rather
//! than accepting one over the wire, so no code path has to reconstruct
//! invariants from optional fields.

use arcbox_migration::{
    ContainerMount, ContainerNetworkAttachment, ContainerPlan, ContainerSpec, ImagePlan,
    MigrationPlan, NetworkModeSpec, NetworkPlan, PortPublish, ReplacementSummary,
    RestartPolicySpec, RunningVolumeBlocker, SourceInfo, VolumePlan,
};
use arcbox_protocol::v1 as wire;

/// Projects an internal migration type onto the wire message that carries it.
///
/// Implemented on the internal types rather than as free functions so a caller
/// reads `plan.to_wire()`, and defined here rather than in `arcbox_migration`
/// so the planner and executor stay free of any wire dependency.
pub(super) trait ToWire {
    /// The message this type projects onto.
    type Wire;

    /// Builds the wire message. Infallible: the model is strictly the more
    /// precise of the two representations.
    fn to_wire(&self) -> Self::Wire;
}

impl ToWire for MigrationPlan {
    type Wire = wire::MigrationPlan;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationPlan {
            source: Some(self.source.to_wire()),
            helper_image: self.helper_image.clone(),
            images: self.images.to_wire(),
            volumes: self.volumes.to_wire(),
            networks: self.networks.to_wire(),
            containers: self.containers.to_wire(),
            unsupported_resources: self.unsupported_resources.clone(),
            warnings: self.warnings.clone(),
            replacements: Some(self.replacements.to_wire()),
            blockers: self.blockers.to_wire(),
        }
    }
}

impl ToWire for SourceInfo {
    type Wire = wire::MigrationSourceInfo;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationSourceInfo {
            kind: self.kind.as_str().to_string(),
            socket_path: self.socket_path.to_string_lossy().into_owned(),
            daemon_name: self.daemon_name.clone(),
            server_version: self.server_version.clone(),
            operating_system: self.operating_system.clone(),
            architecture: self.architecture.clone(),
        }
    }
}

impl ToWire for ImagePlan {
    type Wire = wire::MigrationImagePlan;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationImagePlan {
            image_id: self.image_id.clone(),
            export_references: self.export_references.clone(),
            repo_tags: self.repo_tags.clone(),
            replace_tags: self.replace_tags.clone(),
        }
    }
}

impl ToWire for VolumePlan {
    type Wire = wire::MigrationVolumePlan;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationVolumePlan {
            name: self.name.clone(),
            driver: self.driver.clone(),
            labels: self.labels.clone(),
            options: self.options.clone(),
            replace_existing: self.replace_existing,
            attached_containers: self.attached_containers.clone(),
        }
    }
}

impl ToWire for NetworkPlan {
    type Wire = wire::MigrationNetworkPlan;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationNetworkPlan {
            name: self.name.clone(),
            id: self.id.clone(),
            driver: self.driver.clone(),
            internal: self.internal,
            enable_ipv6: self.enable_ipv6,
            attachable: self.attachable,
            labels: self.labels.clone(),
            options: self.options.clone(),
            ipam: self
                .ipam
                .iter()
                .map(|entry| wire::MigrationNetworkIpam {
                    subnet: entry.subnet.clone(),
                    gateway: entry.gateway.clone(),
                    ip_range: entry.ip_range.clone(),
                })
                .collect(),
            replace_existing: self.replace_existing,
        }
    }
}

impl ToWire for ContainerPlan {
    type Wire = wire::MigrationContainerPlan;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationContainerPlan {
            name: self.name.clone(),
            id: self.id.clone(),
            image_reference: self.image_reference.clone(),
            spec: Some(self.spec.to_wire()),
            extra_networks: self.extra_networks.to_wire(),
            replace_existing: self.replace_existing,
            was_running: self.was_running,
            created: self.created.clone(),
        }
    }
}

impl ToWire for ContainerSpec {
    type Wire = wire::MigrationContainerSpec;

    fn to_wire(&self) -> Self::Wire {
        // `network_mode` splits into an enum plus an optional attachment: the
        // model's `Named` variant carries its network inline, which protobuf
        // cannot do without a oneof that decodes back to `None` anyway.
        let named_network = match &self.network_mode {
            NetworkModeSpec::Named(attachment) => Some(attachment.to_wire()),
            NetworkModeSpec::Default | NetworkModeSpec::Host | NetworkModeSpec::None => None,
        };
        wire::MigrationContainerSpec {
            hostname: self.hostname.clone().unwrap_or_default(),
            domainname: self.domainname.clone().unwrap_or_default(),
            user: self.user.clone().unwrap_or_default(),
            env: self.env.clone(),
            labels: self.labels.clone(),
            exposed_ports: self.exposed_ports.clone(),
            tty: self.tty,
            open_stdin: self.open_stdin,
            working_dir: self.working_dir.clone().unwrap_or_default(),
            entrypoint: self.entrypoint.clone(),
            cmd: self.cmd.clone(),
            mounts: self.mounts.to_wire(),
            publishes: self.publishes.to_wire(),
            restart_policy: self.restart_policy.as_ref().map(ToWire::to_wire),
            privileged: self.privileged,
            read_only_rootfs: self.read_only_rootfs,
            extra_hosts: self.extra_hosts.clone(),
            auto_remove: self.auto_remove,
            memory: self.memory.unwrap_or_default(),
            nano_cpus: self.nano_cpus.unwrap_or_default(),
            cap_add: self.cap_add.clone(),
            network_mode: self.network_mode.to_wire() as i32,
            named_network,
        }
    }
}

impl ToWire for NetworkModeSpec {
    type Wire = wire::MigrationNetworkMode;

    fn to_wire(&self) -> Self::Wire {
        match self {
            Self::Default => wire::MigrationNetworkMode::Default,
            Self::Host => wire::MigrationNetworkMode::Host,
            Self::None => wire::MigrationNetworkMode::None,
            Self::Named(_) => wire::MigrationNetworkMode::Named,
        }
    }
}

impl ToWire for ContainerMount {
    type Wire = wire::MigrationContainerMount;

    fn to_wire(&self) -> Self::Wire {
        // The model's three variants flatten into one message keyed by `type`,
        // so a consumer reads a fixed field set instead of a oneof. Fields that
        // do not apply to a variant stay at their zero value.
        match self {
            Self::Volume { source, target, rw } => wire::MigrationContainerMount {
                r#type: wire::MigrationMountType::Volume as i32,
                source: source.clone(),
                target: target.clone(),
                rw: *rw,
                options: String::new(),
            },
            Self::Bind { source, target, rw } => wire::MigrationContainerMount {
                r#type: wire::MigrationMountType::Bind as i32,
                source: source.clone(),
                target: target.clone(),
                rw: *rw,
                options: String::new(),
            },
            Self::Tmpfs { target, options } => wire::MigrationContainerMount {
                r#type: wire::MigrationMountType::Tmpfs as i32,
                source: String::new(),
                target: target.clone(),
                rw: false,
                options: options.clone().unwrap_or_default(),
            },
        }
    }
}

impl ToWire for PortPublish {
    type Wire = wire::MigrationPortPublish;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationPortPublish {
            container_port: self.container_port.clone(),
            host_ip: self.host_ip.clone().unwrap_or_default(),
            host_port: self.host_port.clone().unwrap_or_default(),
        }
    }
}

impl ToWire for RestartPolicySpec {
    type Wire = wire::MigrationRestartPolicy;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationRestartPolicy {
            name: self.name.clone(),
            maximum_retry_count: self.maximum_retry_count.unwrap_or_default(),
        }
    }
}

impl ToWire for ContainerNetworkAttachment {
    type Wire = wire::MigrationContainerNetworkAttachment;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationContainerNetworkAttachment {
            network: self.network.clone(),
            aliases: self.aliases.clone(),
        }
    }
}

impl ToWire for ReplacementSummary {
    type Wire = wire::MigrationReplacementSummary;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationReplacementSummary {
            containers: self.containers.clone(),
            volumes: self.volumes.clone(),
            networks: self.networks.clone(),
            image_tags: self.image_tags.clone(),
        }
    }
}

impl ToWire for RunningVolumeBlocker {
    type Wire = wire::MigrationRunningVolumeBlocker;

    fn to_wire(&self) -> Self::Wire {
        wire::MigrationRunningVolumeBlocker {
            volume_name: self.volume_name.clone(),
            containers: self.containers.clone(),
        }
    }
}

impl<T: ToWire> ToWire for Vec<T> {
    type Wire = Vec<T::Wire>;

    fn to_wire(&self) -> Self::Wire {
        self.iter().map(ToWire::to_wire).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::ToWire;
    use arcbox_migration::{
        ContainerMount, ContainerNetworkAttachment, ContainerPlan, ContainerSpec, NetworkModeSpec,
    };
    use arcbox_protocol::v1 as wire;

    fn plan_with(spec: ContainerSpec) -> wire::MigrationContainerPlan {
        ContainerPlan {
            name: "api".to_string(),
            id: "abc".to_string(),
            image_reference: "postgres:16".to_string(),
            spec,
            extra_networks: Vec::new(),
            replace_existing: false,
            was_running: true,
            created: "2026-08-03T00:00:00Z".to_string(),
        }
        .to_wire()
    }

    #[test]
    fn a_named_network_mode_splits_into_enum_and_attachment() {
        let wire = plan_with(ContainerSpec {
            network_mode: NetworkModeSpec::Named(ContainerNetworkAttachment {
                network: "app-net".to_string(),
                aliases: vec!["db".to_string()],
            }),
            ..ContainerSpec::default()
        });

        let spec = wire.spec.expect("spec is always projected");
        assert_eq!(
            spec.network_mode,
            wire::MigrationNetworkMode::Named as i32,
            "mode must name the NAMED member"
        );
        let attachment = spec
            .named_network
            .expect("NAMED carries the attachment it was built from");
        assert_eq!(attachment.network, "app-net");
        assert_eq!(attachment.aliases, vec!["db".to_string()]);
    }

    #[test]
    fn modes_without_a_network_leave_the_attachment_unset() {
        for mode in [
            NetworkModeSpec::Default,
            NetworkModeSpec::Host,
            NetworkModeSpec::None,
        ] {
            let wire = plan_with(ContainerSpec {
                network_mode: mode.clone(),
                ..ContainerSpec::default()
            });
            let spec = wire.spec.expect("spec is always projected");
            assert!(
                spec.named_network.is_none(),
                "{mode:?} must not carry an attachment"
            );
        }
    }

    #[test]
    fn mount_variants_flatten_onto_the_fields_they_use() {
        let wire = plan_with(ContainerSpec {
            mounts: vec![
                ContainerMount::Volume {
                    source: "pgdata".to_string(),
                    target: "/var/lib/postgresql".to_string(),
                    rw: true,
                },
                ContainerMount::Bind {
                    source: "/host/src".to_string(),
                    target: "/src".to_string(),
                    rw: false,
                },
                ContainerMount::Tmpfs {
                    target: "/tmp".to_string(),
                    options: Some("size=64m".to_string()),
                },
            ],
            ..ContainerSpec::default()
        });
        let mounts = wire.spec.expect("spec is always projected").mounts;

        assert_eq!(mounts[0].r#type, wire::MigrationMountType::Volume as i32);
        assert_eq!(mounts[0].source, "pgdata");
        assert!(mounts[0].rw);
        assert!(mounts[0].options.is_empty(), "volumes carry no options");

        assert_eq!(mounts[1].r#type, wire::MigrationMountType::Bind as i32);
        assert_eq!(mounts[1].source, "/host/src");
        assert!(!mounts[1].rw);

        assert_eq!(mounts[2].r#type, wire::MigrationMountType::Tmpfs as i32);
        assert!(mounts[2].source.is_empty(), "tmpfs has no source");
        assert_eq!(mounts[2].options, "size=64m");
    }

    #[test]
    fn unset_optionals_project_to_zero_values() {
        // The proto documents empty/0 as "not set", so a `None` must not become
        // a literal "None" or a sentinel a consumer would read as a real value.
        let wire = plan_with(ContainerSpec::default());
        let spec = wire.spec.expect("spec is always projected");

        assert!(spec.hostname.is_empty());
        assert!(spec.working_dir.is_empty());
        assert_eq!(spec.memory, 0);
        assert_eq!(spec.nano_cpus, 0);
        assert!(spec.restart_policy.is_none());
    }
}
