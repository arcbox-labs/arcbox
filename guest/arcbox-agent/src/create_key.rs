//! Stable identity for sandbox creation requests.

use std::collections::BTreeMap;

use arcbox_connect::sandbox_v1::{
    CreateSandboxRequest, Mount, NetworkSpec, ResourceLimits, RestoreRequest,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const CREATE_KEY_DOMAIN: &[u8] = b"arcbox.sandbox.create-key/v1\0";
const RESTORE_KEY_DOMAIN: &[u8] = b"arcbox.sandbox.restore-key/v1\0";

#[derive(Serialize)]
struct CanonicalCreateRequest<'a> {
    id: &'a str,
    labels: BTreeMap<&'a str, &'a str>,
    limits: Option<&'a ResourceLimits>,
    cmd: &'a [String],
    env: BTreeMap<&'a str, &'a str>,
    working_dir: &'a str,
    user: &'a str,
    mounts: &'a [Mount],
    network: Option<&'a NetworkSpec>,
    ttl_seconds: u32,
    ssh_public_key: Option<&'a str>,
    template: &'a str,
}

#[derive(Serialize)]
struct CanonicalRestoreRequest<'a> {
    id: &'a str,
    snapshot_id: &'a str,
    labels: BTreeMap<&'a str, &'a str>,
    network_override: bool,
    ttl_seconds: u32,
}

fn hash(domain: &[u8], value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value)
        .expect("serializing a canonical sandbox request into memory cannot fail");
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

/// Return the versioned SHA-256 identity of a complete create request.
pub fn create_key(request: &CreateSandboxRequest) -> String {
    let CreateSandboxRequest {
        id,
        labels,
        limits,
        cmd,
        env,
        working_dir,
        user,
        mounts,
        network,
        ttl_seconds,
        ssh_public_key,
        template,
        ..
    } = request;
    let canonical = CanonicalCreateRequest {
        id,
        labels: labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect(),
        limits: limits.as_option(),
        cmd,
        env: env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect(),
        working_dir,
        user,
        mounts,
        network: network.as_option(),
        ttl_seconds: *ttl_seconds,
        ssh_public_key: ssh_public_key.as_deref(),
        template,
    };
    hash(CREATE_KEY_DOMAIN, &canonical)
}

/// Return the versioned SHA-256 identity of a complete restore request.
pub fn restore_key(request: &RestoreRequest) -> String {
    let RestoreRequest {
        id,
        snapshot_id,
        labels,
        network_override,
        ttl_seconds,
        ..
    } = request;
    let canonical = CanonicalRestoreRequest {
        id,
        snapshot_id,
        labels: labels
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect(),
        network_override: *network_override,
        ttl_seconds: *ttl_seconds,
    };
    hash(RESTORE_KEY_DOMAIN, &canonical)
}

#[cfg(test)]
mod tests {
    use arcbox_connect::sandbox_v1::{
        CreateSandboxRequest, Mount, NetworkMode, NetworkSpec, ResourceLimits, RestoreRequest,
    };

    use super::{create_key, restore_key};

    fn request() -> CreateSandboxRequest {
        CreateSandboxRequest {
            id: "sandbox-1".into(),
            labels: [
                ("app".into(), "api".into()),
                ("tier".into(), "backend".into()),
            ]
            .into_iter()
            .collect(),
            limits: Some(ResourceLimits {
                vcpus: 2,
                memory_mib: 4096,
                ..Default::default()
            })
            .into(),
            cmd: vec!["sh".into(), "-lc".into(), "echo ready".into()],
            env: [
                ("LANG".into(), "C.UTF-8".into()),
                ("MODE".into(), "test".into()),
            ]
            .into_iter()
            .collect(),
            working_dir: "/workspace".into(),
            user: "1000:1000".into(),
            mounts: vec![Mount {
                source: "/host/data".into(),
                target: "/data".into(),
                readonly: true,
                ..Default::default()
            }],
            network: Some(NetworkSpec {
                mode: NetworkMode::Enabled.into(),
                ..Default::default()
            })
            .into(),
            ttl_seconds: 300,
            ssh_public_key: Some("ssh-ed25519 test".into()),
            template: "docker:alpine".into(),
            ..Default::default()
        }
    }

    #[test]
    fn map_insertion_order_does_not_change_key() {
        let first = request();
        let mut reversed = first.clone();
        reversed.labels.clear();
        reversed.labels.insert("tier".into(), "backend".into());
        reversed.labels.insert("app".into(), "api".into());
        reversed.env.clear();
        reversed.env.insert("MODE".into(), "test".into());
        reversed.env.insert("LANG".into(), "C.UTF-8".into());

        let key = create_key(&first);
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(key, create_key(&reversed));
    }

    #[test]
    fn semantic_fields_change_key() {
        let original = request();
        let mut template_changed = original.clone();
        template_changed.template = "docker:debian".into();
        let mut memory_changed = original.clone();
        memory_changed
            .limits
            .as_option_mut()
            .expect("fixture has resource limits")
            .memory_mib += 1;

        assert_ne!(create_key(&original), create_key(&template_changed));
        assert_ne!(create_key(&original), create_key(&memory_changed));
    }

    #[test]
    fn restore_key_is_order_independent_and_covers_restore_inputs() {
        let original = RestoreRequest {
            id: "sandbox-1".into(),
            snapshot_id: "snapshot-1".into(),
            labels: [
                ("app".into(), "api".into()),
                ("tier".into(), "backend".into()),
            ]
            .into_iter()
            .collect(),
            network_override: true,
            ttl_seconds: 300,
            ..Default::default()
        };
        let mut reordered = original.clone();
        reordered.labels.clear();
        reordered.labels.insert("tier".into(), "backend".into());
        reordered.labels.insert("app".into(), "api".into());

        assert_eq!(restore_key(&original), restore_key(&reordered));
        for changed in [
            RestoreRequest {
                id: "sandbox-2".into(),
                ..original.clone()
            },
            RestoreRequest {
                snapshot_id: "snapshot-2".into(),
                ..original.clone()
            },
            RestoreRequest {
                labels: std::iter::once(("app".into(), "worker".into())).collect(),
                ..original.clone()
            },
            RestoreRequest {
                network_override: false,
                ..original.clone()
            },
            RestoreRequest {
                ttl_seconds: 301,
                ..original.clone()
            },
        ] {
            assert_ne!(restore_key(&original), restore_key(&changed));
        }
        assert_ne!(
            restore_key(&original),
            create_key(&CreateSandboxRequest {
                id: original.id,
                ..CreateSandboxRequest::default()
            })
        );
    }
}
