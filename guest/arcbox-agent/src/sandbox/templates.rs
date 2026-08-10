//! Template catalog handlers (CORE-107).
//!
//! Decode → manager → encode glue over the catalog surface on
//! [`SandboxManager`](arcbox_vm::SandboxManager), plus the Build
//! orchestrator, which drives the existing rootfs pipeline (`template.rs`
//! export + `rootfs_builder` conversion) and registers the result as the
//! catalog draft. `template.rs` (singular) is the
//! `CreateSandboxRequest.template` reference parser and docker exporter.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Mutex;

use arcbox_connect::sandbox_v1;
use arcbox_vm::template_catalog::{
    TemplateDefaultsSpec, TemplateEntry, WarmArtifact, compute_digest,
};
use buffa::Message;

use super::{SandboxService, convert, template};
use crate::error::SandboxError;

/// Operation-lock key for a template name: template builds/publishes/deletes
/// serialize per name, in a namespace sandbox ids cannot collide with
/// (`:` is invalid in a sandbox id).
fn operation_key(name: &str) -> String {
    format!("template:{name}")
}

/// What `CreateSandboxRequest.template` resolved to.
pub(super) enum TemplateSource {
    /// Built-in busybox + `vm-agent` image.
    Default,
    /// `docker:<ref>` — exported and converted at create time.
    DockerImage(String),
    /// A catalog template: pre-built rootfs, defaults already merged into
    /// the request, canonical ref already pinned.
    Catalog(arcbox_vm::template_catalog::ResolvedTemplate),
}

/// Reject the contradictory override combination the proto calls out:
/// `no_default_cmd` claims "explicitly no command" while `cmd` supplies one.
pub(super) fn validate_template_overrides(
    request: &sandbox_v1::CreateSandboxRequest,
) -> Result<(), SandboxError> {
    if request.no_default_cmd && !request.cmd.is_empty() {
        return Err(SandboxError::InvalidArgument(
            "no_default_cmd cannot be combined with a non-empty cmd".into(),
        ));
    }
    Ok(())
}

/// Fold a catalog template's defaults into the request (the proto's
/// per-field override contract): a set `limits` replaces the default
/// wholesale (zero subfield = daemon default) while an unset one inherits
/// the template's; a non-empty `cmd` replaces, an empty one inherits unless
/// `no_default_cmd` says "explicitly none"; `env` merges per key with the
/// request winning unless `no_default_env` discards the template's map.
/// `exposed_ports`/`ready_probe` have no per-create counterpart and stay on
/// the template entry. Runs before the create key is computed.
pub(super) fn merge_template_defaults(
    request: &mut sandbox_v1::CreateSandboxRequest,
    defaults: &TemplateDefaultsSpec,
) {
    if request.limits.as_option().is_none() && (defaults.vcpus != 0 || defaults.memory_mib != 0) {
        request.limits = Some(sandbox_v1::ResourceLimits {
            vcpus: defaults.vcpus,
            memory_mib: defaults.memory_mib,
            ..Default::default()
        })
        .into();
    }
    if !request.no_default_cmd && request.cmd.is_empty() {
        request.cmd = defaults.cmd.clone();
    }
    if !request.no_default_env {
        for (key, value) in &defaults.env {
            if !request.env.contains_key(key) {
                request.env.insert(key.clone(), value.clone());
            }
        }
    }
}

/// Content-addressed tag for a Dockerfile build:
/// `arcbox-template-build:<sha256[..16]>` of the Dockerfile bytes.
fn dockerfile_tag(dockerfile: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let hex = format!("{:x}", Sha256::digest(dockerfile));
    format!("arcbox-template-build:{}", &hex[..16])
}

/// Clears the in-flight marker for a template build on drop, so every error
/// path frees the name.
struct BuildFlight<'a> {
    name: String,
    builds: &'a Mutex<HashSet<String>>,
}

impl Drop for BuildFlight<'_> {
    fn drop(&mut self) {
        self.builds.lock().unwrap().remove(&self.name);
    }
}

impl SandboxService {
    /// Build a template from a source and register it as the catalog draft.
    /// Blocks for the whole pipeline; a second Build on the same name errors
    /// instead of queueing behind a long conversion.
    pub async fn build_template(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::Template, SandboxError> {
        use sandbox_v1::build_template_request::Source;
        let req = sandbox_v1::BuildTemplateRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        arcbox_vm::template_catalog::validate_template_name(&req.name)
            .map_err(SandboxError::from)?;
        let defaults = convert::template_defaults_from_proto(&req.defaults)?;
        let source = req.source.clone().ok_or_else(|| {
            SandboxError::InvalidArgument(
                "build source is required: docker_ref, dockerfile, or snapshot_id".into(),
            )
        })?;
        let _flight = self.begin_template_build(&req.name)?;
        let labels: HashMap<String, String> = req.labels.clone().into_iter().collect();
        match source {
            Source::DockerRef(image) => {
                self.build_template_from_docker(&req.name, &image, defaults, labels, req.prewarm)
                    .await
            }
            Source::Dockerfile(dockerfile) => {
                self.build_template_from_dockerfile(
                    &req.name,
                    &dockerfile,
                    defaults,
                    labels,
                    req.prewarm,
                )
                .await
            }
            // `prewarm` is ignored for snapshot sources — warm by
            // construction, per the proto.
            Source::SnapshotId(snapshot_id) => {
                self.build_template_from_snapshot(&req.name, &snapshot_id, defaults, labels)
                    .await
            }
        }
    }

    /// Promote an existing checkpoint into a template: the copied snapshot
    /// becomes the template's warm start point ("warm by construction" —
    /// `prewarm` is ignored for this source, per the proto). No build runs.
    async fn build_template_from_snapshot(
        &self,
        name: &str,
        snapshot_id: &str,
        defaults: TemplateDefaultsSpec,
        labels: HashMap<String, String>,
    ) -> Result<sandbox_v1::Template, SandboxError> {
        if snapshot_id.trim().is_empty() {
            return Err(SandboxError::InvalidArgument(
                "snapshot_id must name a checkpoint".into(),
            ));
        }
        let promoted = self
            .manager
            .promote_snapshot_to_template(snapshot_id, name)
            .await
            .map_err(SandboxError::from)?;
        // Content identity is the ORIGIN checkpoint, never the fresh copy id:
        // re-promoting the same source must reproduce the digest so Publish
        // stays idempotent and canonical refs pin content. Displaced copies
        // are released by snapshot id, which needs no digest involvement.
        let digest = compute_digest(snapshot_id, Some("promoted"), &defaults, &labels);
        // Any failure between the committed copy and its registration must
        // take the copy with it, or it sits orphaned outside every listing.
        let rootfs_bytes = match tokio::fs::metadata(&promoted.rootfs_path).await {
            Ok(meta) => meta.len(),
            Err(e) => {
                self.manager
                    .discard_promoted_snapshot(&promoted.snapshot_id)
                    .await;
                return Err(SandboxError::Internal(format!(
                    "stat {}: {e}",
                    promoted.rootfs_path
                )));
            }
        };
        let entry = TemplateEntry {
            version: String::new(),
            digest,
            rootfs_path: promoted.rootfs_path.clone(),
            warm: Some(WarmArtifact {
                snapshot_id: promoted.snapshot_id.clone(),
                vcpus: promoted.geometry.vcpus,
                memory_mib: promoted.geometry.memory_mib,
            }),
            defaults,
            labels,
            created_at: chrono::Utc::now(),
            size_bytes: promoted.artifact_bytes + rootfs_bytes,
        };
        self.register_draft(name, entry).await
    }

    /// Register a built entry, discarding its warm snapshot when
    /// registration fails — the snapshot would otherwise sit as a
    /// (recoverable) orphan until an operator noticed the log line.
    async fn register_draft(
        &self,
        name: &str,
        entry: TemplateEntry,
    ) -> Result<sandbox_v1::Template, SandboxError> {
        // The registration step joins the same per-name operation lock
        // Publish/Delete hold, so the final catalog mutation serializes with
        // theirs; the long build phases deliberately run outside it (holding
        // it for minutes would block every other verb on the name — the
        // in-flight guard already keeps concurrent Builds out).
        let _operation = self.operations.lock(&operation_key(name)).await;
        let warm_id = entry.warm.as_ref().map(|w| w.snapshot_id.clone());
        match self.manager.register_template_draft(name, entry).await {
            Ok(entry) => Ok(convert::template_to_proto(name, &entry)),
            // `Unavailable` is the atomic-write durability-uncertain shape:
            // the record may already be renamed into place and referencing
            // the snapshot, so deleting it here would install a template
            // whose warm restore points at missing artifacts. Leave the
            // copy; the error is retryable and the referenced-or-orphan
            // outcome is safe either way.
            Err(error @ arcbox_vm::VmmError::Unavailable(_)) => Err(SandboxError::from(error)),
            Err(error) => {
                // Registration certainly did not commit — the copy is
                // otherwise orphaned (recoverable, but why wait).
                if let Some(snapshot_id) = warm_id {
                    self.manager.discard_promoted_snapshot(&snapshot_id).await;
                }
                Err(SandboxError::from(error))
            }
        }
    }

    /// Build inline Dockerfile content in the guest's dockerd, then proceed
    /// exactly as a `docker_ref` build of the resulting image.
    ///
    /// The tag is content-addressed (`arcbox-template-build:<sha256[..16]>`
    /// of the Dockerfile bytes): an identical rebuild reuses the image, and
    /// two concurrent Builds of different templates cannot race one mutable
    /// tag. The build context holds only the Dockerfile — `COPY`/`ADD` of
    /// local paths fails inside the build with dockerd's own message.
    async fn build_template_from_dockerfile(
        &self,
        name: &str,
        dockerfile: &str,
        defaults: TemplateDefaultsSpec,
        labels: HashMap<String, String>,
        prewarm: bool,
    ) -> Result<sandbox_v1::Template, SandboxError> {
        if dockerfile.trim().is_empty() {
            return Err(SandboxError::InvalidArgument(
                "dockerfile content must not be empty".into(),
            ));
        }
        let tag = dockerfile_tag(dockerfile.as_bytes());
        if template::inspect_image(&tag).await.is_ok() {
            tracing::info!(template = name, %tag, "reusing previously built dockerfile image");
        } else {
            template::build_image(dockerfile.as_bytes(), &tag)
                .await
                .map_err(|e| SandboxError::Internal(format!("template build {name}: {e:#}")))?;
        }
        self.build_template_from_docker(name, &tag, defaults, labels, prewarm)
            .await
    }

    /// Export `image` from the guest's dockerd, convert it to a cached ext4,
    /// optionally boot-and-checkpoint it (prewarm), and register the draft.
    async fn build_template_from_docker(
        &self,
        name: &str,
        image: &str,
        defaults: TemplateDefaultsSpec,
        labels: HashMap<String, String>,
        prewarm: bool,
    ) -> Result<sandbox_v1::Template, SandboxError> {
        if image.trim().is_empty() {
            return Err(SandboxError::InvalidArgument(
                "docker_ref must name an image".into(),
            ));
        }
        let layout = template::export_docker_image(image)
            .await
            .map_err(|e| SandboxError::Internal(format!("template build {image}: {e:#}")))?;
        // Snapshot-referenced images must survive the conversion's cache
        // sweep — a restore cannot rebuild its dm-snapshot origin.
        let pinned = self
            .manager
            .pinned_rootfs_paths()
            .map_err(SandboxError::from)?;
        let rootfs = crate::rootfs_builder::convert_layer_to_rootfs(&layout, &pinned)
            .await
            .map_err(|e| SandboxError::Internal(format!("template build {image}: {e:#}")))?;
        // The cache file stem (`rootfs-<layer>-<agent>`) is content-derived —
        // layer diff IDs plus the injected vm-agent — which makes it the
        // digest's source identity: stable across rebuilds, changed by
        // either a new image filesystem or a new agent.
        let source_identity = Path::new(&rootfs)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                SandboxError::Internal(format!("unparsable rootfs cache path {rootfs}"))
            })?
            .to_owned();
        let rootfs_bytes = tokio::fs::metadata(&rootfs)
            .await
            .map_err(|e| SandboxError::Internal(format!("stat {rootfs}: {e}")))?
            .len();
        let (warm, artifact_bytes) = if prewarm {
            let outcome = self
                .manager
                .prewarm_template(name, &rootfs, &defaults)
                .await
                .map_err(SandboxError::from)?;
            (Some(outcome.warm), outcome.artifact_bytes)
        } else {
            (None, 0)
        };
        // The warm input is a content TAG (prewarmed + geometry), never the
        // freshly minted snapshot id — an identical rebuild must reproduce
        // the digest or idempotent re-publish breaks.
        let warm_tag = warm
            .as_ref()
            .map(|w| format!("prewarmed:{}x{}", w.vcpus, w.memory_mib));
        let digest = compute_digest(&source_identity, warm_tag.as_deref(), &defaults, &labels);
        let entry = TemplateEntry {
            version: String::new(),
            digest,
            rootfs_path: rootfs,
            warm,
            defaults,
            labels,
            created_at: chrono::Utc::now(),
            size_bytes: rootfs_bytes + artifact_bytes,
        };
        self.register_draft(name, entry).await
    }

    /// Mark `name` as having a build in flight; the guard clears it on drop.
    fn begin_template_build(&self, name: &str) -> Result<BuildFlight<'_>, SandboxError> {
        let mut builds = self.template_builds.lock().unwrap();
        if !builds.insert(name.to_owned()) {
            return Err(SandboxError::WrongState(format!(
                "a build for template {name} is already running"
            )));
        }
        Ok(BuildFlight {
            name: name.to_owned(),
            builds: &self.template_builds,
        })
    }
    /// Resolve a `name[:version]` reference to its template.
    pub fn get_template(&self, payload: &[u8]) -> Result<sandbox_v1::Template, SandboxError> {
        let req = sandbox_v1::GetTemplateRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let resolved = self
            .manager
            .get_template(&req.reference)
            .map_err(SandboxError::from)?;
        Ok(convert::template_to_proto(&resolved.name, &resolved.entry))
    }

    /// List templates (reference-ordered, paginated, label-filtered).
    pub fn list_templates(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::ListTemplatesResponse, SandboxError> {
        let req = sandbox_v1::ListTemplatesRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let mut rows = self.manager.list_templates().map_err(SandboxError::from)?;
        // Label filter: every requested pair must match (mirrors snapshots).
        if !req.labels.is_empty() {
            rows.retain(|(_, entry)| {
                req.labels
                    .iter()
                    .all(|(key, value)| entry.labels.get(key) == Some(value))
            });
        }
        let rows: Vec<(String, sandbox_v1::Template)> = rows
            .into_iter()
            .map(|(name, entry)| {
                let reference = format!("{name}:{}", entry.version);
                (reference, convert::template_to_proto(&name, &entry))
            })
            .collect();
        let (page, next_page_token) =
            convert::paginate(rows, |row| row.0.as_str(), req.page_size, &req.page_token);
        Ok(sandbox_v1::ListTemplatesResponse {
            templates: page.into_iter().map(|row| row.1).collect(),
            next_page_token,
            ..Default::default()
        })
    }

    /// Freeze a template's draft as an immutable version.
    pub async fn publish_template(
        &self,
        payload: &[u8],
    ) -> Result<sandbox_v1::Template, SandboxError> {
        let req = sandbox_v1::PublishTemplateRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let _operation = self.operations.lock(&operation_key(&req.name)).await;
        let entry = self
            .manager
            .publish_template(&req.name, &req.version)
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::template_to_proto(&req.name, &entry))
    }

    /// Delete a template version or a whole template with its artifacts.
    pub async fn delete_template(&self, payload: &[u8]) -> Result<(), SandboxError> {
        let req = sandbox_v1::DeleteTemplateRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let name = req
            .reference
            .split_once(':')
            .map_or(&*req.reference, |(name, _)| name);
        let _operation = self.operations.lock(&operation_key(name)).await;
        self.manager
            .delete_template(&req.reference)
            .await
            .map_err(SandboxError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dockerfile_tag_is_content_addressed_and_valid() {
        let a = dockerfile_tag(b"FROM alpine\n");
        let b = dockerfile_tag(b"FROM alpine\n");
        let c = dockerfile_tag(b"FROM debian\n");
        assert_eq!(a, b, "identical content must reuse the tag");
        assert_ne!(a, c, "different content must not share a tag");
        // repo:tag shape docker accepts, 16-hex suffix.
        let (repo, tag) = a.split_once(':').expect("repo:tag");
        assert_eq!(repo, "arcbox-template-build");
        assert_eq!(tag.len(), 16);
        assert!(tag.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    fn defaults() -> TemplateDefaultsSpec {
        TemplateDefaultsSpec {
            vcpus: 4,
            memory_mib: 2048,
            cmd: vec!["python".into(), "app.py".into()],
            env: HashMap::from([
                ("SHARED".to_string(), "template".to_string()),
                ("ONLY_TEMPLATE".to_string(), "yes".to_string()),
            ]),
            ..Default::default()
        }
    }

    #[test]
    fn unset_limits_inherit_and_set_limits_replace_wholesale() {
        let mut request = sandbox_v1::CreateSandboxRequest::default();
        merge_template_defaults(&mut request, &defaults());
        assert_eq!(request.limits.vcpus, 4);
        assert_eq!(request.limits.memory_mib, 2048);

        // A set message replaces wholesale: the zero memory_mib means the
        // DAEMON default, never a per-field fall-through to the template.
        let mut request = sandbox_v1::CreateSandboxRequest {
            limits: Some(sandbox_v1::ResourceLimits {
                vcpus: 1,
                memory_mib: 0,
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        merge_template_defaults(&mut request, &defaults());
        assert_eq!(request.limits.vcpus, 1);
        assert_eq!(request.limits.memory_mib, 0);
    }

    #[test]
    fn cmd_inherits_replaces_or_suppresses() {
        let mut request = sandbox_v1::CreateSandboxRequest::default();
        merge_template_defaults(&mut request, &defaults());
        assert_eq!(
            request.cmd,
            vec!["python".to_string(), "app.py".to_string()]
        );

        let mut request = sandbox_v1::CreateSandboxRequest {
            cmd: vec!["bash".into()],
            ..Default::default()
        };
        merge_template_defaults(&mut request, &defaults());
        assert_eq!(request.cmd, vec!["bash".to_string()]);

        let mut request = sandbox_v1::CreateSandboxRequest {
            no_default_cmd: true,
            ..Default::default()
        };
        merge_template_defaults(&mut request, &defaults());
        assert!(request.cmd.is_empty(), "explicit empty must stay empty");
    }

    #[test]
    fn env_merges_per_key_with_the_request_winning() {
        let mut request = sandbox_v1::CreateSandboxRequest::default();
        request.env.insert("SHARED".into(), "request".into());
        request.env.insert("ONLY_REQUEST".into(), "yes".into());
        merge_template_defaults(&mut request, &defaults());
        assert_eq!(
            request.env.get("SHARED").map(String::as_str),
            Some("request")
        );
        assert_eq!(
            request.env.get("ONLY_TEMPLATE").map(String::as_str),
            Some("yes")
        );
        assert_eq!(
            request.env.get("ONLY_REQUEST").map(String::as_str),
            Some("yes")
        );

        let mut request = sandbox_v1::CreateSandboxRequest {
            no_default_env: true,
            ..Default::default()
        };
        request.env.insert("ONLY_REQUEST".into(), "yes".into());
        merge_template_defaults(&mut request, &defaults());
        assert!(!request.env.contains_key("ONLY_TEMPLATE"));
        assert_eq!(request.env.len(), 1);
    }

    #[test]
    fn contradictory_cmd_flags_are_rejected() {
        let request = sandbox_v1::CreateSandboxRequest {
            no_default_cmd: true,
            cmd: vec!["bash".into()],
            ..Default::default()
        };
        assert!(validate_template_overrides(&request).is_err());
        let request = sandbox_v1::CreateSandboxRequest {
            no_default_cmd: true,
            ..Default::default()
        };
        assert!(validate_template_overrides(&request).is_ok());
    }
}
