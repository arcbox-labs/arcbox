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
use arcbox_vm::template_catalog::{TemplateDefaultsSpec, TemplateEntry, compute_digest};
use buffa::Message;

use super::{SandboxService, convert, template};
use crate::error::SandboxError;

/// Operation-lock key for a template name: template builds/publishes/deletes
/// serialize per name, in a namespace sandbox ids cannot collide with
/// (`:` is invalid in a sandbox id).
fn operation_key(name: &str) -> String {
    format!("template:{name}")
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
        if req.prewarm && !matches!(source, Source::SnapshotId(_)) {
            // Loud, not silently ignored: a caller asking for a warm
            // template must not receive a cold one labeled as built.
            return Err(SandboxError::Unsupported(
                "prewarm is not implemented yet (CORE-107)".into(),
            ));
        }
        let _flight = self.begin_template_build(&req.name)?;
        let labels: HashMap<String, String> = req.labels.clone().into_iter().collect();
        match source {
            Source::DockerRef(image) => {
                self.build_template_from_docker(&req.name, &image, defaults, labels)
                    .await
            }
            Source::Dockerfile(_) => Err(SandboxError::Unsupported(
                "dockerfile builds are not implemented yet (CORE-107); \
                 build the image through the docker context and use docker_ref"
                    .into(),
            )),
            Source::SnapshotId(_) => Err(SandboxError::Unsupported(
                "snapshot promotion is not implemented yet (CORE-107)".into(),
            )),
        }
    }

    /// Export `image` from the guest's dockerd, convert it to a cached ext4,
    /// and register the draft entry.
    async fn build_template_from_docker(
        &self,
        name: &str,
        image: &str,
        defaults: TemplateDefaultsSpec,
        labels: HashMap<String, String>,
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
        let size_bytes = tokio::fs::metadata(&rootfs)
            .await
            .map_err(|e| SandboxError::Internal(format!("stat {rootfs}: {e}")))?
            .len();
        let digest = compute_digest(&source_identity, None, &defaults, &labels);
        let entry = TemplateEntry {
            version: String::new(),
            digest,
            rootfs_path: rootfs,
            warm: None,
            defaults,
            labels,
            created_at: chrono::Utc::now(),
            size_bytes,
        };
        // The registration step joins the same per-name operation lock
        // Publish/Delete hold, so the final catalog mutation serializes with
        // theirs; the long build phases above deliberately run outside it
        // (holding it for minutes would block every other verb on the name —
        // the in-flight guard already keeps concurrent Builds out).
        let _operation = self.operations.lock(&operation_key(name)).await;
        let entry = self
            .manager
            .register_template_draft(name, entry)
            .await
            .map_err(SandboxError::from)?;
        Ok(convert::template_to_proto(name, &entry))
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
