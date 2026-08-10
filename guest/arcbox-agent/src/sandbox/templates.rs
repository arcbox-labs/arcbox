//! Template catalog handlers (CORE-107).
//!
//! Thin decode → manager → encode glue over the catalog surface on
//! [`SandboxManager`](arcbox_vm::SandboxManager); build orchestration (the
//! rootfs pipeline) lands separately and registers its result through the
//! same manager methods. `template.rs` (singular) is the unrelated
//! `CreateSandboxRequest.template` reference parser and docker exporter.

use arcbox_connect::sandbox_v1;
use buffa::Message;

use super::{SandboxService, convert};
use crate::error::SandboxError;

/// Operation-lock key for a template name: template builds/publishes/deletes
/// serialize per name, in a namespace sandbox ids cannot collide with
/// (`:` is invalid in a sandbox id).
fn operation_key(name: &str) -> String {
    format!("template:{name}")
}

impl SandboxService {
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
