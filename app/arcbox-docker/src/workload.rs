//! Tracks which utility VM role each Docker workload is bound to.
//!
//! After `POST /containers/create` or `POST /containers/{id}/exec` selects a
//! role for a new workload, lifecycle handlers consult this registry to keep
//! follow-up operations on the same role. Without it, an `amd64` container
//! created on the `rosetta` utility VM would have its `start`/`logs`/`stop`
//! calls silently re-routed to `native`.
//!
//! Scope:
//!
//! - Process-local. After an `arcbox-daemon` restart, lookups for pre-existing
//!   workloads return `None` and callers fall back to the native default
//!   routing. Durable persistence is part of a later workstream once the
//!   connector layer actually resolves each role to a distinct VM.
//! - Tracks both container and exec IDs in a single namespace because Docker's
//!   ID generator makes them globally distinct.
//! - Build sessions are out of scope; their routing is decided per call from
//!   query parameters.

use crate::routing::UtilityVmRole;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Maps Docker workload IDs (container or exec) to the utility VM role they
/// were created on.
#[derive(Debug, Default)]
pub struct WorkloadRoleRegistry {
    inner: RwLock<HashMap<String, UtilityVmRole>>,
}

impl WorkloadRoleRegistry {
    /// Returns a new shared, empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records the role for `workload_id` (a canonical container or exec ID).
    ///
    /// Replacing an existing record with a different role indicates the
    /// caller is mixing roles for the same ID, which would corrupt routing
    /// for in-flight follow-up calls. Such a replacement is logged as a
    /// warning and the new value wins.
    pub async fn record(&self, workload_id: impl Into<String>, role: UtilityVmRole) {
        let id = workload_id.into();
        let previous = self.inner.write().await.insert(id.clone(), role);
        if let Some(previous) = previous
            && previous != role
        {
            tracing::warn!(
                workload_id = %id,
                previous = previous.as_str(),
                new = role.as_str(),
                "workload role record replaced with a different role",
            );
        }
    }

    /// Returns the recorded role, or `None` when no record exists.
    pub async fn lookup(&self, workload_id: &str) -> Option<UtilityVmRole> {
        self.inner.read().await.get(workload_id).copied()
    }

    /// Removes the record for `workload_id` and returns its previous value.
    pub async fn forget(&self, workload_id: &str) -> Option<UtilityVmRole> {
        self.inner.write().await.remove(workload_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lookup_returns_none_for_unknown_id() {
        let registry = WorkloadRoleRegistry::new();
        assert!(registry.lookup("missing").await.is_none());
    }

    #[tokio::test]
    async fn record_then_lookup_returns_stored_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record("abc", UtilityVmRole::Rosetta).await;
        assert_eq!(registry.lookup("abc").await, Some(UtilityVmRole::Rosetta));
    }

    #[tokio::test]
    async fn forget_removes_record_and_returns_previous() {
        let registry = WorkloadRoleRegistry::new();
        registry.record("abc", UtilityVmRole::Native).await;
        assert_eq!(registry.forget("abc").await, Some(UtilityVmRole::Native));
        assert!(registry.lookup("abc").await.is_none());
    }

    #[tokio::test]
    async fn record_overwrites_existing_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record("abc", UtilityVmRole::Native).await;
        registry.record("abc", UtilityVmRole::Rosetta).await;
        assert_eq!(registry.lookup("abc").await, Some(UtilityVmRole::Rosetta));
    }
}
