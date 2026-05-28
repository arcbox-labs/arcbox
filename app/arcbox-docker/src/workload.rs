//! Tracks the utility VM role for each Docker workload during the daemon's
//! lifetime.
//!
//! Whenever a workload is created (`POST /containers/create`,
//! `POST /containers/{id}/exec`, or a BuildKit session), lifecycle handlers
//! consult this registry so follow-up operations land on the same role.
//! Without it an `amd64` container created on the `rosetta` utility VM would
//! have its `start`/`logs`/`stop` calls silently re-routed to `native`.
//!
//! Scope:
//!
//! - The registry is **in-process** and not durable. After an `arcbox-daemon`
//!   restart, lookups for pre-existing workloads return `None` and callers
//!   fall back to the native default. Surviving role bindings across daemon
//!   restarts will require either persistent storage or rebuilding the map by
//!   inspecting each role's guest dockerd at startup, and is part of a later
//!   workstream.
//! - Container and exec IDs share the same key namespace because Docker's
//!   ID generator makes them globally distinct.
//! - For containers, the canonical 64-char ID, the user-supplied name (e.g.
//!   `--name web`), and any subsequent rename are all registered. Lookup by
//!   short hex prefix (≥ 4 chars) is also supported so `docker logs ab12c3`
//!   resolves to the same role as the canonical entry.

use crate::routing::UtilityVmRole;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Tracks Docker workload IDs (container, exec, BuildKit session) and the
/// utility VM role they were created on. See module docs for scope and
/// guarantees.
#[derive(Debug, Default)]
pub struct WorkloadRoleRegistry {
    inner: RwLock<RegistryInner>,
}

#[derive(Debug, Default)]
struct RegistryInner {
    /// Direct key → role bindings (canonical IDs, aliases, exec IDs, etc.).
    roles: HashMap<String, UtilityVmRole>,
    /// Canonical ID → aliases registered for it, so a single `forget` or
    /// `rename_alias` call can update every binding atomically.
    aliases: HashMap<String, Vec<String>>,
}

impl WorkloadRoleRegistry {
    /// Returns a new shared, empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records a role binding for `id` (a canonical container ID, exec ID,
    /// or BuildKit session UUID).
    ///
    /// Replacing an existing binding with a different role indicates the
    /// caller is mixing roles for the same ID, which would corrupt routing
    /// for in-flight follow-up calls. Such a replacement is logged as a
    /// warning and the new value wins.
    pub async fn record(&self, id: impl Into<String>, role: UtilityVmRole) {
        let id = id.into();
        let previous = self.inner.write().await.roles.insert(id.clone(), role);
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

    /// Registers an additional lookup key (e.g. a container `--name`) that
    /// shares the role binding of `canonical`. The alias is tracked so that
    /// [`Self::forget`] or [`Self::rename_alias`] can drop it cleanly.
    ///
    /// Does nothing if `canonical` has no recorded role yet — callers should
    /// always [`Self::record`] the canonical first.
    pub async fn add_alias(&self, canonical: &str, alias: impl Into<String>) {
        let alias = alias.into();
        if alias.is_empty() || alias == canonical {
            return;
        }
        let mut guard = self.inner.write().await;
        let Some(role) = guard.roles.get(canonical).copied() else {
            tracing::debug!(
                canonical,
                alias = %alias,
                "skipping alias registration: canonical ID has no role binding",
            );
            return;
        };
        guard.roles.insert(alias.clone(), role);
        guard
            .aliases
            .entry(canonical.to_string())
            .or_default()
            .push(alias);
    }

    /// Replaces every alias previously registered against `canonical` with a
    /// single new alias. Used by `docker rename`, which preserves the
    /// container ID but invalidates the old name.
    pub async fn rename_alias(&self, canonical: &str, new_alias: impl Into<String>) {
        let new_alias = new_alias.into();
        let mut guard = self.inner.write().await;
        let Some(role) = guard.roles.get(canonical).copied() else {
            return;
        };
        if let Some(old_aliases) = guard.aliases.remove(canonical) {
            for old in old_aliases {
                guard.roles.remove(&old);
            }
        }
        if new_alias.is_empty() || new_alias == canonical {
            return;
        }
        guard.roles.insert(new_alias.clone(), role);
        guard.aliases.insert(canonical.to_string(), vec![new_alias]);
    }

    /// Returns the recorded role for `id`, considering exact matches and
    /// hex short-ID prefix matches against canonical entries.
    pub async fn lookup(&self, id: &str) -> Option<UtilityVmRole> {
        let guard = self.inner.read().await;
        if let Some(role) = guard.roles.get(id).copied() {
            return Some(role);
        }
        if !is_hex_short_id(id) {
            return None;
        }
        guard
            .roles
            .iter()
            .find(|(key, _)| is_canonical_id(key) && key.starts_with(id))
            .map(|(_, role)| *role)
    }

    /// Removes the record for `id`. If `id` is a canonical with tracked
    /// aliases, the aliases are dropped as well. Returns the role that was
    /// associated with `id`, if any.
    pub async fn forget(&self, id: &str) -> Option<UtilityVmRole> {
        let mut guard = self.inner.write().await;
        let role = guard.roles.remove(id);
        if let Some(aliases) = guard.aliases.remove(id) {
            for alias in aliases {
                guard.roles.remove(&alias);
            }
        }
        role
    }
}

/// A short hex ID is at least 4 hex characters and shorter than a full
/// canonical ID. We use this as the trigger for prefix scans so non-hex
/// names like `alpine` don't pay the cost of a scan and arbitrary strings
/// can't accidentally prefix-match a canonical ID.
fn is_hex_short_id(id: &str) -> bool {
    let len = id.len();
    (4..64).contains(&len) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Docker container/exec canonical IDs are 64 lowercase hex characters.
fn is_canonical_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANONICAL_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CANONICAL_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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

    #[tokio::test]
    async fn alias_lookup_returns_canonical_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        registry.add_alias(CANONICAL_A, "web").await;
        assert_eq!(registry.lookup("web").await, Some(UtilityVmRole::Rosetta));
    }

    #[tokio::test]
    async fn add_alias_is_noop_without_canonical_record() {
        let registry = WorkloadRoleRegistry::new();
        registry.add_alias(CANONICAL_A, "ghost").await;
        assert!(registry.lookup("ghost").await.is_none());
    }

    #[tokio::test]
    async fn forget_canonical_drops_aliases() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        registry.add_alias(CANONICAL_A, "web").await;
        registry.add_alias(CANONICAL_A, "frontend").await;
        assert_eq!(
            registry.forget(CANONICAL_A).await,
            Some(UtilityVmRole::Rosetta)
        );
        assert!(registry.lookup("web").await.is_none());
        assert!(registry.lookup("frontend").await.is_none());
    }

    #[tokio::test]
    async fn rename_alias_drops_old_and_adds_new() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.add_alias(CANONICAL_A, "old-name").await;
        registry.rename_alias(CANONICAL_A, "new-name").await;
        assert!(registry.lookup("old-name").await.is_none());
        assert_eq!(
            registry.lookup("new-name").await,
            Some(UtilityVmRole::Native)
        );
        assert_eq!(
            registry.lookup(CANONICAL_A).await,
            Some(UtilityVmRole::Native)
        );
    }

    #[tokio::test]
    async fn short_hex_prefix_resolves_to_canonical_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        // 12-char Docker short ID.
        assert_eq!(
            registry.lookup(&CANONICAL_A[..12]).await,
            Some(UtilityVmRole::Rosetta),
        );
        // 4-char minimum.
        assert_eq!(
            registry.lookup(&CANONICAL_A[..4]).await,
            Some(UtilityVmRole::Rosetta),
        );
    }

    #[tokio::test]
    async fn short_prefix_does_not_match_non_canonical_keys() {
        let registry = WorkloadRoleRegistry::new();
        // 4-char hex string that isn't a canonical 64-char ID — must not match.
        registry.record("abcd", UtilityVmRole::Rosetta).await;
        assert!(registry.lookup("abc").await.is_none());
    }

    #[tokio::test]
    async fn prefix_picks_correct_canonical_among_many() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.record(CANONICAL_B, UtilityVmRole::Rosetta).await;
        assert_eq!(
            registry.lookup(&CANONICAL_B[..8]).await,
            Some(UtilityVmRole::Rosetta),
        );
        assert_eq!(
            registry.lookup(&CANONICAL_A[..8]).await,
            Some(UtilityVmRole::Native),
        );
    }

    #[tokio::test]
    async fn non_hex_strings_skip_prefix_scan() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        // `alpine` contains non-hex characters; prefix scan must not fire.
        assert!(registry.lookup("alpine").await.is_none());
    }
}
