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
//! - Lookups return [`WorkloadRoleLookup`], a tri-state of
//!   `Found(role)` / `Missing` / `Ambiguous`. Ambiguity (a short ID that
//!   matches canonical workloads on more than one utility VM) is a
//!   first-class outcome so the handler layer can fail closed with a 409
//!   instead of silently picking native.
//! - The registry itself is **in-process**. After an `arcbox-daemon`
//!   restart it starts empty; durability across restarts is recovered
//!   *lazily*: the docker handler probes every configured role's guest
//!   dockerd on a `Missing` lookup, accepts exactly one match, and
//!   re-records the binding. Multiple matches across guests are
//!   reported as `Ambiguous`. See `rebuild_container_role_from_guests`
//!   in `handlers/mod.rs`.
//! - Container and exec IDs share the same key namespace because Docker's
//!   ID generator makes them globally distinct.
//! - For containers, the canonical 64-char ID, the user-supplied name (e.g.
//!   `--name web`), and any subsequent rename are all registered. Lookup by
//!   short hex prefix (≥ 4 chars) is also supported so `docker logs ab12c3`
//!   resolves to the same canonical entry, except when the prefix is
//!   ambiguous (handled per above).
//!
//! ABX-375 runs a single HV utility VM, so every recorded role is
//! [`UtilityVmRole::Native`]. The registry is retained (rather than removed)
//! because it still maps short IDs / `--name` aliases to canonical IDs and
//! fails closed on ambiguity; the role field is the seam that the demoted
//! VZ/Rosetta build backend and the ABX-374 fallback continue to rely on.

use crate::routing::UtilityVmRole;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Result of a registry lookup. Distinguishes "no role known" from
/// "multiple roles could claim this identifier" so the caller can fail
/// closed on ambiguity rather than silently defaulting to native.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadRoleLookup {
    /// Exactly one role is associated with the identifier.
    Found(UtilityVmRole),
    /// No role binding exists. The caller decides whether to rebuild,
    /// fall back to a default, or surface an error.
    Missing,
    /// Multiple distinct roles claim this identifier — typically a short
    /// hex prefix that matches canonical container IDs on more than one
    /// utility VM. Routing must refuse to pick one without explicit
    /// disambiguation by the user.
    Ambiguous,
}

impl WorkloadRoleLookup {
    /// Returns the role for a [`Self::Found`] result, otherwise `None`.
    #[must_use]
    pub const fn role(self) -> Option<UtilityVmRole> {
        match self {
            Self::Found(role) => Some(role),
            _ => None,
        }
    }
}

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
    /// Alias key → the canonical it currently belongs to. Required so that
    /// reassigning an alias (or forgetting the previous owner) cannot leave
    /// the alias list and the role binding out of sync.
    alias_owner: HashMap<String, String>,
}

impl WorkloadRoleRegistry {
    /// Returns a new shared, empty registry.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Records a role binding for `id` (a canonical container ID or exec ID).
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
    /// If the alias is currently owned by a different canonical (e.g. a
    /// previous container with the same name that has not yet been
    /// forgotten), the alias is detached from the previous owner first so
    /// the old owner's alias list never points to a key that now resolves
    /// to a different role.
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
        detach_alias_from_previous_owner(&mut guard, &alias);
        guard.roles.insert(alias.clone(), role);
        guard
            .alias_owner
            .insert(alias.clone(), canonical.to_string());
        let entry = guard.aliases.entry(canonical.to_string()).or_default();
        if !entry.iter().any(|existing| existing == &alias) {
            entry.push(alias);
        }
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
                guard.alias_owner.remove(&old);
            }
        }
        if new_alias.is_empty() || new_alias == canonical {
            return;
        }
        detach_alias_from_previous_owner(&mut guard, &new_alias);
        guard.roles.insert(new_alias.clone(), role);
        guard
            .alias_owner
            .insert(new_alias.clone(), canonical.to_string());
        guard.aliases.insert(canonical.to_string(), vec![new_alias]);
    }

    /// Returns the recorded role for `id`. Considers, in order:
    ///
    /// 1. Direct hits in the canonical/alias map.
    /// 2. Hex short-ID prefix matches against canonical entries: if every
    ///    match agrees on a single role that role is returned; if matches
    ///    disagree on role the result is
    ///    [`WorkloadRoleLookup::Ambiguous`] so the caller fails closed
    ///    instead of guessing.
    pub async fn lookup(&self, id: &str) -> WorkloadRoleLookup {
        let guard = self.inner.read().await;
        if let Some(role) = guard.roles.get(id).copied() {
            return WorkloadRoleLookup::Found(role);
        }
        if !is_hex_short_id(id) {
            return WorkloadRoleLookup::Missing;
        }
        let mut resolved: Option<UtilityVmRole> = None;
        for (key, role) in &guard.roles {
            if !is_canonical_id(key) || !key.starts_with(id) {
                continue;
            }
            match resolved {
                None => resolved = Some(*role),
                Some(existing) if existing != *role => {
                    tracing::warn!(
                        prefix = %id,
                        "short ID prefix matches workloads on multiple roles; refusing to guess",
                    );
                    return WorkloadRoleLookup::Ambiguous;
                }
                _ => {}
            }
        }
        match resolved {
            Some(role) => WorkloadRoleLookup::Found(role),
            None => WorkloadRoleLookup::Missing,
        }
    }

    /// Removes the record for `id` and keeps the alias bookkeeping
    /// consistent. Returns the role that was associated with `id`, if any.
    ///
    /// - If `id` is a canonical with tracked aliases, every alias still
    ///   owned by this canonical is dropped from `roles` and `alias_owner`.
    ///   Aliases that have since been reassigned to another canonical are
    ///   left intact.
    /// - If `id` is itself an alias, it is removed from its owner's alias
    ///   list and from `alias_owner`.
    pub async fn forget(&self, id: &str) -> Option<UtilityVmRole> {
        let mut guard = self.inner.write().await;
        let role = guard.roles.remove(id);
        if let Some(alias_list) = guard.aliases.remove(id) {
            for alias in alias_list {
                if guard.alias_owner.get(&alias).map(String::as_str) == Some(id) {
                    guard.roles.remove(&alias);
                    guard.alias_owner.remove(&alias);
                }
            }
        }
        if let Some(owner) = guard.alias_owner.remove(id)
            && let Some(owner_aliases) = guard.aliases.get_mut(&owner)
        {
            owner_aliases.retain(|a| a != id);
        }
        role
    }
}

/// If `alias` currently belongs to a different canonical, drop it from that
/// canonical's alias list so a later `forget`/`rename_alias` against the old
/// owner can't accidentally remove the binding that now points to the new
/// owner.
fn detach_alias_from_previous_owner(inner: &mut RegistryInner, alias: &str) {
    let Some(previous_owner) = inner.alias_owner.remove(alias) else {
        return;
    };
    if let Some(previous_list) = inner.aliases.get_mut(&previous_owner) {
        previous_list.retain(|existing| existing != alias);
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
        assert_eq!(
            registry.lookup("missing").await,
            WorkloadRoleLookup::Missing
        );
    }

    #[tokio::test]
    async fn record_then_lookup_returns_stored_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record("abc", UtilityVmRole::Rosetta).await;
        assert_eq!(
            registry.lookup("abc").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
    }

    #[tokio::test]
    async fn forget_removes_record_and_returns_previous() {
        let registry = WorkloadRoleRegistry::new();
        registry.record("abc", UtilityVmRole::Native).await;
        assert_eq!(registry.forget("abc").await, Some(UtilityVmRole::Native));
        assert_eq!(registry.lookup("abc").await, WorkloadRoleLookup::Missing);
    }

    #[tokio::test]
    async fn record_overwrites_existing_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record("abc", UtilityVmRole::Native).await;
        registry.record("abc", UtilityVmRole::Rosetta).await;
        assert_eq!(
            registry.lookup("abc").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
    }

    #[tokio::test]
    async fn alias_lookup_returns_canonical_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        registry.add_alias(CANONICAL_A, "web").await;
        assert_eq!(
            registry.lookup("web").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
    }

    #[tokio::test]
    async fn add_alias_is_noop_without_canonical_record() {
        let registry = WorkloadRoleRegistry::new();
        registry.add_alias(CANONICAL_A, "ghost").await;
        assert_eq!(registry.lookup("ghost").await, WorkloadRoleLookup::Missing);
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
        assert_eq!(registry.lookup("web").await, WorkloadRoleLookup::Missing);
        assert_eq!(
            registry.lookup("frontend").await,
            WorkloadRoleLookup::Missing
        );
    }

    #[tokio::test]
    async fn rename_alias_drops_old_and_adds_new() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.add_alias(CANONICAL_A, "old-name").await;
        registry.rename_alias(CANONICAL_A, "new-name").await;
        assert_eq!(
            registry.lookup("old-name").await,
            WorkloadRoleLookup::Missing
        );
        assert_eq!(
            registry.lookup("new-name").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Native)
        );
        assert_eq!(
            registry.lookup(CANONICAL_A).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Native)
        );
    }

    #[tokio::test]
    async fn short_hex_prefix_resolves_to_canonical_role() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        // 12-char Docker short ID.
        assert_eq!(
            registry.lookup(&CANONICAL_A[..12]).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
        // 4-char minimum.
        assert_eq!(
            registry.lookup(&CANONICAL_A[..4]).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
    }

    #[tokio::test]
    async fn short_prefix_does_not_match_non_canonical_keys() {
        let registry = WorkloadRoleRegistry::new();
        // 4-char hex string that isn't a canonical 64-char ID — must not match.
        registry.record("abcd", UtilityVmRole::Rosetta).await;
        assert_eq!(registry.lookup("abc").await, WorkloadRoleLookup::Missing);
    }

    #[tokio::test]
    async fn prefix_picks_correct_canonical_among_many() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.record(CANONICAL_B, UtilityVmRole::Rosetta).await;
        assert_eq!(
            registry.lookup(&CANONICAL_B[..8]).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
        assert_eq!(
            registry.lookup(&CANONICAL_A[..8]).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Native)
        );
    }

    #[tokio::test]
    async fn non_hex_strings_skip_prefix_scan() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Rosetta).await;
        // `alpine` contains non-hex characters; prefix scan must not fire.
        assert_eq!(registry.lookup("alpine").await, WorkloadRoleLookup::Missing);
    }

    /// Two canonicals share the same hex prefix but live on different VMs.
    /// Returning either role would be a silent misroute, so the registry
    /// reports the prefix as ambiguous and the caller must fail closed.
    #[tokio::test]
    async fn cross_role_prefix_collision_is_ambiguous() {
        let prefix = "abcd";
        let canonical_x = format!("{prefix}{}", "1".repeat(60));
        let canonical_y = format!("{prefix}{}", "2".repeat(60));
        let registry = WorkloadRoleRegistry::new();
        registry.record(canonical_x, UtilityVmRole::Native).await;
        registry.record(canonical_y, UtilityVmRole::Rosetta).await;
        assert_eq!(registry.lookup(prefix).await, WorkloadRoleLookup::Ambiguous);
    }

    /// Two canonicals share the same hex prefix but are on the same role.
    /// The user's prefix is ambiguous for *which container* but unambiguous
    /// for routing, so the registry returns the agreed role.
    #[tokio::test]
    async fn same_role_prefix_collision_resolves() {
        let prefix = "deed";
        let canonical_x = format!("{prefix}{}", "1".repeat(60));
        let canonical_y = format!("{prefix}{}", "2".repeat(60));
        let registry = WorkloadRoleRegistry::new();
        registry.record(canonical_x, UtilityVmRole::Rosetta).await;
        registry.record(canonical_y, UtilityVmRole::Rosetta).await;
        assert_eq!(
            registry.lookup(prefix).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
    }

    /// Reassigning the same alias from canonical A to canonical B must:
    ///   (a) make the alias resolve to B's role,
    ///   (b) survive a subsequent `forget(A)` — A's alias list should no
    ///       longer claim ownership of the alias.
    #[tokio::test]
    async fn alias_reassignment_survives_old_owner_forget() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.add_alias(CANONICAL_A, "web").await;
        registry.record(CANONICAL_B, UtilityVmRole::Rosetta).await;
        registry.add_alias(CANONICAL_B, "web").await;
        assert_eq!(
            registry.lookup("web").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );

        // Forgetting A must not drop the binding now owned by B.
        registry.forget(CANONICAL_A).await;
        assert_eq!(
            registry.lookup("web").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Rosetta)
        );
    }

    /// Renaming canonical A's alias to one currently owned by B steals the
    /// alias from B's bookkeeping rather than leaving a dangling entry that
    /// a later `forget(B)` would drop incorrectly.
    #[tokio::test]
    async fn rename_alias_steals_from_previous_owner() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.record(CANONICAL_B, UtilityVmRole::Rosetta).await;
        registry.add_alias(CANONICAL_B, "web").await;

        // A is renamed to "web", stealing the alias from B.
        registry.rename_alias(CANONICAL_A, "web").await;
        assert_eq!(
            registry.lookup("web").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Native)
        );

        // forget(B) must not undo A's claim on "web".
        registry.forget(CANONICAL_B).await;
        assert_eq!(
            registry.lookup("web").await,
            WorkloadRoleLookup::Found(UtilityVmRole::Native)
        );
    }

    /// Adding the same alias to the same canonical twice should not produce
    /// duplicate entries in the canonical's alias list — otherwise the next
    /// `forget` would attempt redundant cleanup and any future reassignment
    /// would mis-account.
    #[tokio::test]
    async fn duplicate_alias_for_same_canonical_is_deduped() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.add_alias(CANONICAL_A, "web").await;
        registry.add_alias(CANONICAL_A, "web").await;
        // A single forget must clear the alias cleanly.
        registry.forget(CANONICAL_A).await;
        assert_eq!(registry.lookup("web").await, WorkloadRoleLookup::Missing);
        assert_eq!(
            registry.lookup(CANONICAL_A).await,
            WorkloadRoleLookup::Missing
        );
    }

    /// Forgetting an alias key should leave the canonical untouched but
    /// remove the alias from `roles` and `alias_owner` so a later
    /// `forget(canonical)` does not try to scrub it twice.
    #[tokio::test]
    async fn forget_alias_only_removes_alias() {
        let registry = WorkloadRoleRegistry::new();
        registry.record(CANONICAL_A, UtilityVmRole::Native).await;
        registry.add_alias(CANONICAL_A, "web").await;
        assert_eq!(registry.forget("web").await, Some(UtilityVmRole::Native));
        assert_eq!(registry.lookup("web").await, WorkloadRoleLookup::Missing);
        assert_eq!(
            registry.lookup(CANONICAL_A).await,
            WorkloadRoleLookup::Found(UtilityVmRole::Native)
        );
        // forget(canonical) still succeeds after the alias was already gone.
        registry.forget(CANONICAL_A).await;
    }
}
