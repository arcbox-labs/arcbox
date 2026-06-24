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
