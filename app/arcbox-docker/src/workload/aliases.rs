//! Alias ownership helpers for workload role bindings.

use super::RegistryInner;

/// If `alias` currently belongs to a different canonical, drop it from that
/// canonical's alias list so a later `forget`/`rename_alias` against the old
/// owner can't accidentally remove the binding that now points to the new
/// owner.
pub(super) fn detach_alias_from_previous_owner(inner: &mut RegistryInner, alias: &str) {
    let Some(previous_owner) = inner.alias_owner.remove(alias) else {
        return;
    };
    if let Some(previous_list) = inner.aliases.get_mut(&previous_owner) {
        previous_list.retain(|existing| existing != alias);
    }
}
