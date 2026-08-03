//! Helper image constants for volume-copy containers.

/// Name prefix shared by every object migration creates for its own use.
///
/// Planning excludes anything carrying it, so a previous run's scaffolding is
/// never mistaken for user data. The random token is what makes that exclusion
/// safe: `arcbox-migration-` alone is a namespace ArcBox's own services may
/// legitimately name containers in, and excluding the bare prefix would drop
/// those from the plan silently. It is fixed rather than per-run, because a
/// crashed run strands helpers a later run must still recognize.
pub const HELPER_OBJECT_PREFIX: &str = "arcbox-migration-cea3989d-";

/// Returns the helper image reference used for temporary migration containers.
#[must_use]
pub const fn helper_image_reference() -> &'static str {
    "arcbox-migration-helper:latest"
}

/// Returns whether a name belongs to migration's own scaffolding.
#[must_use]
pub fn is_helper_object(name: &str) -> bool {
    name.starts_with(HELPER_OBJECT_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::{HELPER_OBJECT_PREFIX, is_helper_object};

    #[test]
    fn helper_containers_share_one_prefix() {
        assert!(is_helper_object(&format!(
            "{HELPER_OBJECT_PREFIX}src-pgdata"
        )));
        assert!(is_helper_object(&format!(
            "{HELPER_OBJECT_PREFIX}dst-pgdata"
        )));
    }

    #[test]
    fn the_bare_namespace_is_not_scaffolding() {
        // ArcBox's own services may own these; excluding them from the plan
        // would be silent data loss. The helper image is matched by exact
        // reference instead, so it does not need the prefix either.
        assert!(!is_helper_object("arcbox-migration-src-pgdata"));
        assert!(!is_helper_object("arcbox-migration-helper:latest"));
        assert!(!is_helper_object("postgres"));
    }
}
