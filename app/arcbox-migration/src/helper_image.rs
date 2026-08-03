//! Helper image constants for volume-copy containers.

/// Name prefix shared by every *container* migration creates for its own use.
///
/// Planning excludes anything carrying it, so scaffolding is never mistaken for
/// user data. The random token is what makes that exclusion safe:
/// `arcbox-migration-` alone is a namespace ArcBox's own services may
/// legitimately name containers in, and excluding the bare prefix would drop
/// those from the plan silently. The helper *image* deliberately does not carry
/// the prefix — there is exactly one and it is matched by exact reference.
///
/// The token is fixed rather than per-run so that a retry reconstructs the same
/// helper name and can clear a stray left by an interrupted run; see
/// `DockerCliRunner::remove_stale_helper`.
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
    use super::is_helper_object;

    // No positive `is_helper_object(format!("{HELPER_OBJECT_PREFIX}..."))` test
    // lives here: composing the input from the same constant the predicate
    // matches on holds for any value of it, including an empty string, so it
    // asserts nothing. What is worth pinning is the exclusion's boundary.

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
