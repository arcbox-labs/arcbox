//! Helper image constants for volume-copy containers.

/// Name prefix shared by every object migration creates for its own use.
///
/// Planning excludes anything carrying it, so a previous run's scaffolding is
/// never mistaken for user data.
pub const HELPER_OBJECT_PREFIX: &str = "arcbox-migration-";

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
    use super::{helper_image_reference, is_helper_object};

    #[test]
    fn helper_objects_share_one_prefix() {
        assert!(is_helper_object(helper_image_reference()));
        assert!(is_helper_object("arcbox-migration-src-pgdata"));
        assert!(is_helper_object("arcbox-migration-dst-pgdata"));
        assert!(!is_helper_object("my-arcbox-migration-notes"));
        assert!(!is_helper_object("postgres"));
    }
}
