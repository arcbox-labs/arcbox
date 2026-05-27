/// Internal ArcBox host share tag.
pub const TAG_ARCBOX: &str = "arcbox";

/// Host `/Users` share tag.
pub const TAG_USERS: &str = "users";

/// Host `/private` share tag (macOS symlink targets: `/tmp`, `/var/folders`, etc.).
pub const TAG_PRIVATE: &str = "private";

/// Guest mountpoint for the internal ArcBox share.
pub const MOUNT_ARCBOX: &str = "/arcbox";

/// Guest mountpoint for the host `/Users` share.
pub const MOUNT_USERS: &str = "/Users";

/// Guest mountpoint for the host `/private` share.
pub const MOUNT_PRIVATE: &str = "/private";
