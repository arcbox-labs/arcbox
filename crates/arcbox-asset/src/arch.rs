//! Host architecture detection.

/// Returns the current host architecture as a string used in asset URLs.
///
/// - `aarch64` → `"arm64"`
/// - `x86_64`  → `"x86_64"`
/// - anything else → the raw `std::env::consts::ARCH` value
#[must_use]
pub fn current_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_arch_is_non_empty() {
        assert!(!current_arch().is_empty());
    }
}
