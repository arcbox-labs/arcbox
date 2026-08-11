//! Built-in sandbox image templates.
//!
//! A template is a Dockerfile shipped inside the CLI, so a sandbox image for a
//! known workload can be built without the user writing or hosting anything.
//! Templates go through the same `docker build` path as `--from-dockerfile`
//! (see [`crate::rootfs_builder`]) — they are an input to it, not a parallel
//! mechanism.

/// A Dockerfile embedded in the binary.
pub struct Template {
    /// Name used by `--from-preset` and `sandbox presets`.
    pub name: &'static str,
    /// One-line summary shown when listing.
    pub description: &'static str,
    /// Dockerfile contents. Needs no build context: templates must not
    /// reference local files with `COPY`/`ADD`.
    pub dockerfile: &'static str,
}

/// Every template the CLI ships.
pub const TEMPLATES: &[Template] = &[Template {
    name: "claude",
    description: "Claude Code on Node.js 22 with git, running as a non-root user",
    dockerfile: include_str!("../assets/templates/claude.Dockerfile"),
}];

/// Look up a template by name.
#[must_use]
pub fn find(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|template| template.name == name)
}

/// Comma-separated template names, for error messages and help text.
#[must_use]
pub fn names() -> String {
    TEMPLATES
        .iter()
        .map(|template| template.name)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_resolves_known_names_only() {
        assert_eq!(find("claude").map(|t| t.name), Some("claude"));
        assert!(find("nope").is_none());
        assert!(find("").is_none());
    }

    #[test]
    fn template_names_are_unique() {
        let mut names: Vec<_> = TEMPLATES.iter().map(|t| t.name).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "template names must be unique");
    }

    #[test]
    fn every_template_is_a_buildable_dockerfile() {
        // Catches a template that would only fail once `docker build` runs.
        for template in TEMPLATES {
            let dir = tempfile::TempDir::new().unwrap();
            let path = dir.path().join("Dockerfile");
            std::fs::write(&path, template.dockerfile).unwrap();
            assert!(
                crate::rootfs_builder::looks_like_dockerfile(&path),
                "template {} is not a Dockerfile",
                template.name
            );
            assert!(
                !template.description.is_empty(),
                "template {} needs a description",
                template.name
            );
        }
    }

    #[test]
    fn templates_do_not_need_a_build_context() {
        // Templates are written to an empty temp dir, so a COPY/ADD of a local
        // path could never resolve.
        for template in TEMPLATES {
            for line in template.dockerfile.lines() {
                let directive = line.trim().to_ascii_uppercase();
                assert!(
                    !directive.starts_with("COPY ") && !directive.starts_with("ADD "),
                    "template {} uses a build context: {line}",
                    template.name
                );
            }
        }
    }
}
