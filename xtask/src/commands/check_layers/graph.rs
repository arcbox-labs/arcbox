//! The workspace dependency graph the layer rules are evaluated over.
//!
//! Built once from `cargo metadata` ([`Graph::try_from`]) and then read by
//! the pure evaluator, so the evaluator can be tested on graphs written by
//! hand.

use std::fmt;

use anyhow::{Context, Result, bail};
use cargo_metadata::Metadata;
use cargo_metadata::camino::Utf8Path;

/// A layer is a top-level directory of the repository; a workspace member
/// belongs to the layer its manifest lives under.
///
/// A member under a directory this enum does not name fails the gate: the
/// layer rules must know every layer, so a new top-level directory is added
/// here (and to the rules that concern it) before it can carry a crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    Common,
    Virt,
    Rpc,
    Runtime,
    Engine,
    Computer,
    App,
    Guest,
    Sdk,
    Fleet,
    Tests,
    Xtask,
}

impl Layer {
    /// Every layer; keep in step with the variants above.
    pub const ALL: [Self; 12] = [
        Self::Common,
        Self::Virt,
        Self::Rpc,
        Self::Runtime,
        Self::Engine,
        Self::Computer,
        Self::App,
        Self::Guest,
        Self::Sdk,
        Self::Fleet,
        Self::Tests,
        Self::Xtask,
    ];

    /// The repository directory holding this layer's crates.
    pub const fn dir(self) -> &'static str {
        match self {
            Self::Common => "common",
            Self::Virt => "virt",
            Self::Rpc => "rpc",
            Self::Runtime => "runtime",
            Self::Engine => "engine",
            Self::Computer => "computer",
            Self::App => "app",
            Self::Guest => "guest",
            Self::Sdk => "sdk",
            Self::Fleet => "fleet",
            Self::Tests => "tests",
            Self::Xtask => "xtask",
        }
    }

    /// The layer whose directory is `dir`, if there is one.
    pub fn from_dir(dir: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|layer| layer.dir() == dir)
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.dir())
    }
}

/// A workspace member and its direct dependencies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// Package name.
    pub name: String,
    /// The layer the member's manifest lives under.
    pub layer: Layer,
    /// Package names of every direct dependency of every kind (normal, dev
    /// and build), workspace members and external crates alike — sorted and
    /// deduplicated. Renamed dependencies carry their real package name.
    pub deps: Vec<String>,
}

/// A direct dependency edge between two crates, `from -> to`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// The dependent workspace member.
    pub from: String,
    /// The dependency's package name.
    pub to: String,
}

impl fmt::Display for Edge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.from, self.to)
    }
}

/// A dependency as the graph sees it: one of our workspace members, or an
/// external crate the graph knows only by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// A workspace member.
    Member(&'a Member),
    /// A crate outside the workspace.
    External(&'a str),
}

impl Target<'_> {
    /// The package name.
    pub fn name(&self) -> &str {
        match self {
            Self::Member(member) => &member.name,
            Self::External(name) => name,
        }
    }
}

/// The direct-dependency graph of the workspace members.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Graph {
    /// Every workspace member, sorted by name.
    pub members: Vec<Member>,
}

impl Graph {
    /// Resolves a dependency name to a member of this graph, or to an
    /// external crate when no member carries the name.
    pub fn target<'a>(&'a self, name: &'a str) -> Target<'a> {
        self.members
            .iter()
            .find(|member| member.name == name)
            .map_or(Target::External(name), Target::Member)
    }
}

impl TryFrom<&Metadata> for Graph {
    type Error = anyhow::Error;

    /// Builds the graph from `cargo metadata --no-deps` output: one member
    /// per workspace package, placed in the layer of its manifest directory.
    fn try_from(metadata: &Metadata) -> Result<Self> {
        let mut members = Vec::new();
        for package in &metadata.packages {
            if !metadata.workspace_members.contains(&package.id) {
                continue;
            }
            let layer = layer_of_manifest(&metadata.workspace_root, &package.manifest_path)
                .with_context(|| format!("placing workspace member {} in a layer", package.name))?;
            let mut deps: Vec<String> = package
                .dependencies
                .iter()
                .map(|dependency| dependency.name.clone())
                .collect();
            deps.sort();
            deps.dedup();
            members.push(Member {
                name: package.name.to_string(),
                layer,
                deps,
            });
        }
        members.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Self { members })
    }
}

/// The layer of the member whose manifest is `manifest_path`: the first path
/// component below the workspace root.
fn layer_of_manifest(workspace_root: &Utf8Path, manifest_path: &Utf8Path) -> Result<Layer> {
    let relative = manifest_path
        .strip_prefix(workspace_root)
        .with_context(|| {
            format!("{manifest_path} lies outside the workspace root {workspace_root}")
        })?;
    let mut components = relative.components();
    let (Some(dir), Some(_)) = (components.next(), components.next()) else {
        bail!("{manifest_path} sits at the workspace root, under no layer directory");
    };
    Layer::from_dir(dir.as_str()).with_context(|| {
        let known: Vec<&str> = Layer::ALL.iter().map(|layer| layer.dir()).collect();
        format!(
            "`{dir}` is not a layer directory (known: {}); add it to `Layer` in {}",
            known.join(", "),
            file!()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_is_the_first_directory_below_the_root() {
        let root = Utf8Path::new("/ws");
        assert_eq!(
            layer_of_manifest(root, Utf8Path::new("/ws/engine/arcbox-engine/Cargo.toml")).unwrap(),
            Layer::Engine
        );
        assert_eq!(
            layer_of_manifest(root, Utf8Path::new("/ws/sdk/rust/Cargo.toml")).unwrap(),
            Layer::Sdk
        );
        assert_eq!(
            layer_of_manifest(root, Utf8Path::new("/ws/xtask/Cargo.toml")).unwrap(),
            Layer::Xtask
        );
    }

    #[test]
    fn unknown_directory_names_itself_and_the_known_layers() {
        let error = layer_of_manifest(
            Utf8Path::new("/ws"),
            Utf8Path::new("/ws/platform/node/Cargo.toml"),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("`platform`"), "{error}");
        assert!(error.contains("common, virt"), "{error}");
    }

    #[test]
    fn manifests_outside_or_at_the_root_have_no_layer() {
        let root = Utf8Path::new("/ws");
        assert!(layer_of_manifest(root, Utf8Path::new("/elsewhere/Cargo.toml")).is_err());
        assert!(layer_of_manifest(root, Utf8Path::new("/ws/Cargo.toml")).is_err());
    }
}
