//! Layer-rule gate over the workspace dependency graph.
//!
//! The layer rules — engine and computer are daemon-free, common has no VM
//! dependency, orchestrators depend on the port and never on an adapter —
//! live only in AGENTS.md prose today. `cargo xtask check-layers` reads
//! `cargo metadata` and builds the graph of direct edges between workspace
//! members ([`graph`]); the rules that are evaluated over it land next.
//!
//! Only direct edges, only workspace members: an external crate is a name
//! the graph carries but never an edge of its own.

pub mod graph;

use anyhow::{Context, Result};
use cargo_metadata::MetadataCommand;
use xtask_kit::repo;

use crate::CheckLayersArgs;
use graph::{Edge, Graph, Target};

pub fn run(args: CheckLayersArgs) -> Result<()> {
    let root = repo::root_from_xtask_manifest(env!("CARGO_MANIFEST_DIR"))?;
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .context("reading the workspace with cargo metadata")?;
    let graph = Graph::try_from(&metadata)?;
    let edges = member_edges(&graph);
    if args.verbose {
        for edge in &edges {
            println!("edge: {edge}");
        }
    }
    println!(
        "layer graph: {} members, {} edges",
        graph.members.len(),
        edges.len()
    );
    Ok(())
}

/// Every direct edge between two workspace members, in member order.
fn member_edges(graph: &Graph) -> Vec<Edge> {
    graph
        .members
        .iter()
        .flat_map(|member| {
            member
                .deps
                .iter()
                .filter(|dep| matches!(graph.target(dep), Target::Member(_)))
                .map(move |dep| Edge {
                    from: member.name.clone(),
                    to: dep.clone(),
                })
        })
        .collect()
}
