//! Layer-rule gate over the workspace dependency graph.
//!
//! The layer rules — engine and computer are daemon-free, common has no VM
//! dependency, orchestrators depend on the port and never on an adapter —
//! used to live only in AGENTS.md prose. `cargo xtask check-layers` reads
//! `cargo metadata`, builds the graph of direct edges between workspace
//! members ([`graph`]), and fails on any edge the [`rules`] table forbids;
//! CI runs it in the `linux-engine` job. The evaluator
//! ([`evaluate::evaluate`]) is a pure function over that graph, so the rules
//! are unit-tested on graphs written by hand rather than on whatever the tree
//! happens to contain.
//!
//! Only direct edges, only workspace members: an external crate is checked
//! only where a rule names it explicitly.

pub mod evaluate;
pub mod graph;
pub mod rule;
pub mod rules;

use anyhow::{Context, Result, bail};
use cargo_metadata::MetadataCommand;
use xtask_kit::repo;

use crate::CheckLayersArgs;
use evaluate::{Report, evaluate};
use graph::Graph;

pub fn run(args: CheckLayersArgs) -> Result<()> {
    let root = repo::root_from_xtask_manifest(env!("CARGO_MANIFEST_DIR"))?;
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .context("reading the workspace with cargo metadata")?;
    let graph = Graph::try_from(&metadata)?;
    let report = evaluate(&graph, rules::RULES, rules::EXCEPTIONS);
    print_report(&graph, &report, args.verbose)
}

/// Prints violations and stale exceptions to stderr, the edge walk (with
/// `verbose`) and the summary to stdout, and fails when the gate is red.
fn print_report(graph: &Graph, report: &Report, verbose: bool) -> Result<()> {
    if verbose {
        for edge in &report.edges {
            println!("edge: {edge}");
        }
        for grandfathered in &report.grandfathered {
            println!(
                "allowed (grandfathered): {}: {} (until {})",
                grandfathered.edge, grandfathered.exception.reason, grandfathered.exception.until
            );
        }
    }
    for violation in &report.violations {
        eprintln!(
            "layer rule violated: {}: {}",
            violation.edge, violation.rule.reason
        );
    }
    for exception in &report.stale_exceptions {
        eprintln!(
            "stale exception: {} -> {} is no longer an edge (was allowed until {}); \
             remove it from the EXCEPTIONS table",
            exception.from, exception.to, exception.until
        );
    }
    let summary = format!(
        "{} members, {} edges checked, {} grandfathered",
        graph.members.len(),
        report.edges.len(),
        report.grandfathered.len()
    );
    if !report.is_clean() {
        bail!(
            "layer rules: {} violation(s), {} stale exception(s) ({summary})",
            report.violations.len(),
            report.stale_exceptions.len()
        );
    }
    println!("layer rules: {summary}");
    Ok(())
}
