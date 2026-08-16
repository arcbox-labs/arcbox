//! The evaluator: a pure function from a graph and the rule tables to a
//! [`Report`], so the rules are tested on graphs written by hand.

use super::graph::{Edge, Graph, Target};
use super::rule::{Exception, Rule};

/// A direct edge that a rule forbids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    /// The offending edge.
    pub edge: Edge,
    /// The rule it breaks.
    pub rule: Rule,
}

/// A direct edge an exception allows for now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grandfathered {
    /// The tolerated edge.
    pub edge: Edge,
    /// The exception that tolerates it.
    pub exception: Exception,
}

/// Everything one evaluation found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Every direct edge between two workspace members, in evaluation
    /// order. Edges to external crates are matched against the rules that
    /// name them but are not listed here.
    pub edges: Vec<Edge>,
    /// Edges an exception took out of rule evaluation.
    pub grandfathered: Vec<Grandfathered>,
    /// Edges the rules forbid, one entry per (edge, rule) pair.
    pub violations: Vec<Violation>,
    /// Exceptions that matched no edge: the debt they recorded is paid, so
    /// they must be removed from the table.
    pub stale_exceptions: Vec<Exception>,
}

impl Report {
    /// Whether the gate passes: no violation and no stale exception.
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty() && self.stale_exceptions.is_empty()
    }
}

/// Evaluates every direct dependency of every member against `exceptions`
/// first and `rules` second. Only direct edges are looked at, and an
/// external crate matters only where a rule or exception names it.
pub fn evaluate(graph: &Graph, rules: &[Rule], exceptions: &[Exception]) -> Report {
    let mut report = Report::default();
    let mut exception_used = vec![false; exceptions.len()];
    for member in &graph.members {
        for dep in &member.deps {
            let target = graph.target(dep);
            let edge = Edge {
                from: member.name.clone(),
                to: dep.clone(),
            };
            if matches!(target, Target::Member(_)) {
                report.edges.push(edge.clone());
            }
            if let Some(index) = exceptions.iter().position(|e| e.covers(&edge)) {
                exception_used[index] = true;
                report.grandfathered.push(Grandfathered {
                    edge,
                    exception: exceptions[index],
                });
                continue;
            }
            for rule in rules.iter().filter(|rule| rule.forbids(member, target)) {
                report.violations.push(Violation {
                    edge: edge.clone(),
                    rule: *rule,
                });
            }
        }
    }
    report.stale_exceptions = exceptions
        .iter()
        .zip(exception_used)
        .filter(|(_, used)| !used)
        .map(|(exception, _)| *exception)
        .collect();
    report
}
