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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::check_layers::graph::{Layer, Member};
    use crate::commands::check_layers::rule::{Forbidden, Subject};

    fn member(name: &str, layer: Layer, deps: &[&str]) -> Member {
        Member {
            name: name.to_owned(),
            layer,
            deps: deps.iter().map(|dep| (*dep).to_owned()).collect(),
        }
    }

    fn graph(members: Vec<Member>) -> Graph {
        Graph { members }
    }

    fn edges(violations: &[Violation]) -> Vec<String> {
        violations.iter().map(|v| v.edge.to_string()).collect()
    }

    const ENGINE_NO_APP: Rule = Rule {
        subject: Subject::Layers(&[Layer::Engine, Layer::Computer]),
        forbidden: Forbidden::Layers(&[Layer::App]),
        reason: "engine is daemon-free",
    };
    const COMPUTER_NO_VMM: Rule = Rule {
        subject: Subject::Layers(&[Layer::Computer]),
        forbidden: Forbidden::Crates(&["arcbox-vmm"]),
        reason: "computer reaches the platform through engine",
    };
    const PORT_IS_A_LEAF: Rule = Rule {
        subject: Subject::Members(&["arcbox-vm-driver"]),
        forbidden: Forbidden::AnyMember,
        reason: "the port depends on nothing of ours",
    };
    const AGENT_STAYS_SMALL: Rule = Rule {
        subject: Subject::Members(&["arcbox-vm-agent"]),
        forbidden: Forbidden::Crates(&["tokio"]),
        reason: "the in-sandbox binary stays small",
    };

    #[test]
    fn layer_to_layer_rule_fires_on_the_forbidden_layer_only() {
        let graph = graph(vec![
            member(
                "arcbox-engine",
                Layer::Engine,
                &["arcbox-core", "arcbox-image"],
            ),
            member("arcbox-image", Layer::Engine, &[]),
            member("arcbox-core", Layer::App, &["arcbox-engine"]),
        ]);
        let report = evaluate(&graph, &[ENGINE_NO_APP], &[]);
        assert_eq!(edges(&report.violations), ["arcbox-engine -> arcbox-core"]);
        assert_eq!(report.violations[0].rule, ENGINE_NO_APP);
        assert_eq!(report.edges.len(), 3);
        assert!(!report.is_clean());
    }

    #[test]
    fn layer_to_crate_rule_matches_the_named_member_from_the_named_layer_only() {
        let graph = graph(vec![
            member("arcbox-computer", Layer::Computer, &["arcbox-vmm"]),
            member("arcbox-engine", Layer::Engine, &["arcbox-vmm"]),
            member("arcbox-vmm", Layer::Virt, &[]),
        ]);
        let report = evaluate(&graph, &[COMPUTER_NO_VMM], &[]);
        assert_eq!(edges(&report.violations), ["arcbox-computer -> arcbox-vmm"]);
    }

    #[test]
    fn member_to_any_member_rule_lets_externals_through() {
        let graph = graph(vec![
            member("arcbox-vm-driver", Layer::Virt, &["arcbox-error", "serde"]),
            member("arcbox-error", Layer::Common, &[]),
        ]);
        let report = evaluate(&graph, &[PORT_IS_A_LEAF], &[]);
        assert_eq!(
            edges(&report.violations),
            ["arcbox-vm-driver -> arcbox-error"]
        );
    }

    #[test]
    fn crate_rule_matches_an_external_crate_by_name() {
        let graph = graph(vec![
            member("arcbox-vm-agent", Layer::Virt, &["libc", "tokio"]),
            member("arcbox-vm", Layer::Virt, &["tokio"]),
        ]);
        let report = evaluate(&graph, &[AGENT_STAYS_SMALL], &[]);
        assert_eq!(edges(&report.violations), ["arcbox-vm-agent -> tokio"]);
        assert!(
            report.edges.is_empty(),
            "external edges are not member edges"
        );
    }

    #[test]
    fn a_rule_naming_an_absent_crate_is_a_no_op() {
        let graph = graph(vec![
            member("arcbox-engine", Layer::Engine, &["arcbox-image"]),
            member("arcbox-image", Layer::Engine, &[]),
        ]);
        let rules = [
            COMPUTER_NO_VMM,
            PORT_IS_A_LEAF,
            Rule {
                subject: Subject::Layers(&[Layer::Engine]),
                forbidden: Forbidden::Crates(&["arcbox-fc-driver"]),
                reason: "not landed yet",
            },
        ];
        let report = evaluate(&graph, &rules, &[]);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.edges.len(), 1);
    }

    #[test]
    fn a_grandfathered_edge_is_reported_and_never_a_violation() {
        let graph = graph(vec![
            member("arcbox-engine", Layer::Engine, &["arcbox-core"]),
            member("arcbox-core", Layer::App, &[]),
        ]);
        let exception = Exception {
            from: "arcbox-engine",
            to: "arcbox-core",
            reason: "legacy",
            until: "R4",
        };
        let report = evaluate(&graph, &[ENGINE_NO_APP], &[exception]);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(
            report.grandfathered,
            [Grandfathered {
                edge: Edge {
                    from: "arcbox-engine".to_owned(),
                    to: "arcbox-core".to_owned(),
                },
                exception,
            }]
        );
    }

    #[test]
    fn an_exception_matching_no_edge_is_stale() {
        let graph = graph(vec![member("arcbox-engine", Layer::Engine, &[])]);
        let exception = Exception {
            from: "arcbox-engine",
            to: "arcbox-vmm",
            reason: "paid off",
            until: "R4",
        };
        let report = evaluate(&graph, &[], &[exception]);
        assert_eq!(report.stale_exceptions, [exception]);
        assert!(!report.is_clean());
    }
}
