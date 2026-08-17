//! The vocabulary the layer rules are written in.
//!
//! A [`Rule`] pairs a [`Subject`] (which members it constrains) with a
//! [`Forbidden`] (what they must not depend on) and a reason naming the
//! document that owns it. An [`Exception`] grandfathers one direct edge a
//! rule would otherwise forbid, for a stated phase. The tables themselves
//! live in [`super::rules`].

use super::graph::{Edge, Layer, Member, Target};

/// The dependent side of a rule: which workspace members it constrains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject {
    /// Every member whose manifest lives under one of these layers.
    Layers(&'static [Layer]),
    /// The named members. A name no member carries is a no-op, so a rule
    /// may be written for a crate before it lands.
    Members(&'static [&'static str]),
}

impl Subject {
    /// Whether the rule constrains `member`.
    pub fn covers(self, member: &Member) -> bool {
        match self {
            Self::Layers(layers) => layers.contains(&member.layer),
            Self::Members(names) => names.contains(&member.name.as_str()),
        }
    }
}

/// The dependency side of a rule: what the subject must not depend on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forbidden {
    /// Any workspace member under one of these layers.
    Layers(&'static [Layer]),
    /// The named crates, matched literally by package name — workspace
    /// members and external crates alike. This is the only way a rule
    /// reaches an external crate; a name nothing depends on is a no-op.
    Crates(&'static [&'static str]),
    /// Every workspace member.
    AnyMember,
}

impl Forbidden {
    /// Whether depending on `target` is what the rule forbids.
    pub fn matches(self, target: Target<'_>) -> bool {
        match (self, target) {
            (Self::Layers(layers), Target::Member(member)) => layers.contains(&member.layer),
            (Self::Layers(_), Target::External(_)) => false,
            (Self::Crates(names), target) => names.contains(&target.name()),
            (Self::AnyMember, target) => matches!(target, Target::Member(_)),
        }
    }
}

/// One layer rule: no member in `subject` may have a direct dependency
/// (of any kind) on anything `forbidden`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Which members the rule constrains.
    pub subject: Subject,
    /// What they must not depend on.
    pub forbidden: Forbidden,
    /// Why — naming the charter decision, design doc or AGENTS.md section
    /// that owns the rule. Printed with every violation.
    pub reason: &'static str,
}

impl Rule {
    /// Whether the direct edge `member -> target` violates this rule.
    pub fn forbids(&self, member: &Member, target: Target<'_>) -> bool {
        self.subject.covers(member) && self.forbidden.matches(target)
    }
}

/// A grandfathered direct edge: allowed for now, never reported as a
/// violation, and listed in verbose output. Every exception names the phase
/// that removes it; an exception whose edge no longer exists fails the gate
/// so the table cannot outlive the debt it records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exception {
    /// The dependent workspace member.
    pub from: &'static str,
    /// The dependency's package name.
    pub to: &'static str,
    /// Why the edge exists today.
    pub reason: &'static str,
    /// The phase whose landing removes this exception.
    pub until: &'static str,
}

impl Exception {
    /// Whether this exception grandfathers `edge`.
    pub fn covers(&self, edge: &Edge) -> bool {
        edge.from == self.from && edge.to == self.to
    }
}
