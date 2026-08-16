//! The layer rules and the grandfathered edges, as data.
//!
//! This table is the one place the layer rules are written down for the
//! machine; the AGENTS.md files that state them in prose point here. To add a
//! rule, append a [`Rule`] whose `reason` names the document that owns it —
//! a rule may name a crate that does not exist yet, it is a no-op until the
//! crate lands. To grandfather an edge, append an [`Exception`] with the
//! reason the edge exists and the phase (`until`) that removes it; the gate
//! fails once that edge is gone, so the exception leaves with it.

use super::graph::Layer;
use super::rule::{Exception, Forbidden, Rule, Subject};

/// The daemon-free orchestration layers (architecture charter D1/D4).
const ORCHESTRATION: &[Layer] = &[Layer::Engine, Layer::Computer];

/// The layer rules, evaluated over every direct dependency edge.
pub const RULES: &[Rule] = &[
    Rule {
        subject: Subject::Layers(ORCHESTRATION),
        forbidden: Forbidden::Layers(&[Layer::App]),
        reason: "charter D1/D4 — engine and computer are daemon-free and never reach app/",
    },
    Rule {
        subject: Subject::Layers(ORCHESTRATION),
        forbidden: Forbidden::Crates(&[
            "arcbox-vz",
            "arcbox-vmnet",
            "arcbox-route",
            "arcbox-hv",
            "ifbridge",
        ]),
        reason: "charter D4 — macOS-only backends are reached only through the \
                 platform seam, never directly",
    },
    Rule {
        subject: Subject::Layers(&[Layer::Common]),
        forbidden: Forbidden::Layers(&[
            Layer::Virt,
            Layer::Engine,
            Layer::Computer,
            Layer::App,
            Layer::Guest,
        ]),
        reason: "common/AGENTS.md \"The one hard rule\" — no VM / VirtIO / device / \
                 hypervisor dependency, so the host-only proxy harness stays buildable",
    },
    Rule {
        subject: Subject::Members(&["arcbox-vm-proto"]),
        forbidden: Forbidden::AnyMember,
        reason: "CORE-127 — the guest/host sandbox wire is a leaf crate shared by \
                 the in-sandbox binary and the host; it depends on nothing of ours",
    },
    Rule {
        subject: Subject::Members(&["arcbox-vm-agent"]),
        forbidden: Forbidden::Crates(&["arcbox-vm", "arcbox-snapshot", "tokio", "aya", "fc-sdk"]),
        reason: "CORE-127 — the in-sandbox binary is a compiler-enforced crate boundary \
                 and stays a small static musl binary",
    },
    Rule {
        subject: Subject::Layers(ORCHESTRATION),
        forbidden: Forbidden::Crates(&[
            "arcbox-vmm",
            "arcbox-hypervisor",
            "arcbox-fc-driver",
            "arcbox-vz-driver",
            "arcbox-tap-net",
            "arcbox-ch-driver",
        ]),
        reason: "vm-stack-redesign D-VM4 / charter D4 — orchestrators depend on the \
                 port arcbox-vm-driver, never on a VMM adapter nor on arcbox-vmm / \
                 arcbox-hypervisor directly (engine's two edges are grandfathered \
                 until R4; computer/AGENTS.md \"Reaching the platform without a #[cfg]\")",
    },
    Rule {
        subject: Subject::Members(&["arcbox-vm-driver"]),
        forbidden: Forbidden::AnyMember,
        reason: "vm-stack-redesign D-VM1 — the port sits below every adapter and \
                 orchestrator; it depends on nothing of ours",
    },
];

/// Direct edges the layer rules tolerate for now. An exception is checked
/// before the rules, so it holds even as the rules tighten around it; the
/// edge itself is the debt, and `until` names the phase that clears it.
pub const EXCEPTIONS: &[Exception] = &[
    Exception {
        from: "arcbox-engine",
        to: "arcbox-vmm",
        reason: "engine drives the macOS backends through arcbox-vmm until the \
                 arcbox-vm-driver port replaces that edge",
        until: "vm-stack-redesign R4",
    },
    Exception {
        from: "arcbox-engine",
        to: "arcbox-hypervisor",
        reason: "engine reaches the hypervisor seam directly until the \
                 arcbox-vm-driver port replaces that edge",
        until: "vm-stack-redesign R4",
    },
];
