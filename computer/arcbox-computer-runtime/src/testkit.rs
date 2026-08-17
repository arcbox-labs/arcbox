//! Fakes for this crate's ports, for tests that must not need a VMM.
//!
//! Together with `arcbox_vm_driver::testkit`'s `FakeDriver` and
//! `FakeNetwork`, [`agent::FakeAgentFactory`] is what lets the real
//! create → boot → readiness → exec path run anywhere — no KVM, no root,
//! no Firecracker, and on macOS as well as Linux.
//!
//! Behind the `testkit` feature, so production builds carry none of it.

pub mod agent;
