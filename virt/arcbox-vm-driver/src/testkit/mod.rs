//! Fakes and the contract test-kit (feature `testkit`).
//!
//! - [`FakeDriver`] — an in-memory [`VmDriver`](crate::VmDriver) with a
//!   real state machine and events. Runtime unit tests drive their real
//!   actors and state machines against it on any host, no KVM required.
//!
//! The capabilities, the fake network, and the contract test-kit land in
//! the sibling modules.

use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod fake_driver;
mod fake_vm;

pub use fake_driver::FakeDriver;
pub use fake_vm::FakeVm;

/// Locks `mutex`, tolerating poison: a fake that panicked while holding a
/// lock has already failed the test, and the state behind it is still the
/// most useful thing to show.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
