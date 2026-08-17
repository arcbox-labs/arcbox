//! Checkpoint settlement policy: where a capture left the guest, and
//! therefore whether the sandbox survives it.
//!
//! The subtlest rule in the crate. The driver settles the guest before it
//! reports — a failed capture is resumed, a successful one is resumed
//! unless the request asked to hold it — so a guest found frozen where it
//! should be running has no way back: the port has no resume verb. Every
//! caller of `super::super::checkpoint::checkpoint_impl` must fail the
//! sandbox on [`Settlement::Frozen`] rather than report it usable.

use arcbox_vm_driver::VmState;

/// What the request asked the driver to do with the guest once the capture
/// was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox) enum GuestHold {
    /// Resume it — every checkpoint but pause.
    Resume,
    /// Hold it quiesced: pause's whole point is that the guest must never
    /// run past the memory image.
    Hold,
}

/// Whether the capture produced a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox) enum Capture {
    Succeeded,
    Failed,
}

/// Where the guest ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::sandbox) enum Settlement {
    /// Running again, or held quiesced on purpose with the capture in hand:
    /// the sandbox is as usable as the request intended.
    AsRequested,
    /// Frozen with no way back — the driver's own resume after the capture
    /// failed, or the guest was held on request and a later step failed.
    Frozen,
}

/// Read the settlement off the guest's state, the request's intent, and
/// whether the capture succeeded.
pub(in crate::sandbox) fn settlement(
    state: VmState,
    hold: GuestHold,
    capture: Capture,
) -> Settlement {
    let frozen =
        state == VmState::Quiesced && (hold == GuestHold::Resume || capture == Capture::Failed);
    if frozen {
        Settlement::Frozen
    } else {
        Settlement::AsRequested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_vm_driver::ExitStatus;

    #[test]
    fn a_guest_is_stranded_only_where_no_verb_can_thaw_it() {
        use Capture::{Failed, Succeeded};
        use GuestHold::{Hold, Resume};
        use Settlement::{AsRequested, Frozen};

        let table = [
            // A running guest is fine however the capture went — including
            // when the hold did not take, which leaves nothing stranded.
            (VmState::Running, Resume, Succeeded, AsRequested),
            (VmState::Running, Resume, Failed, AsRequested),
            (VmState::Running, Hold, Succeeded, AsRequested),
            (VmState::Running, Hold, Failed, AsRequested),
            // Quiesced where the request asked for a resume: the driver's
            // own resume failed, so the guest is stranded either way.
            (VmState::Quiesced, Resume, Succeeded, Frozen),
            (VmState::Quiesced, Resume, Failed, Frozen),
            // Quiesced on request: pause's happy path — but only with the
            // capture in hand. A failure after the freeze leaves a guest
            // nobody will resume.
            (VmState::Quiesced, Hold, Succeeded, AsRequested),
            (VmState::Quiesced, Hold, Failed, Frozen),
            // An exited VM is not frozen: there is no guest to thaw, and the
            // caller's own teardown covers it.
            (
                VmState::Exited(ExitStatus::exited(0)),
                Resume,
                Succeeded,
                AsRequested,
            ),
            (
                VmState::Exited(ExitStatus::exited(0)),
                Resume,
                Failed,
                AsRequested,
            ),
            (
                VmState::Exited(ExitStatus::exited(0)),
                Hold,
                Succeeded,
                AsRequested,
            ),
            (
                VmState::Exited(ExitStatus::exited(0)),
                Hold,
                Failed,
                AsRequested,
            ),
        ];

        for (state, hold, capture, expected) in table {
            assert_eq!(
                settlement(state, hold, capture),
                expected,
                "{state} {hold:?} {capture:?}"
            );
        }
    }
}
