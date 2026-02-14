//! Core Foundation Run Loop utilities.
//!
//! Provides wrappers around CFRunLoop for handling asynchronous operations
//! that require the run loop to be active.

use std::ffi::c_void;
use std::time::{Duration, Instant};

// ============================================================================
// Types
// ============================================================================

/// Opaque type for CFRunLoop reference.
pub type CFRunLoopRef = *mut c_void;

/// Result of running the run loop in a specific mode.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CFRunLoopRunResult {
    /// The run loop finished processing all sources.
    Finished = 1,
    /// The run loop was stopped with `cf_run_loop_stop`.
    Stopped = 2,
    /// The run loop timed out.
    TimedOut = 3,
    /// A source was handled.
    HandledSource = 4,
}

impl From<i32> for CFRunLoopRunResult {
    fn from(value: i32) -> Self {
        match value {
            1 => Self::Finished,
            2 => Self::Stopped,
            3 => Self::TimedOut,
            4 => Self::HandledSource,
            _ => Self::TimedOut,
        }
    }
}

// ============================================================================
// FFI Declarations
// ============================================================================

unsafe extern "C" {
    fn CFRunLoopGetMain() -> CFRunLoopRef;
    fn CFRunLoopGetCurrent() -> CFRunLoopRef;
    fn CFRunLoopRun();
    fn CFRunLoopStop(rl: CFRunLoopRef);
    fn CFRunLoopRunInMode(
        mode: *const c_void,
        seconds: f64,
        returnAfterSourceHandled: bool,
    ) -> i32;

    // kCFRunLoopDefaultMode is a CFStringRef constant
    static kCFRunLoopDefaultMode: *const c_void;
}

// ============================================================================
// Public API
// ============================================================================

/// Gets the main CFRunLoop.
///
/// The main run loop is the run loop of the main thread.
pub fn cf_run_loop_get_main() -> CFRunLoopRef {
    unsafe { CFRunLoopGetMain() }
}

/// Gets the current thread's CFRunLoop.
///
/// Each thread has its own run loop.
pub fn cf_run_loop_get_current() -> CFRunLoopRef {
    unsafe { CFRunLoopGetCurrent() }
}

/// Runs the current run loop indefinitely.
///
/// This function blocks until the run loop is stopped via `cf_run_loop_stop`.
/// It should not normally be used directly; prefer `run_loop_until` for
/// most use cases.
pub fn cf_run_loop_run() {
    unsafe { CFRunLoopRun() }
}

/// Stops a run loop.
///
/// This causes a running `cf_run_loop_run` or `cf_run_loop_run_in_mode`
/// to exit.
///
/// # Arguments
///
/// * `rl` - The run loop to stop
pub fn cf_run_loop_stop(rl: CFRunLoopRef) {
    unsafe { CFRunLoopStop(rl) }
}

/// Runs the run loop in default mode for up to the specified duration.
///
/// # Arguments
///
/// * `seconds` - Maximum time to run the run loop
/// * `return_after_source_handled` - If true, return after handling a single source
///
/// # Returns
///
/// The result indicating why the run loop exited.
pub fn cf_run_loop_run_in_mode(
    seconds: f64,
    return_after_source_handled: bool,
) -> CFRunLoopRunResult {
    unsafe {
        let result = CFRunLoopRunInMode(kCFRunLoopDefaultMode, seconds, return_after_source_handled);
        CFRunLoopRunResult::from(result)
    }
}

/// Runs the run loop until a predicate returns true or timeout is reached.
///
/// This is useful for waiting on asynchronous operations that require
/// the run loop to be active (e.g., Virtualization.framework callbacks).
///
/// # Arguments
///
/// * `predicate` - A function that returns true when the wait should end
/// * `timeout_secs` - Maximum time to wait in seconds
///
/// # Returns
///
/// Returns `true` if the predicate returned true, `false` if timed out.
///
/// # Example
///
/// ```rust,no_run
/// use arcbox_vz::ffi::run_loop_until;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use std::sync::Arc;
///
/// let ready = Arc::new(AtomicBool::new(false));
///
/// // Wait for up to 5 seconds for the ready flag
/// let success = run_loop_until(|| ready.load(Ordering::SeqCst), 5.0);
///
/// if success {
///     println!("Operation completed!");
/// } else {
///     println!("Timed out!");
/// }
/// ```
pub fn run_loop_until<F>(mut predicate: F, timeout_secs: f64) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    let timeout = Duration::from_secs_f64(timeout_secs);

    while !predicate() {
        if start.elapsed() > timeout {
            return false;
        }

        // Run the run loop for a short interval (10ms)
        cf_run_loop_run_in_mode(0.01, true);
    }

    true
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_main_run_loop() {
        let main = cf_run_loop_get_main();
        assert!(!main.is_null());
    }

    #[test]
    fn test_get_current_run_loop() {
        let current = cf_run_loop_get_current();
        assert!(!current.is_null());
    }

    #[test]
    fn test_run_loop_until_immediate() {
        let result = run_loop_until(|| true, 1.0);
        assert!(result);
    }

    #[test]
    fn test_run_loop_until_timeout() {
        let start = Instant::now();
        let result = run_loop_until(|| false, 0.1);
        let elapsed = start.elapsed();

        assert!(!result);
        assert!(elapsed.as_secs_f64() >= 0.1);
        assert!(elapsed.as_secs_f64() < 0.5);
    }

    #[test]
    fn test_run_loop_run_in_mode() {
        let result = cf_run_loop_run_in_mode(0.01, true);
        // Should return Finished (no sources) or TimedOut
        assert!(
            result == CFRunLoopRunResult::Finished || result == CFRunLoopRunResult::TimedOut,
            "Expected Finished or TimedOut, got {:?}",
            result
        );
    }
}
